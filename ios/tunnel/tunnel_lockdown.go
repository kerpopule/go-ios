package tunnel

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/golog"
)

const coreDeviceProxy = "com.apple.internal.devicecompute.CoreDeviceProxy"

func ConnectTunnelLockdown(device ios.DeviceEntry) (Tunnel, error) {
	conn, err := ios.ConnectToService(device, coreDeviceProxy)
	if err != nil {
		return Tunnel{}, err
	}
	return connectToTunnelLockdown(context.TODO(), device, conn)
}

func connectToTunnelLockdown(ctx context.Context, device ios.DeviceEntry, connToDevice io.ReadWriteCloser) (Tunnel, error) {
	return connectToTunnelLockdownThen(ctx, device, connToDevice, nil)
}

// connectToTunnelLockdownThen is connectToTunnelLockdown with afterExchange (when not nil) run once
// the CDTunnel parameters are in, before the interface is set up and forwarding starts. A failure
// there stops the tunnel before it exists; closing connToDevice is left to the caller, as for every
// other failure here.
//
// The loopback-streams road uses it to clear the deadline that bounded the TLS-PSK handshake AND the
// parameter exchange: a stream can open and then carry nothing at either step, and a deadline left
// on the connection would tear the tunnel down mid-session.
func connectToTunnelLockdownThen(ctx context.Context, device ios.DeviceEntry, connToDevice io.ReadWriteCloser, afterExchange func() error) (Tunnel, error) {
	golog.Info("connect to lockdown tunnel endpoint on device", "module", logModule, "udid", device.Properties.SerialNumber)

	tunnelInfo, err := exchangeCoreTunnelParameters(connToDevice)
	if err != nil {
		return Tunnel{}, fmt.Errorf("could not exchange tunnel parameters. %w", err)
	}
	if afterExchange != nil {
		if err := afterExchange(); err != nil {
			return Tunnel{}, fmt.Errorf("could not prepare the connection to carry the tunnel. %w", err)
		}
	}

	utunIface, err := setupTunnelInterface(tunnelInfo)
	if err != nil {
		return Tunnel{}, fmt.Errorf("could not setup tunnel interface. %w", err)
	}

	return startLockdownForwarding(ctx, device, tunnelInfo, connToDevice, utunIface), nil
}

// startLockdownForwarding runs the two packet pumps between the device connection and the
// interface and returns the Tunnel that owns them.
//
// Either pump stopping means the tunnel is dead: the device connection ended (on the loopback-streams
// road, every relay epoch end does this) or the interface failed. The first stop closes Done and
// records the reason for Err. The other pump is left to the caller's Close, which also removes the
// interface; nothing here closes the tunnel on its own.
func startLockdownForwarding(ctx context.Context, device ios.DeviceEntry, tunnelInfo tunnelParameters, connToDevice, utunIface io.ReadWriteCloser) Tunnel {
	// we want a copy of the parent ctx here, but it shouldn't time out/be cancelled at the same time.
	// doing it like this allows us to have a context with a timeout for the tunnel creation, but the tunnel itself
	tunnelCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	ended := newTunnelEnd()

	go func() {
		err := forwardTCPToInterface(tunnelCtx, tunnelInfo.ClientParameters.Mtu, connToDevice, utunIface)
		if err != nil {
			golog.Error("failed to forward data to tunnel interface", "module", logModule, "udid", device.Properties.SerialNumber, "error", err)
			err = fmt.Errorf("forwarding from the device stopped: %w", err)
		}
		ended.end(err)
	}()

	go func() {
		err := forwardTUNToDevice(tunnelCtx, tunnelInfo.ClientParameters.Mtu, utunIface, connToDevice)
		if err != nil {
			golog.Error("failed to forward data to the device", "module", logModule, "udid", device.Properties.SerialNumber, "error", err)
			err = fmt.Errorf("forwarding to the device stopped: %w", err)
		}
		ended.end(err)
	}()

	closeFunc := func() error {
		// Ended by the caller, not by a failure: Err stays nil. Recorded before the closes so the
		// errors the pumps then hit on closed handles are not taken for the reason.
		ended.end(nil)
		cancel()
		return errors.Join(utunIface.Close(), connToDevice.Close())
	}
	return Tunnel{
		Address: tunnelInfo.ServerAddress,
		RsdPort: int(tunnelInfo.ServerRSDPort),
		Udid:    device.Properties.SerialNumber,
		closer:  closeFunc,
		ended:   ended,
	}
}

// tunnelEnd is closed once, by whichever comes first: a pump stopping or Close.
type tunnelEnd struct {
	done chan struct{}
	once sync.Once
	err  error // written before done is closed, read only after
}

func newTunnelEnd() *tunnelEnd { return &tunnelEnd{done: make(chan struct{})} }

func (e *tunnelEnd) end(err error) {
	e.once.Do(func() {
		e.err = err
		close(e.done)
	})
}

func (e *tunnelEnd) reason() error {
	select {
	case <-e.done:
		return e.err
	default:
		return nil
	}
}

func forwardTUNToDevice(ctx context.Context, mtu uint64, tun io.Reader, deviceConn io.Writer) error {
	packet := make([]byte, mtu)
	for {

		select {
		case <-ctx.Done():
			return nil
		default:

			n, err := tun.Read(packet)

			if err != nil {
				return fmt.Errorf("could not read packet. %w", err)
			}

			_, err = deviceConn.Write(packet[:n])
			if err != nil {
				return fmt.Errorf("could not write packet. %w", err)
			}
		}

	}
}

func forwardTCPToInterface(ctx context.Context, mtu uint64, deviceConn io.Reader, tun io.Writer) error {
	payload := make([]byte, mtu)
	ip6Header := make([]byte, 40)

	br := bufio.NewReader(deviceConn)
	bw := bufio.NewWriter(tun)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			_, err := io.ReadFull(br, ip6Header)
			if err != nil {
				return fmt.Errorf("failed to read IPv6 header: %w", err)
			}

			if ip6Header[0]>>4 != 6 {
				return fmt.Errorf("not an IPv6 packet: expected version 6, got %d", ip6Header[0]>>4)
			}
			payloadLength := binary.BigEndian.Uint16(ip6Header[4:6])
			_, err = io.ReadFull(br, payload[:payloadLength])
			if err != nil {
				return fmt.Errorf("failed to read payload of length %d: %w", payloadLength, err)
			}

			// we don't need to check all errors here as `Flush` will return the error from a previous write as well
			_, _ = bw.Write(ip6Header)
			_, _ = bw.Write(payload[:payloadLength])
			err = bw.Flush()
			if err != nil {
				return fmt.Errorf("could not flush packet: %w", err)
			}
		}

	}
}
