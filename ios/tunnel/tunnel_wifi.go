package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/tunnel/tlspsk"
)

// remotePairingHandshakeTimeout bounds the whole control-channel exchange.
//
// A sleeping iPhone still ANSWERS mDNS — the network's sleep proxy does it for
// them — so discovery can succeed against a phone that will never complete a
// TCP handshake. Without a deadline this waits on a device that is not there.
const remotePairingHandshakeTimeout = 30 * time.Second

// ConnectToTunnelOverRemotePairing brings up the CoreDevice tunnel over Wi-Fi,
// with no cable and no usbmux entry.
//
// It is ManualPairAndConnectToTunnelTCP with its first three steps replaced.
// Those steps — find the device's link-local address by browsing _remoted._tcp,
// ask RemoteServiceDiscovery for the untrusted tunnelservice port, open an
// HTTP/2 RemoteXPC connection — exist only to reach the control channel across
// USB. Over Wi-Fi the device advertises that same control channel directly, so
// all three collapse into one dial.
//
// Everything after that is untouched and shared with the USB path: ManualPair,
// createTcpTunnelListener, the TLS-PSK session keyed by the pair-verify shared
// secret, and the CDTunnel data plane.
//
// WHAT THIS STILL NEEDS, none of which this function can supply:
//   - The phone AWAKE and on this Wi-Fi network. See the timeout above.
//   - An existing pair record. The Wi-Fi control channel performs pair-VERIFY;
//     it does not do first-time pair-setup. A Mac that has never paired with
//     this phone gets a verify failure, not a trust prompt. Pair once (a cable,
//     Xcode's Device Hub, or Settings > Developer > Paired Macs) and this works
//     from then on.
//   - Developer Mode on the phone.
func ConnectToTunnelOverRemotePairing(ctx context.Context, endpoint ios.RemotePairingEndpoint, device ios.DeviceEntry, p PairRecordManager) (Tunnel, error) {
	return connectToTunnelOverRemotePairing(ctx, endpoint, device, p, nil)
}

// ConnectToTunnelOverRemotePairingVia is ConnectToTunnelOverRemotePairing with BOTH of its TCP legs —
// the RemotePairing control channel and the TLS-PSK tunnel port — opened by dial instead of a direct
// TCP connect. A nil dial is exactly ConnectToTunnelOverRemotePairing.
//
// The loopback-streams road (contract rev 4) passes StreamsDialer, with endpoint.Addresses[0] set to
// "phone" or "127.0.0.1": the phone's tunnel extension connects to its OWN loopback, so the tunnel
// port is dialled at that same host. Everything after the TLS-PSK handshake is unchanged.
func ConnectToTunnelOverRemotePairingVia(ctx context.Context, endpoint ios.RemotePairingEndpoint, device ios.DeviceEntry, p PairRecordManager, dial RemotePairingDialer) (Tunnel, error) {
	return connectToTunnelOverRemotePairing(ctx, endpoint, device, p, dial)
}

func connectToTunnelOverRemotePairing(ctx context.Context, endpoint ios.RemotePairingEndpoint, device ios.DeviceEntry, p PairRecordManager, dial RemotePairingDialer) (Tunnel, error) {
	address := endpoint.Address()
	if address == "" {
		return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairing: %s advertised no dialable address", endpoint.HostName)
	}

	var conn *rpPairingConn
	var err error
	if dial == nil {
		conn, err = dialRemotePairing(address, remotePairingHandshakeTimeout)
		if err != nil {
			// The most likely cause by far, said plainly rather than as a dial error.
			return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairing: %s advertised %s but did not answer — a sleeping iPhone keeps advertising after it stops accepting connections, so wake and unlock it and try again: %w", endpoint.HostName, address, err)
		}
	} else {
		conn, err = dialRemotePairingVia(ctx, dial, address, remotePairingHandshakeTimeout, StreamsLegControl)
		if err != nil {
			return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairing: could not open the RemotePairing control channel at %s: %w", address, err)
		}
	}
	if err := conn.SetDeadline(time.Now().Add(remotePairingHandshakeTimeout)); err != nil {
		_ = conn.Close()
		return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairing: failed to bound the handshake: %w", err)
	}

	ts := newTunnelServiceWithXpc(conn, conn, p)

	if err := ts.ManualPair(); err != nil {
		_ = conn.Close()
		return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairing: failed to pair with %s — the Wi-Fi channel can only VERIFY an existing pairing, so pair this Mac with the phone once (cable, Xcode Device Hub, or Settings > Developer > Paired Macs) and try again: %w", endpoint.HostName, err)
	}

	tunnelPort, err := ts.createTcpTunnelListener()
	if err != nil {
		_ = conn.Close()
		return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairing: failed to create tcp tunnel listener: %w", err)
	}

	var tlsConn net.Conn
	if dial == nil {
		// The listener is on the phone's Wi-Fi interface here, not on a link-local
		// USB address — so it is reached at the same host that answered the
		// control channel, on the port it just named.
		tunnelAddr := hostWithPort(endpoint.Addresses[0], tunnelPort)
		tcpConn, err := ios.DialTunnelTCP(tunnelAddr)
		if err != nil {
			_ = conn.Close()
			return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairing: failed to dial tunnel port %s: %w", tunnelAddr, err)
		}
		tlsConn, err = tlspsk.Client(tcpConn, ts.sharedSecret)
		if err != nil {
			_ = conn.Close()
			return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairing: TLS-PSK handshake failed: %w", err)
		}
	} else {
		tlsConn, err = dialTunnelPortVia(ctx, dial, endpoint.Addresses[0], tunnelPort, ts.sharedSecret)
		if err != nil {
			_ = conn.Close()
			return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairing: %w", err)
		}
	}

	// The control-channel deadline covered the HANDSHAKE only. What comes out
	// of this is long-lived, and a deadline left on the socket underneath would
	// tear the tunnel down mid-session. A failure to clear it is not worth
	// refusing a working tunnel over — it would surface later as a read error,
	// with a better message than anything that could be said here.
	_ = conn.SetDeadline(time.Time{})

	if dial == nil {
		return connectToTunnelLockdown(ctx, device, tlsConn)
	}
	t, err := connectStreamedTunnelLockdown(ctx, device, tlsConn)
	if err != nil {
		// Give both stream slots back now rather than when the collector gets to them.
		_ = tlsConn.Close()
		_ = conn.Close()
		return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairing: %w", err)
	}
	return t, nil
}

// connectStreamedTunnelLockdown runs the CDTunnel data plane over a tunnel-port connection from
// dialTunnelPortVia, which still carries the deadline that bounds its setup. The parameter exchange
// runs under that deadline — a stream that completes TLS-PSK and then carries nothing must fail, not
// hang — and the deadline is cleared once the parameters are in, before any packet is forwarded.
func connectStreamedTunnelLockdown(ctx context.Context, device ios.DeviceEntry, tlsConn net.Conn) (Tunnel, error) {
	return connectToTunnelLockdownThen(ctx, device, tlsConn, func() error {
		if err := tlsConn.SetDeadline(time.Time{}); err != nil {
			return fmt.Errorf("failed to clear the tunnel-port setup deadline: %w", err)
		}
		return nil
	})
}

// dialTunnelPortVia opens the per-session TLS-PSK tunnel port through dial, at the same host the
// control channel used, and runs the TLS-PSK handshake on it.
//
// Unlike the direct path, the setup is bounded: over loopback streams the stream can open and then
// never carry a byte (the phone's listener accepted and stalled, or the epoch is wedged), and an
// unbounded read would hold the caller forever. The dial gets ios.TunnelDialTimeout; the TLS-PSK
// handshake and the CDTunnel parameter exchange after it share a second ios.TunnelDialTimeout, set
// here and LEFT ON the returned connection. connectStreamedTunnelLockdown clears it once the
// parameters are in; any other caller must clear it before using the connection long-term.
func dialTunnelPortVia(ctx context.Context, dial RemotePairingDialer, host string, port uint16, psk []byte) (net.Conn, error) {
	tunnelAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	dctx, cancel := context.WithTimeout(ctx, ios.TunnelDialTimeout)
	raw, err := dial(dctx, tunnelAddr)
	cancel()
	if err == nil && raw == nil {
		err = errors.New("dialer returned no connection")
	}
	if err != nil {
		tagStreamsLeg(err, StreamsLegTunnelPort)
		return nil, fmt.Errorf("failed to open tunnel port %s (the RemotePairing control channel on the same host worked): %w", tunnelAddr, err)
	}
	if err := raw.SetDeadline(time.Now().Add(ios.TunnelDialTimeout)); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("failed to bound the TLS-PSK handshake on %s: %w", tunnelAddr, err)
	}
	tlsConn, err := tlspsk.Client(raw, psk)
	if err != nil {
		// tlspsk.Client has already closed raw.
		return nil, fmt.Errorf("TLS-PSK handshake on %s failed: %w", tunnelAddr, err)
	}
	return tlsConn, nil
}

// hostWithPort joins a host that may be an IPv6 literal, with or without a
// zone, to a port. net.JoinHostPort does the bracketing; this exists so the
// intent is named at the call site.
func hostWithPort(host string, port uint16) string {
	return fmt.Sprintf("[%s]:%d", host, port)
}
