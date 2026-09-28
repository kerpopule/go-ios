package tunnel

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/http"
)

// PairThroughTunnel performs the one-time RemotePairing pair-SETUP with a phone that is reached
// through a CoreDevice tunnel that is ALREADY UP — in Co-Agent's case the lockdown CoreDeviceProxy
// tunnel over Wi-Fi (lanmux + `ios tunnel start`), which needs no cable.
//
// WHY (2026-09-22). The Wi-Fi RemotePairing channel (_remotepairing._tcp, port 49152) answers
// pair-VERIFY but resets the connection on setupManualPairing — measured on iOS 27, not assumed.
// The untrusted tunnelservice that DOES accept setupManualPairing is normally reached over the USB
// NCM link, but the trusted RSD inside an existing tunnel lists it too (see ios/rsd_test.go). So a
// Mac that can already control the phone over Wi-Fi can create its own RemotePairing record without
// a cable. The phone shows its own "Trust This Computer?" prompt and asks for the passcode; nothing
// here can answer that for the owner.
//
// The record lands in p (selfIdentity.plist + peers/). It is this Mac's own identity, independent of
// Apple's TCC-locked records in /var/db/lockdown/RemotePairing.
func PairThroughTunnel(address string, rsdPort int, device ios.DeviceEntry, p PairRecordManager) error {
	rsdService, err := ios.NewWithAddrPortDevice(address, rsdPort, device)
	if err != nil {
		return fmt.Errorf("PairThroughTunnel: failed to reach RSD at %s port %d: %w", address, rsdPort, err)
	}
	handshake, err := rsdService.Handshake()
	_ = rsdService.Close()
	if err != nil {
		return fmt.Errorf("PairThroughTunnel: RSD handshake failed: %w", err)
	}
	port := handshake.GetPort(untrustedTunnelServiceName)
	if port == 0 {
		return fmt.Errorf("PairThroughTunnel: RSD inside this tunnel does not list '%s'", untrustedTunnelServiceName)
	}

	conn, err := ios.ConnectTUNDevice(address, port, device)
	if err != nil {
		return fmt.Errorf("PairThroughTunnel: failed to connect to %s port %d: %w", untrustedTunnelServiceName, port, err)
	}
	h, err := http.NewHttpConnection(conn)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("PairThroughTunnel: failed to create HTTP2 connection: %w", err)
	}
	xpcConn, err := ios.CreateXpcConnection(h)
	if err != nil {
		_ = h.Close()
		return fmt.Errorf("PairThroughTunnel: failed to create RemoteXPC connection: %w", err)
	}
	ts := newTunnelServiceWithXpc(xpcConn, h, p)
	defer func() { _ = ts.Close() }()

	if err := ts.ManualPair(); err != nil {
		return fmt.Errorf("PairThroughTunnel: pairing did not complete (was Trust tapped and the passcode entered?): %w", err)
	}
	return nil
}

// VerifyRemotePairing checks that the record in p is accepted by the RemotePairing control channel
// at address ("host:port") — pair-VERIFY only. Unlike ManualPair it never falls back to pair-setup,
// so it can never raise a prompt on the phone; a nil error means the record works on that road.
func VerifyRemotePairing(address string, timeout time.Duration, p PairRecordManager) error {
	return VerifyRemotePairingVia(address, timeout, p, nil)
}

// VerifyRemotePairingVia is VerifyRemotePairing with the control channel opened by dial (for example
// StreamsDialer) instead of a direct TCP connect. With a dial, timeout is ONE budget for the whole
// call: the stream's open (which the desk can legitimately hold for most of it) and the pair-verify
// exchange share it, so a caller can wrap the verify probe in timeout plus a little slack.
//
// A nil dial is exactly VerifyRemotePairing, whose bound is unchanged: the TCP connect gets timeout
// and the exchange then gets its own timeout.
func VerifyRemotePairingVia(address string, timeout time.Duration, p PairRecordManager, dial RemotePairingDialer) error {
	var conn *rpPairingConn
	var err error
	var deadline time.Time
	if dial == nil {
		conn, err = dialRemotePairing(address, timeout)
	} else {
		deadline = time.Now().Add(timeout)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		conn, err = dialRemotePairingVia(ctx, dial, address, timeout, StreamsLegControl)
		cancel()
	}
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if dial == nil {
		deadline = time.Now().Add(timeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("VerifyRemotePairing: failed to bound the exchange: %w", err)
	}
	ts := newTunnelServiceWithXpc(conn, conn, p)
	if err := ts.controlChannel.writeRequest(map[string]interface{}{
		"handshake": map[string]interface{}{
			"_0": map[string]interface{}{
				"hostOptions":         map[string]interface{}{"attemptPairVerify": true},
				"wireProtocolVersion": int64(19),
			},
		},
	}); err != nil {
		return fmt.Errorf("VerifyRemotePairing: failed to send handshake: %w", err)
	}
	if _, err := ts.controlChannel.read(); err != nil {
		return fmt.Errorf("VerifyRemotePairing: failed to read handshake response: %w", err)
	}
	if err := ts.verifyPair(); err != nil {
		return fmt.Errorf("VerifyRemotePairing: the phone did not accept this Mac's pairing: %w", err)
	}
	return nil
}

// ConnectToTunnelOverRemotePairingAt is ConnectToTunnelOverRemotePairing for a known "host:port"
// instead of a Bonjour result — the away-from-desk road, where the phone is 10.71.0.2 on the
// Co-Agent utun and Bonjour cannot see it.
func ConnectToTunnelOverRemotePairingAt(ctx context.Context, address string, device ios.DeviceEntry, p PairRecordManager) (Tunnel, error) {
	return ConnectToTunnelOverRemotePairingAtVia(ctx, address, device, p, nil)
}

// ConnectToTunnelOverRemotePairingAtVia is ConnectToTunnelOverRemotePairingAt with both TCP legs
// opened by dial — the loopback-streams road passes StreamsDialer and "phone:49152". A nil dial is
// exactly ConnectToTunnelOverRemotePairingAt.
func ConnectToTunnelOverRemotePairingAtVia(ctx context.Context, address string, device ios.DeviceEntry, p PairRecordManager, dial RemotePairingDialer) (Tunnel, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairingAt: %q is not host:port: %w", address, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairingAt: bad port in %q: %w", address, err)
	}
	return connectToTunnelOverRemotePairing(ctx, ios.RemotePairingEndpoint{
		HostName:  host,
		Port:      port,
		Addresses: []string{host},
	}, device, p, dial)
}
