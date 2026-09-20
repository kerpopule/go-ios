package tunnel

import (
	"context"
	"fmt"
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
	address := endpoint.Address()
	if address == "" {
		return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairing: %s advertised no dialable address", endpoint.HostName)
	}

	conn, err := dialRemotePairing(address, remotePairingHandshakeTimeout)
	if err != nil {
		// The most likely cause by far, said plainly rather than as a dial error.
		return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairing: %s advertised %s but did not answer — a sleeping iPhone keeps advertising after it stops accepting connections, so wake and unlock it and try again: %w", endpoint.HostName, address, err)
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

	// The listener is on the phone's Wi-Fi interface here, not on a link-local
	// USB address — so it is reached at the same host that answered the
	// control channel, on the port it just named.
	tunnelAddr := hostWithPort(endpoint.Addresses[0], tunnelPort)
	tcpConn, err := ios.DialTunnelTCP(tunnelAddr)
	if err != nil {
		_ = conn.Close()
		return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairing: failed to dial tunnel port %s: %w", tunnelAddr, err)
	}
	tlsConn, err := tlspsk.Client(tcpConn, ts.sharedSecret)
	if err != nil {
		_ = conn.Close()
		return Tunnel{}, fmt.Errorf("ConnectToTunnelOverRemotePairing: TLS-PSK handshake failed: %w", err)
	}

	// The control-channel deadline covered the HANDSHAKE only. What comes out
	// of this is long-lived, and a deadline left on the socket underneath would
	// tear the tunnel down mid-session. A failure to clear it is not worth
	// refusing a working tunnel over — it would surface later as a read error,
	// with a better message than anything that could be said here.
	_ = conn.SetDeadline(time.Time{})

	return connectToTunnelLockdown(ctx, device, tlsConn)
}

// hostWithPort joins a host that may be an IPv6 literal, with or without a
// zone, to a port. net.JoinHostPort does the bracketing; this exists so the
// intent is named at the call site.
func hostWithPort(host string, port uint16) string {
	return fmt.Sprintf("[%s]:%d", host, port)
}
