package ios

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ErrRsdConnect marks a RsdHandshakeWithTimeout failure that happened before
// the handshake itself: the dial, or the HTTP/2 and XPC setup on the new
// connection (the part NewWithAddrPortDevice does). A caller can tell "the
// tunnel endpoint did not answer" from "it answered but the handshake failed".
var ErrRsdConnect = errors.New("rsd endpoint did not answer")

// This file holds bounded, verified variants of the RSD shim and handshake
// helpers. They are additive: RsdCheckin, ConnectToShimService and
// NewWithAddrPortDevice keep their existing behaviour for every caller that
// already relies on them.
//
// The unbounded helpers are fine on a cable, where a dead peer shows up as a
// closed socket at once. Over a network tunnel a dead or wedged peer can leave
// a read waiting until TCP keepalive gives up, and a caller that must answer
// within a fixed budget (a status probe, for example) needs a hard deadline and
// a checkin whose reply was actually checked.

// RsdCheckinVerified is RsdCheckin with both replies checked. The device must
// answer the checkin with {Request: "RSDCheckin"} and then send
// {Request: "StartService"}; a reply carrying an Error key, or any other
// Request, is reported as an error instead of being read as success.
//
// It sets no deadline itself: bound it by setting one on the connection first.
func RsdCheckinVerified(rw io.ReadWriter) error {
	req := map[string]interface{}{
		"Label":           "go-ios",
		"ProtocolVersion": "2",
		"Request":         "RSDCheckin",
	}
	prw := NewPlistCodecReadWriter(rw, rw)
	if err := prw.Write(req); err != nil {
		return fmt.Errorf("RsdCheckinVerified: failed to send checkin request: %w", err)
	}
	var checkin map[string]any
	if err := prw.Read(&checkin); err != nil {
		return fmt.Errorf("RsdCheckinVerified: failed to read checkin response: %w", err)
	}
	if err := checkinReply(checkin, "RSDCheckin"); err != nil {
		return fmt.Errorf("RsdCheckinVerified: checkin response: %w", err)
	}
	var start map[string]any
	if err := prw.Read(&start); err != nil {
		return fmt.Errorf("RsdCheckinVerified: failed to read start service message: %w", err)
	}
	if err := checkinReply(start, "StartService"); err != nil {
		return fmt.Errorf("RsdCheckinVerified: start service message: %w", err)
	}
	return nil
}

func checkinReply(m map[string]any, want string) error {
	if e, ok := m["Error"]; ok {
		return fmt.Errorf("device answered with Error %v", e)
	}
	if got, _ := m["Request"].(string); got != want {
		return fmt.Errorf("expected Request %q, got %q", want, got)
	}
	return nil
}

// connectTUNDeviceWithTimeout is ConnectTUNDevice with a caller-chosen dial
// timeout on the kernel TUN road. The userspace TUN road dials the local agent,
// which ConnectTUNDevice already bounds.
func connectTUNDeviceWithTimeout(remoteIp string, port int, d DeviceEntry, timeout time.Duration) (*net.TCPConn, error) {
	if port <= 0 {
		return nil, fmt.Errorf("connectTUNDeviceWithTimeout: invalid port %d for %s", port, remoteIp)
	}
	if d.UserspaceTUN {
		return ConnectTUNDevice(remoteIp, port, d)
	}
	conn, err := DialTunnelTCPWithTimeout(net.JoinHostPort(remoteIp, fmt.Sprint(port)), timeout)
	if err != nil {
		return nil, fmt.Errorf("connectTUNDeviceWithTimeout: failed to dial: %w", err)
	}
	if err := conn.SetKeepAlive(true); err != nil {
		conn.Close()
		return nil, fmt.Errorf("connectTUNDeviceWithTimeout: failed to set keepalive: %w", err)
	}
	if err := conn.SetKeepAlivePeriod(1 * time.Second); err != nil {
		conn.Close()
		return nil, fmt.Errorf("connectTUNDeviceWithTimeout: failed to set keepalive period: %w", err)
	}
	return conn, nil
}

// ConnectToShimServiceWithTimeout is ConnectToShimService with a hard bound and
// a verified checkin: the dial, the RSDCheckin request and both replies must
// all complete within timeout, and the replies must say what RsdCheckinVerified
// requires. On any failure the connection is closed before returning. On
// success the deadline is cleared, so the caller owns the connection's timing
// from then on.
func ConnectToShimServiceWithTimeout(device DeviceEntry, service string, timeout time.Duration) (DeviceConnectionInterface, error) {
	if !device.SupportsRsd() {
		return nil, fmt.Errorf("ConnectToShimServiceWithTimeout: cannot connect to %s, missing tunnel address and RSD port", service)
	}
	port, err := RsdPortForService(device.Rsd, service)
	if err != nil {
		return nil, fmt.Errorf("ConnectToShimServiceWithTimeout: %w", err)
	}
	deadline := time.Now().Add(timeout)
	conn, err := connectTUNDeviceWithTimeout(device.Address, port, device, timeout)
	if err != nil {
		return nil, fmt.Errorf("ConnectToShimServiceWithTimeout: %s: %w", service, err)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ConnectToShimServiceWithTimeout: %s: failed to set deadline: %w", service, err)
	}
	if err := RsdCheckinVerified(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ConnectToShimServiceWithTimeout: %s: %w", service, err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ConnectToShimServiceWithTimeout: %s: failed to clear deadline: %w", service, err)
	}
	return NewDeviceConnectionWithRWC(conn), nil
}

// RsdHandshakeWithTimeout opens the RSD control channel at addr:port, reads the
// handshake (UDID and service table) and closes the channel again, all within
// timeout. d is used only for its userspace TUN fields, as in
// NewWithAddrPortDevice. Failures before the handshake wrap ErrRsdConnect.
func RsdHandshakeWithTimeout(addr string, port int, d DeviceEntry, timeout time.Duration) (RsdHandshakeResponse, error) {
	deadline := time.Now().Add(timeout)
	conn, err := connectTUNDeviceWithTimeout(addr, port, d, timeout)
	if err != nil {
		return RsdHandshakeResponse{}, fmt.Errorf("RsdHandshakeWithTimeout: %w: %w", ErrRsdConnect, err)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return RsdHandshakeResponse{}, fmt.Errorf("RsdHandshakeWithTimeout: %w: failed to set deadline: %w", ErrRsdConnect, err)
	}
	rsd, err := newRsdServiceFromTcpConn(conn)
	if err != nil {
		conn.Close()
		return RsdHandshakeResponse{}, fmt.Errorf("RsdHandshakeWithTimeout: %w: %w", ErrRsdConnect, err)
	}
	defer rsd.Close()
	res, err := rsd.Handshake()
	if err != nil {
		return RsdHandshakeResponse{}, fmt.Errorf("RsdHandshakeWithTimeout: %w", err)
	}
	return res, nil
}
