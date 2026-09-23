package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// LOOPBACK STREAMS (coagent-tunnel-v1 revision 4, §8–§9).
//
// On cellular, iOS refuses NEW TCP connections to the phone's RemotePairing port when they arrive on
// the Co-Agent packet tunnel, but the listener still accepts on the phone's own loopback. The phone's
// tunnel extension therefore opens TCP to 127.0.0.1:<port> itself, on request, and carries the byte
// stream inside the tunnel's end-to-end channel. On this Mac the desk peer exposes each such stream as
// a SOCKS5 CONNECT on a unix socket. This file is the client for that socket: a deliberately small
// RFC 1928 implementation (no auth, CONNECT only), because golang.org/x/net/proxy hides the reply
// code, and the reply code is the only way to tell "the phone is not linked" from "the phone refused".
//
// The desk accepts exactly two target forms, and so does this client:
//
//	phone:<port>      ATYP 03, the 5-byte name "phone"
//	127.0.0.1:<port>  ATYP 01
//
// with <port> in 49152–65535 (the RemotePairing front door and its per-session tunnel listener). Any
// other target is refused here, before the socket is touched.

// RemotePairingDialer opens the byte stream that a RemotePairing leg rides on. address is
// "host:port". The returned conn must support deadlines: the control channel bounds its handshake with
// SetDeadline. A nil RemotePairingDialer means "dial TCP directly", the original behaviour.
type RemotePairingDialer func(ctx context.Context, address string) (net.Conn, error)

// StreamsDialer returns a RemotePairingDialer that opens every leg through the desk peer's
// loopback-streams SOCKS5 socket at socketPath.
func StreamsDialer(socketPath string) RemotePairingDialer {
	return func(ctx context.Context, address string) (net.Conn, error) {
		return DialViaStreams(ctx, socketPath, address)
	}
}

// The words a streams failure is reported as (§9 of the rev-4 contract). The daemon keys off these, so
// they are part of the contract, not prose.
const (
	StreamsSocketUnavailable       = "socket_unavailable"
	StreamsSocksProtocol           = "socks_protocol"
	StreamsGeneralFailure          = "general_failure"
	StreamsNotAllowed              = "not_allowed"
	StreamsPhoneNotLinked          = "phone_not_linked"
	StreamsTimeout                 = "timeout"
	StreamsConnectionRefused       = "connection_refused"
	StreamsCommandNotSupported     = "command_not_supported"
	StreamsAddressTypeNotSupported = "address_type_not_supported"
	// StreamsBadTarget is local: the target is not one the desk would accept, so nothing was sent.
	StreamsBadTarget = "bad_target"
)

// Which RemotePairing leg a streams failure happened on. The difference matters: the front door
// (:49152) refusing means loopback is closed to the extension; the front door working and the tunnel
// port refusing means the per-session listener is not bound where loopback can reach it (§13.2).
const (
	StreamsLegControl    = "control"
	StreamsLegTunnelPort = "tunnel_port"
)

// Streams port range. Anything outside it is refused by both the desk and the phone.
const (
	StreamsMinPort = 49152
	StreamsMaxPort = 65535
)

// streamsPhoneHost is the one domain name the desk accepts (ATYP 03).
const streamsPhoneHost = "phone"

// StreamsError is why a dial through the loopback-streams socket failed.
type StreamsError struct {
	// Word is one of the Streams* words above.
	Word string
	// Rep is the SOCKS5 reply code, or -1 when the failure was not a reply (dial, framing, deadline,
	// bad target).
	Rep int
	// Target is the host:port that was asked for.
	Target string
	// Leg is StreamsLegControl or StreamsLegTunnelPort when a RemotePairing caller knows which leg
	// this was, and "" otherwise.
	Leg string
	// Err is the underlying cause, when there is one.
	Err error
}

func (e *StreamsError) Unwrap() error { return e.Err }

func (e *StreamsError) Error() string {
	msg := "loopback streams " + e.Word
	if e.Target != "" {
		msg += " for " + e.Target
	}
	if e.Rep >= 0 {
		msg += fmt.Sprintf(" (SOCKS reply 0x%02x)", e.Rep)
	}
	if explain := streamsExplanation(e.Word); explain != "" {
		msg += ": " + explain
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// streamsExplanation says what a word usually means, and where the phone's own reason is kept.
func streamsExplanation(word string) string {
	const status = "the phone's own reason is in tunnel-peer-status.json streams.lastFailure"
	switch word {
	case StreamsSocketUnavailable:
		return "the desk peer's streams socket did not accept a connection (peer not running, started with --no-streams, or a different --streams-socket path)"
	case StreamsSocksProtocol:
		return "whatever answered on the streams socket did not speak the desk peer's SOCKS5"
	case StreamsGeneralFailure:
		return "the desk or phone refused the stream (phone build predates loopback streams, too many streams, or the phone failed the open); " + status
	case StreamsNotAllowed:
		return "the port was not allowed, or the phone was denied the loopback connection; " + status
	case StreamsPhoneNotLinked:
		return "the phone is not linked to this Mac through the relay right now (Away from desk off, or the link epoch ended)"
	case StreamsTimeout:
		return "the phone did not open the stream in time; " + status
	case StreamsConnectionRefused:
		return "nothing on the phone accepted on that loopback port; " + status
	case StreamsCommandNotSupported, StreamsAddressTypeNotSupported:
		return "the desk peer refused the SOCKS request form"
	case StreamsBadTarget:
		return "the target must be phone:PORT or 127.0.0.1:PORT with PORT in 49152-65535"
	}
	return ""
}

// streamsReplyWord maps a SOCKS5 reply code to its word. A code the desk never sends is reported as
// general_failure; the code itself survives in StreamsError.Rep.
func streamsReplyWord(rep byte) string {
	switch rep {
	case 0x01:
		return StreamsGeneralFailure
	case 0x02:
		return StreamsNotAllowed
	case 0x03:
		return StreamsPhoneNotLinked
	case 0x04:
		return StreamsTimeout
	case 0x05:
		return StreamsConnectionRefused
	case 0x07:
		return StreamsCommandNotSupported
	case 0x08:
		return StreamsAddressTypeNotSupported
	default:
		return StreamsGeneralFailure
	}
}

// ValidateStreamsTarget reports whether hostPort is a target the desk accepts, without dialing.
func ValidateStreamsTarget(hostPort string) error {
	_, err := encodeStreamsTarget(hostPort)
	return err
}

// encodeStreamsTarget turns a target into the ATYP/ADDR/PORT tail of a SOCKS5 request.
func encodeStreamsTarget(hostPort string) ([]byte, error) {
	bad := func(why string) error {
		return &StreamsError{Word: StreamsBadTarget, Rep: -1, Target: hostPort, Err: errors.New(why)}
	}
	host, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, bad("not host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, bad("port is not a number")
	}
	if port < StreamsMinPort || port > StreamsMaxPort {
		return nil, bad(fmt.Sprintf("port %d is outside 49152-65535", port))
	}
	var tail []byte
	switch host {
	case streamsPhoneHost:
		tail = append([]byte{0x03, byte(len(streamsPhoneHost))}, streamsPhoneHost...)
	case "127.0.0.1":
		tail = []byte{0x01, 127, 0, 0, 1}
	default:
		return nil, bad("host must be phone or 127.0.0.1: the phone only ever connects to its own loopback")
	}
	return append(tail, byte(port>>8), byte(port)), nil
}

// tagStreamsLeg records which RemotePairing leg a streams failure happened on. The *StreamsError it
// finds was just built by DialViaStreams for this one call, so setting the field is not shared state.
func tagStreamsLeg(err error, leg string) {
	var se *StreamsError
	if errors.As(err, &se) && se.Leg == "" {
		se.Leg = leg
	}
}

// aLongTimeAgo is a deadline in the past, used to abort blocked I/O when ctx is cancelled.
var aLongTimeAgo = time.Unix(1, 0)

// DialViaStreams opens a stream to the phone's loopback hostPort through the desk peer's SOCKS5 unix
// socket at socketPath. The whole exchange (dial, greeting, request, reply) is bounded by ctx; once
// the reply is in, the deadline is cleared and the conn is a raw byte pipe to the phone.
//
// Every failure is a *StreamsError. An abort of an established stream (epoch end, RST from the phone)
// reads as EOF: unix sockets have no reset, so the layers above detect truncation themselves.
func DialViaStreams(ctx context.Context, socketPath, hostPort string) (net.Conn, error) {
	tail, err := encodeStreamsTarget(hostPort)
	if err != nil {
		return nil, err
	}
	fail := func(word string, rep int, cause error) error {
		return &StreamsError{Word: word, Rep: rep, Target: hostPort, Err: cause}
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fail(StreamsSocketUnavailable, -1, err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, fail(StreamsSocketUnavailable, -1, fmt.Errorf("failed to bound the SOCKS handshake: %w", err))
		}
	}
	// A cancelled ctx with no deadline still has to unblock a read that the desk never answers.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(aLongTimeAgo) })

	err = socksConnect(conn, tail)
	if !stop() && err == nil {
		// ctx ended in the instant between the reply and here; its deadline may already be on the socket.
		err = &StreamsError{Word: StreamsTimeout, Rep: -1, Err: fmt.Errorf("gave up waiting for the SOCKS reply: %w", context.Cause(ctx))}
	}
	if err != nil {
		_ = conn.Close()
		var se *StreamsError
		if errors.As(err, &se) {
			se.Target = hostPort
			return nil, se
		}
		return nil, fail(StreamsSocksProtocol, -1, err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fail(StreamsSocketUnavailable, -1, fmt.Errorf("failed to clear the SOCKS handshake deadline: %w", err))
	}
	return conn, nil
}

// socksConnect runs greeting, request and reply on conn. It reads exactly the bytes the reply holds and
// nothing more, so the first byte the phone sends after the reply is the first byte the caller reads.
func socksConnect(conn net.Conn, tail []byte) error {
	readErr := func(stage string, err error) error {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return &StreamsError{Word: StreamsTimeout, Rep: -1, Err: fmt.Errorf("no SOCKS %s from the desk peer before the deadline: %w", stage, err)}
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return &StreamsError{Word: StreamsSocksProtocol, Rep: -1, Err: fmt.Errorf("the desk peer closed the socket during the SOCKS %s (too many clients, or this user is not allowed on the socket): %w", stage, err)}
		}
		return &StreamsError{Word: StreamsSocksProtocol, Rep: -1, Err: fmt.Errorf("SOCKS %s: %w", stage, err)}
	}
	protocolErr := func(format string, args ...any) error {
		return &StreamsError{Word: StreamsSocksProtocol, Rep: -1, Err: fmt.Errorf(format, args...)}
	}

	// Greeting: version 5, one method, "no authentication".
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return readErr("greeting", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		return readErr("method selection", err)
	}
	if method[0] != 0x05 {
		return protocolErr("method selection has version 0x%02x, want 0x05", method[0])
	}
	if method[1] == 0xFF {
		return protocolErr("the server refused the no-authentication method (reply 05 FF): this is not the desk peer's streams socket")
	}
	if method[1] != 0x00 {
		return protocolErr("the server chose method 0x%02x, which was not offered", method[1])
	}

	// Request: version 5, CONNECT, reserved, then the target.
	request := append([]byte{0x05, 0x01, 0x00}, tail...)
	if _, err := conn.Write(request); err != nil {
		return readErr("request", err)
	}

	// Reply: VER REP RSV ATYP, then BND.ADDR and BND.PORT. The desk always sends ATYP 01 (10 bytes in
	// all), but the address is skipped by its declared type so a reply of another legal shape can never
	// leave bytes behind to corrupt the stream.
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return readErr("reply", err)
	}
	if head[0] != 0x05 {
		return protocolErr("reply has version 0x%02x, want 0x05", head[0])
	}
	if rep := head[1]; rep != 0x00 {
		return &StreamsError{Word: streamsReplyWord(rep), Rep: int(rep)}
	}
	var rest int
	switch head[3] {
	case 0x01:
		rest = 4 + 2
	case 0x04:
		rest = 16 + 2
	case 0x03:
		n := make([]byte, 1)
		if _, err := io.ReadFull(conn, n); err != nil {
			return readErr("reply", err)
		}
		rest = int(n[0]) + 2
	default:
		return protocolErr("reply has address type 0x%02x", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, rest)); err != nil {
		return readErr("reply", err)
	}
	return nil
}
