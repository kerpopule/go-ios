package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// THE SAME PAIRING PROTOCOL, A DIFFERENT BOTTOM LAYER.
//
// Over USB the RemotePairing control channel rides RemoteXPC (HTTP/2) and every
// message is wrapped as:
//
//	{"mangledTypeName": "RemotePairing.ControlChannelMessageEnvelope", "value": <body>}
//
// Over Wi-Fi the device advertises _remotepairing._tcp and speaks the SAME
// <body>, JSON-encoded, inside a trivial length-prefixed frame:
//
//	"RPPairing" | uint16 big-endian length | JSON body
//
// Nothing above this file changes. ManualPair, verifyPair, setupManualPairing,
// createTcpTunnelListener and the TLS-PSK tunnel are byte-for-byte the same on
// both transports, which is why this is an adapter and not a second protocol:
// rpPairingConn satisfies the existing xpcConn interface (codec.go), so
// controlChannelReadWriter cannot tell the two apart.
//
// Verified against two independent reimplementations of the same wire format
// (pymobiledevice3's RemotePairingTunnelService, jkcoxson/idevice's
// RpPairingSocket), which agree with each other byte for byte.

// rpPairingMagic prefixes every frame on the Wi-Fi control channel. The USB
// tunnel-establish packet uses a different magic ("CDTunnel") with the same
// uint16-length-then-JSON shape; they are not interchangeable.
var rpPairingMagic = []byte("RPPairing")

// rpPairingMaxFrame bounds a single frame. The length field is a uint16, so the
// device cannot exceed this, but reading it from a hostile or confused peer
// should still never allocate more than the protocol can express.
const rpPairingMaxFrame = 1 << 16

// rpPairingConn carries the RemotePairing control channel over a plain TCP
// socket. It is deliberately NOT safe for concurrent use: the pairing state
// machine above it is strictly request/response on one goroutine, and giving it
// a lock would hide a caller that had started doing something else.
type rpPairingConn struct {
	conn    net.Conn
	scratch []byte
}

// dialRemotePairing opens the Wi-Fi control channel to a device advertising
// _remotepairing._tcp. `address` is host:port; for an IPv6 link-local address
// the caller must already have attached the zone (for example
// "[fe80::1c61:b18:d18f:40b%en0]:49152"), because a link-local address without
// one is not routable and fails with "no route to host".
func dialRemotePairing(address string, timeout time.Duration) (*rpPairingConn, error) {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("dialRemotePairing: failed to reach %s: %w", address, err)
	}
	return &rpPairingConn{conn: conn, scratch: make([]byte, 0, 4096)}, nil
}

// dialRemotePairingVia is dialRemotePairing with the connection opened by dial (for example
// StreamsDialer) instead of a direct TCP connect, bounded by timeout. leg names the RemotePairing leg
// on a streams failure.
func dialRemotePairingVia(ctx context.Context, dial RemotePairingDialer, address string, timeout time.Duration, leg string) (*rpPairingConn, error) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dial(dctx, address)
	if err == nil && conn == nil {
		err = errors.New("dialer returned no connection")
	}
	if err != nil {
		tagStreamsLeg(err, leg)
		return nil, fmt.Errorf("dialRemotePairing: failed to reach %s: %w", address, err)
	}
	return &rpPairingConn{conn: conn, scratch: make([]byte, 0, 4096)}, nil
}

func (r *rpPairingConn) Close() error { return r.conn.Close() }

// SetDeadline bounds the whole handshake. A sleeping iPhone keeps advertising
// on Bonjour long after it stops answering TCP, so an unbounded read here waits
// for a device that is never going to speak.
func (r *rpPairingConn) SetDeadline(t time.Time) error { return r.conn.SetDeadline(t) }

// Send takes the envelope controlChannelReadWriter built for RemoteXPC, strips
// the wrapper it does not use, and writes the inner body as a framed JSON
// message. Flags are an XPC concept with no counterpart here and are ignored.
func (r *rpPairingConn) Send(data map[string]interface{}, _ ...uint32) error {
	body, ok := data["value"]
	if !ok {
		// Not an envelope: send it as-is rather than silently dropping it, so a
		// future caller that bypasses the envelope is visible on the wire
		// instead of vanishing.
		body = data
	}
	payload, err := json.Marshal(bytesToBase64(body))
	if err != nil {
		return fmt.Errorf("rpPairingConn.Send: failed to encode body: %w", err)
	}
	if len(payload) > rpPairingMaxFrame-1 {
		return fmt.Errorf("rpPairingConn.Send: body of %d bytes does not fit a uint16 frame", len(payload))
	}
	frame := make([]byte, 0, len(rpPairingMagic)+2+len(payload))
	frame = append(frame, rpPairingMagic...)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	frame = append(frame, payload...)
	if _, err := r.conn.Write(frame); err != nil {
		return fmt.Errorf("rpPairingConn.Send: failed to write frame: %w", err)
	}
	return nil
}

// ReceiveOnClientServerStream reads one frame and re-wraps it under "value",
// because that is the shape controlChannelReadWriter.read unwraps. The name is
// the xpcConn interface's, not a description of what happens here.
func (r *rpPairingConn) ReceiveOnClientServerStream() (map[string]interface{}, error) {
	header := make([]byte, len(rpPairingMagic)+2)
	if _, err := io.ReadFull(r.conn, header); err != nil {
		return nil, fmt.Errorf("rpPairingConn.Receive: failed to read frame header: %w", err)
	}
	if string(header[:len(rpPairingMagic)]) != string(rpPairingMagic) {
		return nil, fmt.Errorf("rpPairingConn.Receive: not a RemotePairing frame (magic %q)", header[:len(rpPairingMagic)])
	}
	size := binary.BigEndian.Uint16(header[len(rpPairingMagic):])
	payload := make([]byte, size)
	if _, err := io.ReadFull(r.conn, payload); err != nil {
		return nil, fmt.Errorf("rpPairingConn.Receive: failed to read %d byte body: %w", size, err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, fmt.Errorf("rpPairingConn.Receive: body is not JSON: %w", err)
	}
	return map[string]interface{}{"value": base64ToBytes(body)}, nil
}

// bytesToBase64 walks a message and turns every []byte into the base64 string
// this transport carries. A generic walk rather than a list of known fields,
// because the byte-carrying fields are spread across the protocol — the pairing
// data blob and the TLS pre-shared key in createListener are in different
// messages — and a list is a thing that goes out of date silently.
func bytesToBase64(value interface{}) interface{} {
	switch v := value.(type) {
	case []byte:
		return base64.StdEncoding.EncodeToString(v)
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, child := range v {
			out[key] = bytesToBase64(child)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, child := range v {
			out[i] = bytesToBase64(child)
		}
		return out
	default:
		return value
	}
}

// base64ToBytes is the inverse, and it is deliberately NOT generic.
//
// Going out, "this is a []byte" is unambiguous. Coming back, every byte field
// is just a JSON string, and a walk that base64-decoded every string it could
// would corrupt ordinary text: "kind" carries values like "setupManualPairing",
// and "sendingHost" carries a hostname — both of which decode as valid base64
// often enough to matter, and neither of which is bytes.
//
// So only the two fields the decoders above actually read as []byte are
// converted, named by the shape they sit in:
//
//	<anything>.pairingData._0.data   (pairingData.Decode, codec.go)
//	<anything>.streamEncrypted._0    (cipherStream.read, codec.go)
func base64ToBytes(value interface{}) interface{} {
	node, ok := value.(map[string]interface{})
	if !ok {
		if list, isList := value.([]interface{}); isList {
			for i, child := range list {
				list[i] = base64ToBytes(child)
			}
		}
		return value
	}
	for key, child := range node {
		switch key {
		case "pairingData":
			if inner, isMap := child.(map[string]interface{}); isMap {
				if zero, isMap := inner["_0"].(map[string]interface{}); isMap {
					decodeFieldInPlace(zero, "data")
				}
			}
		case "streamEncrypted":
			if inner, isMap := child.(map[string]interface{}); isMap {
				decodeFieldInPlace(inner, "_0")
			}
		}
		node[key] = base64ToBytes(child)
	}
	return node
}

// decodeFieldInPlace replaces one base64 string with its bytes. A field that is
// absent, already bytes, or not valid base64 is left exactly as it was: the
// decoder above it already handles "not the type I wanted" by ignoring the
// field, and turning a decode failure into an error here would fail a handshake
// over a field nothing was going to read.
func decodeFieldInPlace(node map[string]interface{}, field string) {
	text, ok := node[field].(string)
	if !ok {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return
	}
	node[field] = decoded
}
