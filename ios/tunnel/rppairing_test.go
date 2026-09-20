package tunnel

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

// A fake device on the other end of the Wi-Fi control channel. Real sockets on
// purpose: the thing under test is framing on a stream, and a stream that
// delivers a frame in two reads is exactly the case a hand-rolled parser gets
// wrong.
func rpPair(t *testing.T) (*rpPairingConn, net.Conn) {
	t.Helper()
	ours, theirs := net.Pipe()
	t.Cleanup(func() { _ = ours.Close(); _ = theirs.Close() })
	return &rpPairingConn{conn: ours}, theirs
}

// writeFrame is called from the fake-device goroutine, so it must NOT call
// t.Fatalf: a Fatal from a non-test goroutine can be attributed to the wrong
// test or swallowed entirely (go vet flags it). Failures come back as a value
// and the test reports them on its own goroutine.
func writeFrame(w io.Writer, body map[string]interface{}) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	frame := append([]byte(nil), rpPairingMagic...)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	frame = append(frame, payload...)
	_, err = w.Write(frame)
	return err
}

func readFrame(t *testing.T, r io.Reader) map[string]interface{} {
	t.Helper()
	header := make([]byte, len(rpPairingMagic)+2)
	if _, err := io.ReadFull(r, header); err != nil {
		t.Fatalf("read header: %v", err)
	}
	if string(header[:len(rpPairingMagic)]) != string(rpPairingMagic) {
		t.Fatalf("magic was %q, want %q", header[:len(rpPairingMagic)], rpPairingMagic)
	}
	payload := make([]byte, binary.BigEndian.Uint16(header[len(rpPairingMagic):]))
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatalf("read body: %v", err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	return body
}

// THE ENVELOPE IS A RemoteXPC THING AND MUST NOT REACH THE WIRE. Over USB every
// message is wrapped in {"mangledTypeName": ..., "value": body}; over Wi-Fi the
// device expects `body` alone. Sending the wrapper would be rejected by a
// device that never asked for it.
func TestSendStripsTheXpcEnvelope(t *testing.T) {
	conn, peer := rpPair(t)
	go func() {
		_ = conn.Send(map[string]interface{}{
			"mangledTypeName": "RemotePairing.ControlChannelMessageEnvelope",
			"value": map[string]interface{}{
				"message":        map[string]interface{}{"plain": map[string]interface{}{"_0": "hello"}},
				"originatedBy":   "host",
				"sequenceNumber": float64(3),
			},
		})
	}()

	body := readFrame(t, peer)
	if _, leaked := body["mangledTypeName"]; leaked {
		t.Fatal("the RemoteXPC envelope reached the wire")
	}
	if body["originatedBy"] != "host" {
		t.Fatalf("body was not the envelope's value: %v", body)
	}
	if body["sequenceNumber"] != float64(3) {
		t.Fatalf("sequenceNumber did not survive: %v", body["sequenceNumber"])
	}
}

// BYTES TRAVEL AS BASE64, WHEREVER THEY SIT. The two byte-carrying fields live
// in different messages — the pairing blob and the TLS pre-shared key in
// createListener — so this is a walk, not a list of known fields.
func TestSendEncodesEveryByteFieldAsBase64(t *testing.T) {
	conn, peer := rpPair(t)
	secret := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	blob := []byte("pairing-data")
	go func() {
		_ = conn.Send(map[string]interface{}{"value": map[string]interface{}{
			"message": map[string]interface{}{
				"plain": map[string]interface{}{"_0": map[string]interface{}{
					"request": map[string]interface{}{"_0": map[string]interface{}{
						"createListener": map[string]interface{}{"key": secret, "transportProtocolType": "tcp"},
					}},
					"event": map[string]interface{}{"_0": map[string]interface{}{
						"pairingData": map[string]interface{}{"_0": map[string]interface{}{"data": blob, "kind": "setupManualPairing"}},
					}},
				}},
			},
		}})
	}()

	body := readFrame(t, peer)
	plain := body["message"].(map[string]interface{})["plain"].(map[string]interface{})["_0"].(map[string]interface{})
	listener := plain["request"].(map[string]interface{})["_0"].(map[string]interface{})["createListener"].(map[string]interface{})
	if got := listener["key"]; got != base64.StdEncoding.EncodeToString(secret) {
		t.Fatalf("createListener.key was not base64: %v", got)
	}
	if listener["transportProtocolType"] != "tcp" {
		t.Fatal("a neighbouring string was mangled")
	}
	pairing := plain["event"].(map[string]interface{})["_0"].(map[string]interface{})["pairingData"].(map[string]interface{})["_0"].(map[string]interface{})
	if got := pairing["data"]; got != base64.StdEncoding.EncodeToString(blob) {
		t.Fatalf("pairingData.data was not base64: %v", got)
	}
	if pairing["kind"] != "setupManualPairing" {
		t.Fatalf("kind was rewritten: %v", pairing["kind"])
	}
}

// COMING BACK, ONLY THE FIELDS THAT ARE REALLY BYTES ARE DECODED.
//
// This is the asymmetry that makes a generic walk wrong in this direction. Over
// the wire a byte field and a text field are both JSON strings, and plenty of
// ordinary text is valid base64: "setupManualPairing" decodes cleanly. A walk
// that decoded every string it could would hand the pairing state machine bytes
// where it expects a word, and the handshake would fail for no visible reason.
func TestReceiveDecodesOnlyRealByteFields(t *testing.T) {
	conn, peer := rpPair(t)
	blob := []byte{0x01, 0x02, 0x03}
	go func() {
		_ = writeFrame(peer, map[string]interface{}{
			"message": map[string]interface{}{
				"plain": map[string]interface{}{"_0": map[string]interface{}{
					"event": map[string]interface{}{"_0": map[string]interface{}{
						"pairingData": map[string]interface{}{"_0": map[string]interface{}{
							"data":        base64.StdEncoding.EncodeToString(blob),
							"kind":        "setupManualPairing",
							"sendingHost": "Steves-MacBook-Pro",
						}},
					}},
				}},
			},
		})
	}()

	got, err := conn.ReceiveOnClientServerStream()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	value, ok := got["value"].(map[string]interface{})
	if !ok {
		t.Fatalf(`the reply was not re-wrapped under "value": %v`, got)
	}
	plain := value["message"].(map[string]interface{})["plain"].(map[string]interface{})["_0"].(map[string]interface{})
	pairing := plain["event"].(map[string]interface{})["_0"].(map[string]interface{})["pairingData"].(map[string]interface{})["_0"].(map[string]interface{})

	data, isBytes := pairing["data"].([]byte)
	if !isBytes {
		t.Fatalf("pairingData.data came back as %T, not []byte — pairingData.Decode would have ignored it", pairing["data"])
	}
	if string(data) != string(blob) {
		t.Fatalf("pairingData.data round-tripped wrong: %v", data)
	}
	// "setupManualPairing" IS valid base64. If this comes back as bytes, the
	// decode walk is too eager and the handshake breaks on a field nobody
	// would think to look at.
	if kind, isString := pairing["kind"].(string); !isString || kind != "setupManualPairing" {
		t.Fatalf("kind was base64-decoded: %#v", pairing["kind"])
	}
	if host, isString := pairing["sendingHost"].(string); !isString || host != "Steves-MacBook-Pro" {
		t.Fatalf("sendingHost was base64-decoded: %#v", pairing["sendingHost"])
	}
}

func TestReceiveDecodesTheEncryptedStream(t *testing.T) {
	conn, peer := rpPair(t)
	ciphertext := []byte{0xaa, 0xbb, 0xcc}
	go func() {
		_ = writeFrame(peer, map[string]interface{}{
			"message": map[string]interface{}{"streamEncrypted": map[string]interface{}{"_0": base64.StdEncoding.EncodeToString(ciphertext)}},
		})
	}()

	got, err := conn.ReceiveOnClientServerStream()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	message := got["value"].(map[string]interface{})["message"].(map[string]interface{})
	stream := message["streamEncrypted"].(map[string]interface{})
	if _, isBytes := stream["_0"].([]byte); !isBytes {
		t.Fatalf("streamEncrypted._0 came back as %T — cipherStream.read would have refused it", stream["_0"])
	}
}

// THE WHOLE CONTROL CHANNEL, UNMODIFIED, OVER THIS TRANSPORT. The point of the
// adapter is that controlChannelReadWriter cannot tell which socket it is on.
func TestControlChannelRunsUnchangedOverRemotePairing(t *testing.T) {
	conn, peer := rpPair(t)
	channel := newControlChannelReadWriter(conn)

	go func() {
		body := readFrame(t, peer)
		// Answer with the same shape the device does.
		_ = writeFrame(peer, map[string]interface{}{
			"message":        map[string]interface{}{"plain": map[string]interface{}{"_0": map[string]interface{}{"echoed": body["sequenceNumber"]}}},
			"originatedBy":   "device",
			"sequenceNumber": float64(0),
		})
	}()

	if err := channel.write(map[string]interface{}{"plain": map[string]interface{}{"_0": "handshake"}}); err != nil {
		t.Fatalf("write: %v", err)
	}
	message, err := channel.read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	plain, ok := message["plain"].(map[string]interface{})
	if !ok {
		t.Fatalf("read did not unwrap to the message: %v", message)
	}
	// newControlChannelReadWriter starts the sequence at 1, not 0 — the number
	// this echoes back is the one the real device would have seen.
	if plain["_0"].(map[string]interface{})["echoed"] != float64(1) {
		t.Fatalf("the first message did not carry the channel's own sequence number: %v", plain)
	}
}

// A FRAME SPLIT ACROSS READS IS THE NORMAL CASE ON A TCP SOCKET, and a parser
// that assumes one read per frame works on a pipe and fails on a network.
func TestReceiveHandlesASplitFrame(t *testing.T) {
	conn, peer := rpPair(t)
	payload, _ := json.Marshal(map[string]interface{}{"message": map[string]interface{}{"plain": map[string]interface{}{"_0": "split"}}})
	frame := append([]byte(nil), rpPairingMagic...)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	frame = append(frame, payload...)

	go func() {
		for _, chunk := range [][]byte{frame[:4], frame[4 : len(rpPairingMagic)+2], frame[len(rpPairingMagic)+2:]} {
			_, _ = peer.Write(chunk)
			time.Sleep(time.Millisecond)
		}
	}()

	got, err := conn.ReceiveOnClientServerStream()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	plain := got["value"].(map[string]interface{})["message"].(map[string]interface{})["plain"].(map[string]interface{})
	if plain["_0"] != "split" {
		t.Fatalf("a split frame was not reassembled: %v", plain)
	}
}

func TestReceiveRefusesAFrameThatIsNotRemotePairing(t *testing.T) {
	conn, peer := rpPair(t)
	// The USB tunnel-establish packet: same shape, different magic. Reading one
	// as the other would produce nonsense rather than an error.
	go func() {
		frame := append([]byte("CDTunnel"), 0x00, 0x02, '{', '}')
		_, _ = peer.Write(frame)
	}()
	if _, err := conn.ReceiveOnClientServerStream(); err == nil {
		t.Fatal("a CDTunnel frame was accepted as a RemotePairing frame")
	}
}

func TestReceiveRefusesABodyThatIsNotJson(t *testing.T) {
	conn, peer := rpPair(t)
	go func() {
		frame := append([]byte(nil), rpPairingMagic...)
		frame = binary.BigEndian.AppendUint16(frame, 3)
		_, _ = peer.Write(append(frame, 'n', 'o', 't'))
	}()
	if _, err := conn.ReceiveOnClientServerStream(); err == nil {
		t.Fatal("a non-JSON body was accepted")
	}
}
