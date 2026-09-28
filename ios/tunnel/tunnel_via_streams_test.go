package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// BOTH LEGS THROUGH THE SOCKET. These run the real RemotePairing client (handshake, pair-verify,
// createTcpTunnelListener, TLS-PSK) against a fake phone that sits behind the fake desk, so the thing
// proven is the threading: the control channel AND the tunnel-port dial each arrive as a SOCKS
// request with the right target, and nothing reaches the network.

// fakeRemotePairingPhone plays the phone's side of the RemotePairing control channel far enough for
// pair-verify to succeed and createListener to answer. It does not check the host's signature — the
// host code under test is what is being exercised, not a device's policy.
type fakeRemotePairingPhone struct {
	// listenerPort is what createListener answers; 0 stops after pair-verify (the verify command).
	listenerPort uint16
}

func readDeviceFrame(r io.Reader) (map[string]interface{}, error) {
	header := make([]byte, len(rpPairingMagic)+2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("frame header: %w", err)
	}
	if !bytes.Equal(header[:len(rpPairingMagic)], rpPairingMagic) {
		return nil, fmt.Errorf("magic %q", header[:len(rpPairingMagic)])
	}
	payload := make([]byte, binary.BigEndian.Uint16(header[len(rpPairingMagic):]))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("frame body: %w", err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, err
	}
	return body, nil
}

func writeDeviceMessage(w io.Writer, message map[string]interface{}) error {
	return writeFrame(w, map[string]interface{}{
		"message":        message,
		"originatedBy":   "device",
		"sequenceNumber": float64(0),
	})
}

func deviceEvent(tlv []byte) map[string]interface{} {
	return map[string]interface{}{"plain": map[string]interface{}{"_0": map[string]interface{}{
		"event": map[string]interface{}{"_0": map[string]interface{}{
			"pairingData": map[string]interface{}{"_0": map[string]interface{}{
				"data": base64.StdEncoding.EncodeToString(tlv), "kind": "verifyManualPairing", "startNewSession": false,
			}},
		}},
	}}}
}

func hostPairingData(body map[string]interface{}) (kind string, data []byte, err error) {
	message, _ := body["message"].(map[string]interface{})
	pd, err := getChildMap(message, "plain", "_0", "event", "_0", "pairingData", "_0")
	if err != nil {
		return "", nil, err
	}
	kind, _ = pd["kind"].(string)
	text, _ := pd["data"].(string)
	data, err = base64.StdEncoding.DecodeString(text)
	return kind, data, err
}

func (f fakeRemotePairingPhone) serve(c net.Conn) error {
	// 1. The handshake request. Its answer's content is ignored by the host.
	body, err := readDeviceFrame(c)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	message, _ := body["message"].(map[string]interface{})
	if _, err := getChildMap(message, "plain", "_0", "request", "_0", "handshake"); err != nil {
		return fmt.Errorf("first message was not the handshake: %v", body)
	}
	if err := writeDeviceMessage(c, map[string]interface{}{"plain": map[string]interface{}{"_0": map[string]interface{}{
		"response": map[string]interface{}{"_1": map[string]interface{}{"handshake": map[string]interface{}{}}},
	}}}); err != nil {
		return err
	}

	// 2. Pair-verify M1 → M2: the host's X25519 key in, ours out.
	body, err = readDeviceFrame(c)
	if err != nil {
		return fmt.Errorf("verify M1: %w", err)
	}
	kind, data, err := hostPairingData(body)
	if err != nil || kind != "verifyManualPairing" {
		return fmt.Errorf("verify M1 was %q (%v)", kind, err)
	}
	hostPub, err := tlvReader(data).readCoalesced(typePublicKey)
	if err != nil {
		return err
	}
	hostKey, err := ecdh.X25519().NewPublicKey(hostPub)
	if err != nil {
		return err
	}
	ours, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	shared, err := ours.ECDH(hostKey)
	if err != nil {
		return err
	}
	m2 := newTlvBuffer()
	m2.writeByte(typeState, pairStateStartResponse)
	m2.writeData(typePublicKey, ours.PublicKey().Bytes())
	if err := writeDeviceMessage(c, deviceEvent(m2.bytes())); err != nil {
		return err
	}

	// 3. Pair-verify M3 → M4 with no error: verified.
	body, err = readDeviceFrame(c)
	if err != nil {
		return fmt.Errorf("verify M3: %w", err)
	}
	if kind, _, err := hostPairingData(body); err != nil || kind != "verifyManualPairing" {
		return fmt.Errorf("verify M3 was %q (%v)", kind, err)
	}
	m4 := newTlvBuffer()
	m4.writeByte(typeState, pairStateVerifyResponse)
	if err := writeDeviceMessage(c, deviceEvent(m4.bytes())); err != nil {
		return err
	}
	if f.listenerPort == 0 {
		return drainUntilClosed(c)
	}

	// 4. createListener, sealed with the session keys derived from the pair-verify secret.
	clientKey, serverKey := make([]byte, 32), make([]byte, 32)
	if _, err := hkdf.New(sha512.New, shared, nil, []byte("ClientEncrypt-main")).Read(clientKey); err != nil {
		return err
	}
	if _, err := hkdf.New(sha512.New, shared, nil, []byte("ServerEncrypt-main")).Read(serverKey); err != nil {
		return err
	}
	fromHost, _ := chacha20poly1305.New(clientKey)
	toHost, _ := chacha20poly1305.New(serverKey)
	nonce := make([]byte, chacha20poly1305.NonceSize)

	body, err = readDeviceFrame(c)
	if err != nil {
		return fmt.Errorf("createListener: %w", err)
	}
	message, _ = body["message"].(map[string]interface{})
	enc, _ := getChildMap(message, "streamEncrypted")
	sealed, err := base64.StdEncoding.DecodeString(fmt.Sprint(enc["_0"]))
	if err != nil {
		return fmt.Errorf("createListener was not streamEncrypted: %v", body)
	}
	plain, err := fromHost.Open(nil, nonce, sealed, nil)
	if err != nil {
		return fmt.Errorf("createListener did not open with the session key: %w", err)
	}
	var request map[string]interface{}
	if err := json.Unmarshal(plain, &request); err != nil {
		return err
	}
	listener, err := getChildMap(request, "request", "_0", "createListener")
	if err != nil {
		return err
	}
	if listener["transportProtocolType"] != "tcp" || listener["key"] != base64.StdEncoding.EncodeToString(shared) {
		return fmt.Errorf("createListener asked for %v, want tcp keyed by the pair-verify secret", listener["transportProtocolType"])
	}
	reply, _ := json.Marshal(map[string]interface{}{"response": map[string]interface{}{"_1": map[string]interface{}{
		"createListener": map[string]interface{}{"port": float64(f.listenerPort)},
	}}})
	if err := writeDeviceMessage(c, map[string]interface{}{"streamEncrypted": map[string]interface{}{
		"_0": base64.StdEncoding.EncodeToString(toHost.Seal(nil, nonce, reply, nil)),
	}}); err != nil {
		return err
	}
	return drainUntilClosed(c)
}

// drainUntilClosed holds a stream open until the host closes it, as the phone's end would.
func drainUntilClosed(c net.Conn) error {
	_, _ = io.Copy(io.Discard, c)
	return nil
}

// socksThen accepts one SOCKS request, checks its target, replies success and hands the stream on.
func socksThen(wantHost string, wantPort int, next func(net.Conn) error) func(net.Conn) error {
	return func(c net.Conn) error {
		req, err := readSocksRequest(c)
		if err != nil {
			return err
		}
		if req.host != wantHost || (wantPort != 0 && req.port != wantPort) {
			return fmt.Errorf("SOCKS target was %s:%d, want %s:%d", req.host, req.port, wantHost, wantPort)
		}
		if _, err := c.Write(socksReply(0x00)); err != nil {
			return err
		}
		return next(c)
	}
}

// socksRefuse accepts one SOCKS request for the given target and refuses it with rep.
func socksRefuse(wantHost string, wantPort int, rep byte) func(net.Conn) error {
	return func(c net.Conn) error {
		req, err := readSocksRequest(c)
		if err != nil {
			return err
		}
		if req.host != wantHost || req.port != wantPort {
			return fmt.Errorf("SOCKS target was %s:%d, want %s:%d", req.host, req.port, wantHost, wantPort)
		}
		_, err = c.Write(socksReply(rep))
		return err
	}
}

// expectTLSClientHello reads the first TLS record header on the tunnel-port stream: proof that the
// TLS-PSK handshake itself rides the stream. Then it hangs up, which ends the test before the utun.
func expectTLSClientHello(c net.Conn) error {
	head := make([]byte, 3)
	if _, err := io.ReadFull(c, head); err != nil {
		return fmt.Errorf("tunnel port stream carried nothing: %w", err)
	}
	if head[0] != 0x16 || head[1] != 0x03 {
		return fmt.Errorf("tunnel port stream began %x, want a TLS handshake record", head)
	}
	return nil
}

func testPairRecords(t *testing.T) PairRecordManager {
	t.Helper()
	pm, err := NewPairRecordManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewPairRecordManager: %v", err)
	}
	return pm
}

func TestVerifyRemotePairingViaRidesTheStreamsSocket(t *testing.T) {
	desk := newFakeDesk(t, socksThen("phone", 49152, fakeRemotePairingPhone{}.serve))
	if err := VerifyRemotePairingVia("phone:49152", 5*time.Second, testPairRecords(t), StreamsDialer(desk.path)); err != nil {
		t.Fatalf("VerifyRemotePairingVia: %v", err)
	}
	desk.wait(t, 1)
}

// The direct road is untouched by the refactor: same fake phone, plain TCP, no dialer.
func TestVerifyRemotePairingDirectStillDialsTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	served := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			served <- err
			return
		}
		defer func() { _ = c.Close() }()
		served <- fakeRemotePairingPhone{}.serve(c)
	}()
	if err := VerifyRemotePairing(ln.Addr().String(), 5*time.Second, testPairRecords(t)); err != nil {
		t.Fatalf("VerifyRemotePairing: %v", err)
	}
	if err := <-served; err != nil {
		t.Fatalf("fake phone: %v", err)
	}
}

func TestVerifyRemotePairingViaReportsTheReplyWord(t *testing.T) {
	desk := newFakeDesk(t, socksRefuse("phone", 49152, 0x03))
	err := VerifyRemotePairingVia("phone:49152", 5*time.Second, testPairRecords(t), StreamsDialer(desk.path))
	se := streamsErr(t, err)
	if se.Word != StreamsPhoneNotLinked || se.Rep != 3 || se.Leg != StreamsLegControl {
		t.Fatalf("got word %q rep %d leg %q, want phone_not_linked 3 control", se.Word, se.Rep, se.Leg)
	}
	desk.wait(t, 1)
}

// THE SECOND DIAL. After createListener names port P, the TLS-PSK leg must go through the same socket
// to the same host (phone:P, or 127.0.0.1:P when --at used that), not to the network.
func TestConnectToTunnelOverRemotePairingViaDialsTheTunnelPortThroughTheSocket(t *testing.T) {
	const listenerPort = 58783
	for _, tc := range []struct{ at, host string }{
		{"phone:49152", "phone"},
		{"127.0.0.1:49152", "127.0.0.1"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			desk := newFakeDesk(t,
				socksThen(tc.host, 49152, fakeRemotePairingPhone{listenerPort: listenerPort}.serve),
				socksThen(tc.host, listenerPort, expectTLSClientHello),
			)
			_, err := ConnectToTunnelOverRemotePairingAtVia(context.Background(), tc.at, ios.DeviceEntry{}, testPairRecords(t), StreamsDialer(desk.path))
			if err == nil {
				t.Fatal("the fake phone hangs up the TLS-PSK handshake, so this must fail")
			}
			if !strings.Contains(err.Error(), "TLS-PSK handshake on "+net.JoinHostPort(tc.host, "58783")) {
				t.Fatalf("want the failure at the TLS-PSK handshake on the streamed tunnel port, got %v", err)
			}
			desk.wait(t, 2)
		})
	}
}

// The front door working and the tunnel port refusing is the contract's risk 13.2 (the per-session
// listener not reachable on loopback). It must be reported as the tunnel-port leg, not the control one.
func TestConnectToTunnelOverRemotePairingViaNamesTheTunnelPortLeg(t *testing.T) {
	const listenerPort = 60001
	desk := newFakeDesk(t,
		socksThen("phone", 49152, fakeRemotePairingPhone{listenerPort: listenerPort}.serve),
		socksRefuse("phone", listenerPort, 0x05),
	)
	_, err := ConnectToTunnelOverRemotePairingAtVia(context.Background(), "phone:49152", ios.DeviceEntry{}, testPairRecords(t), StreamsDialer(desk.path))
	se := streamsErr(t, err)
	if se.Word != StreamsConnectionRefused || se.Rep != 5 || se.Leg != StreamsLegTunnelPort || se.Target != "phone:60001" {
		t.Fatalf("got word %q rep %d leg %q target %q, want connection_refused 5 tunnel_port phone:60001", se.Word, se.Rep, se.Leg, se.Target)
	}
	desk.wait(t, 2)
}

func TestConnectToTunnelOverRemotePairingViaNamesTheControlLeg(t *testing.T) {
	desk := newFakeDesk(t, socksRefuse("phone", 49152, 0x01))
	_, err := ConnectToTunnelOverRemotePairingAtVia(context.Background(), "phone:49152", ios.DeviceEntry{}, testPairRecords(t), StreamsDialer(desk.path))
	se := streamsErr(t, err)
	if se.Word != StreamsGeneralFailure || se.Leg != StreamsLegControl {
		t.Fatalf("got word %q leg %q, want general_failure control", se.Word, se.Leg)
	}
	desk.wait(t, 1)
}

// A stream that opens and then carries nothing on the tunnel port must not hold the caller forever:
// the TLS-PSK handshake on the streamed leg is bounded.
func TestDialTunnelPortViaBoundsTheHandshake(t *testing.T) {
	var phones []net.Conn
	t.Cleanup(func() {
		for _, p := range phones {
			_ = p.Close()
		}
	})
	silent := func(ctx context.Context, address string) (net.Conn, error) {
		ours, theirs := net.Pipe()
		phones = append(phones, theirs)
		go func() { _, _ = io.Copy(io.Discard, theirs) }() // swallow the ClientHello, never answer
		return shortDeadlineConn{Conn: ours, max: 200 * time.Millisecond}, nil
	}
	start := time.Now()
	_, err := dialTunnelPortVia(context.Background(), silent, "phone", 58783, make([]byte, 32))
	if err == nil || !strings.Contains(err.Error(), "TLS-PSK handshake on phone:58783") {
		t.Fatalf("want a bounded TLS-PSK failure, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %v to give up on a silent tunnel port", elapsed)
	}
}

// shortDeadlineConn caps any deadline set on it, so a test can observe a bounded handshake without
// waiting out the production 15 s.
type shortDeadlineConn struct {
	net.Conn
	max time.Duration
}

func (s shortDeadlineConn) SetDeadline(t time.Time) error {
	if !t.IsZero() && time.Until(t) > s.max {
		t = time.Now().Add(s.max)
	}
	return s.Conn.SetDeadline(t)
}

func TestRemotePairingDialerThatReturnsNothingIsAnError(t *testing.T) {
	nothing := func(ctx context.Context, address string) (net.Conn, error) { return nil, nil }
	err := VerifyRemotePairingVia("phone:49152", time.Second, testPairRecords(t), nothing)
	if err == nil || !strings.Contains(err.Error(), "no connection") {
		t.Fatalf("want a 'no connection' error, got %v", err)
	}
}
