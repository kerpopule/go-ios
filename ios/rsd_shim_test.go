package ios

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"howett.net/plist"
)

// shimReplies is what a fake shim sends after reading the RSDCheckin request.
// nil entries are skipped, so a test can model a peer that answers only part
// of the exchange.
type shimReplies []map[string]any

var goodCheckin = shimReplies{
	{"Request": "RSDCheckin"},
	{"Request": "StartService"},
}

// writeFramed runs on the fake shim's goroutines, so it reports nothing
// through t: a failed write shows up as the client's error instead.
func writeFramed(w io.Writer, v any) error {
	payload, err := plist.Marshal(v, plist.XMLFormat)
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(len(payload)))
	buf.Write(payload)
	_, err = w.Write(buf.Bytes())
	return err
}

func readFramed(r io.Reader) (map[string]any, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	var m map[string]any
	_, err := plist.Unmarshal(payload, &m)
	return m, err
}

// fakeShim listens on loopback and, for each connection, reads one framed
// request, records it, sends replies and then holds the connection open, so a
// client that waits for more than was sent has to time out.
func fakeShim(t *testing.T, replies shimReplies) (port int, requests chan map[string]any) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	requests = make(chan map[string]any, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := readFramed(c)
				if err != nil {
					return
				}
				requests <- req
				for _, r := range replies {
					if r != nil {
						writeFramed(c, r)
					}
				}
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, requests
}

func shimDevice(service string, port int) DeviceEntry {
	return DeviceEntry{
		Address: "127.0.0.1",
		Rsd:     RsdHandshakeResponse{Services: map[string]RsdServiceEntry{service: {Port: uint32(port)}}},
	}
}

const testShim = "com.apple.mobile.installation_proxy.shim.remote"

func TestConnectToShimServiceWithTimeoutChecksIn(t *testing.T) {
	port, requests := fakeShim(t, goodCheckin)
	conn, err := ConnectToShimServiceWithTimeout(shimDevice(testShim, port), testShim, 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	req := <-requests
	assert.Equal(t, "RSDCheckin", req["Request"])
	assert.Equal(t, "2", req["ProtocolVersion"])
}

// A checkin answered with an Error plist followed by a second plist used to
// read as success (RsdCheckin does not look at what came back).
func TestConnectToShimServiceWithTimeoutRejectsAnErrorReply(t *testing.T) {
	port, _ := fakeShim(t, shimReplies{
		{"Request": "RSDCheckin", "Error": "ServiceProhibited"},
		{"Request": "StartService"},
	})
	_, err := ConnectToShimServiceWithTimeout(shimDevice(testShim, port), testShim, 2*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ServiceProhibited")
}

func TestConnectToShimServiceWithTimeoutRejectsAWrongSecondMessage(t *testing.T) {
	port, _ := fakeShim(t, shimReplies{
		{"Request": "RSDCheckin"},
		{"Request": "Goodbye"},
	})
	_, err := ConnectToShimServiceWithTimeout(shimDevice(testShim, port), testShim, 2*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "StartService")
}

// A peer that accepts and then says nothing must not hold the caller past its
// budget: this is the wedged-shim case a status probe cannot afford.
func TestConnectToShimServiceWithTimeoutIsBounded(t *testing.T) {
	port, _ := fakeShim(t, shimReplies{{"Request": "RSDCheckin"}}) // never sends StartService
	start := time.Now()
	_, err := ConnectToShimServiceWithTimeout(shimDevice(testShim, port), testShim, 300*time.Millisecond)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 3*time.Second)
	var ne net.Error
	require.ErrorAs(t, err, &ne)
	assert.True(t, ne.Timeout(), "want a timeout, got %v", err)
}

func TestConnectToShimServiceWithTimeoutNeedsTheServiceInRsd(t *testing.T) {
	_, err := ConnectToShimServiceWithTimeout(shimDevice("com.apple.other", 1), testShim, time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not available in RSD")
	_, err = ConnectToShimServiceWithTimeout(DeviceEntry{Address: "127.0.0.1"}, testShim, time.Second)
	require.Error(t, err)
}

// The RSD handshake is HTTP/2 + XPC; a peer that accepts and never speaks must
// fail within the bound instead of waiting on TCP keepalive.
func TestRsdHandshakeWithTimeoutIsBounded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(io.Discard, c) }(c)
		}
	}()
	start := time.Now()
	_, err = RsdHandshakeWithTimeout("127.0.0.1", ln.Addr().(*net.TCPAddr).Port, DeviceEntry{}, 300*time.Millisecond)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 3*time.Second)
	// The silent peer never finished the HTTP/2 setup: that is "did not
	// answer", not "answered with a bad handshake".
	assert.ErrorIs(t, err, ErrRsdConnect)
}

func TestRsdHandshakeWithTimeoutReportsARefusedDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	_, err = RsdHandshakeWithTimeout("127.0.0.1", port, DeviceEntry{}, time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to dial")
	assert.ErrorIs(t, err, ErrRsdConnect)
}
