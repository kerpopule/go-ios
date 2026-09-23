package tunnel

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A FAKE DESK PEER: an in-process SOCKS5 server on a real unix socket, so the client is tested against
// the same socket type, partial reads and close semantics it meets in production.

// streamsSocketPath returns a unix socket path that fits sun_path (104 bytes on darwin). t.TempDir()
// is used when it is short enough; long test names under macOS's /var/folders push it past the limit.
func streamsSocketPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.sock")
	if len(path) < 100 {
		return path
	}
	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// fakeDesk accepts connections on a unix socket and hands the Nth one to handlers[N]. Handlers run on
// their own goroutines, so they report failures as errors (never t.Fatal); the test collects them with
// wait().
type fakeDesk struct {
	path     string
	ln       net.Listener
	errs     chan error
	accepted chan struct{}
	done     chan struct{}
}

func newFakeDesk(t *testing.T, handlers ...func(net.Conn) error) *fakeDesk {
	t.Helper()
	path := streamsSocketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	d := &fakeDesk{path: path, ln: ln, errs: make(chan error, len(handlers)+1), accepted: make(chan struct{}, 16), done: make(chan struct{})}
	t.Cleanup(func() { _ = ln.Close(); <-d.done })
	go func() {
		defer close(d.done)
		for i := 0; ; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			d.accepted <- struct{}{}
			if i >= len(handlers) {
				d.errs <- errors.New("fake desk: more connections than handlers")
				_ = c.Close()
				continue
			}
			go func(h func(net.Conn) error) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				d.errs <- h(c)
			}(handlers[i])
		}
	}()
	return d
}

// wait collects n handler results and fails the test on the first error.
func (d *fakeDesk) wait(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case err := <-d.errs:
			if err != nil {
				t.Fatalf("fake desk: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("fake desk: handler %d never finished", i)
		}
	}
}

func (d *fakeDesk) connections() int { return len(d.accepted) }

// socksRequest is what the fake desk read from the client.
type socksRequest struct {
	greeting []byte
	raw      []byte // the whole request, 05 01 00 ATYP ADDR PORT
	host     string
	port     int
}

func expectBytes(r io.Reader, want []byte, what string) error {
	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		return errors.New(what + ": " + err.Error())
	}
	if !bytes.Equal(got, want) {
		return errors.New(what + ": got " + hexString(got) + ", want " + hexString(want))
	}
	return nil
}

func hexString(b []byte) string { return hex.EncodeToString(b) }

// readSocksRequest reads the greeting, accepts "no authentication", and reads the request. It checks
// the greeting is exactly 05 01 00 (the spec's bytes) and parses the target for the test to inspect.
func readSocksRequest(c net.Conn) (socksRequest, error) {
	var req socksRequest
	req.greeting = []byte{0x05, 0x01, 0x00}
	if err := expectBytes(c, req.greeting, "greeting"); err != nil {
		return req, err
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return req, err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return req, errors.New("request header: " + err.Error())
	}
	req.raw = append(req.raw, head...)
	if !bytes.Equal(head[:3], []byte{0x05, 0x01, 0x00}) {
		return req, errors.New("request is not 05 01 00: " + hexString(head))
	}
	var addr []byte
	switch head[3] {
	case 0x01:
		addr = make([]byte, 4)
		if _, err := io.ReadFull(c, addr); err != nil {
			return req, err
		}
		req.raw = append(req.raw, addr...)
		req.host = net.IP(addr).String()
	case 0x03:
		n := make([]byte, 1)
		if _, err := io.ReadFull(c, n); err != nil {
			return req, err
		}
		addr = make([]byte, n[0])
		if _, err := io.ReadFull(c, addr); err != nil {
			return req, err
		}
		req.raw = append(append(req.raw, n...), addr...)
		req.host = string(addr)
	default:
		return req, errors.New("unexpected ATYP " + hexString(head[3:4]))
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(c, port); err != nil {
		return req, err
	}
	req.raw = append(req.raw, port...)
	req.port = int(port[0])<<8 | int(port[1])
	return req, nil
}

// socksReply is the 10-byte reply the desk always sends.
func socksReply(rep byte) []byte { return []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0} }

// expectClientClosed waits for the client to close its end (EOF), proving it did not leak the conn.
func expectClientClosed(c net.Conn) error {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, io.EOF) {
		return errors.New("client did not close its end after the failure")
	}
	return nil
}

func dialCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func streamsErr(t *testing.T, err error) *StreamsError {
	t.Helper()
	var se *StreamsError
	if !errors.As(err, &se) {
		t.Fatalf("want a *StreamsError, got %T: %v", err, err)
	}
	return se
}

// THE EXACT BYTES, AND NOT ONE BYTE TOO MANY. The desk writes the reply and the phone's first bytes
// back to back; a client that buffered its reads would swallow the start of the RemotePairing stream.
func TestDialViaStreamsSendsTheExactPhoneRequest(t *testing.T) {
	first := []byte("RPPairing\x00\x07{\"x\":1}")
	desk := newFakeDesk(t, func(c net.Conn) error {
		req, err := readSocksRequest(c)
		if err != nil {
			return err
		}
		want := []byte{0x05, 0x01, 0x00, 0x03, 0x05, 'p', 'h', 'o', 'n', 'e', 0xC0, 0x00}
		if !bytes.Equal(req.raw, want) {
			return errors.New("request was " + hexString(req.raw) + ", want " + hexString(want))
		}
		if _, err := c.Write(append(socksReply(0x00), first...)); err != nil {
			return err
		}
		return expectBytes(c, []byte("hello phone"), "client payload")
	})

	conn, err := DialViaStreams(dialCtx(t, 5*time.Second), desk.path, "phone:49152")
	if err != nil {
		t.Fatalf("DialViaStreams: %v", err)
	}
	defer func() { _ = conn.Close() }()
	got := make([]byte, len(first))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read the phone's first bytes: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("the stream began %q, want %q: the reply parser over-read", got, first)
	}
	if _, err := conn.Write([]byte("hello phone")); err != nil {
		t.Fatalf("write: %v", err)
	}
	desk.wait(t, 1)
}

func TestDialViaStreamsSendsTheExactLoopbackRequest(t *testing.T) {
	desk := newFakeDesk(t, func(c net.Conn) error {
		req, err := readSocksRequest(c)
		if err != nil {
			return err
		}
		want := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0xE5, 0x9F} // 58783
		if !bytes.Equal(req.raw, want) {
			return errors.New("request was " + hexString(req.raw) + ", want " + hexString(want))
		}
		_, err = c.Write(socksReply(0x00))
		return err
	})
	conn, err := DialViaStreams(dialCtx(t, 5*time.Second), desk.path, "127.0.0.1:58783")
	if err != nil {
		t.Fatalf("DialViaStreams: %v", err)
	}
	_ = conn.Close()
	desk.wait(t, 1)
}

// EVERY REPLY CODE HAS ITS WORD. The daemon decides what to tell the owner from these, so a code that
// maps to the wrong word is a wrong sentence on the owner's screen.
func TestDialViaStreamsMapsEveryReplyCode(t *testing.T) {
	cases := []struct {
		rep  byte
		word string
	}{
		{0x01, StreamsGeneralFailure},
		{0x02, StreamsNotAllowed},
		{0x03, StreamsPhoneNotLinked},
		{0x04, StreamsTimeout},
		{0x05, StreamsConnectionRefused},
		{0x06, StreamsGeneralFailure}, // TTL expired: the desk never sends it
		{0x07, StreamsCommandNotSupported},
		{0x08, StreamsAddressTypeNotSupported},
		{0x42, StreamsGeneralFailure},
	}
	for _, tc := range cases {
		desk := newFakeDesk(t, func(c net.Conn) error {
			if _, err := readSocksRequest(c); err != nil {
				return err
			}
			if _, err := c.Write(socksReply(tc.rep)); err != nil {
				return err
			}
			return expectClientClosed(c)
		})
		conn, err := DialViaStreams(dialCtx(t, 5*time.Second), desk.path, "phone:49152")
		if err == nil {
			_ = conn.Close()
			t.Fatalf("REP 0x%02x: dial succeeded", tc.rep)
		}
		se := streamsErr(t, err)
		if se.Word != tc.word || se.Rep != int(tc.rep) || se.Target != "phone:49152" {
			t.Fatalf("REP 0x%02x: got word %q rep %d target %q, want %q %d phone:49152", tc.rep, se.Word, se.Rep, se.Target, tc.word, tc.rep)
		}
		desk.wait(t, 1)
	}
}

// 05 FF: WHATEVER IS ON THE SOCKET WANTS AUTHENTICATION, SO IT IS NOT THE DESK PEER. The client must
// stop there and never send the target.
func TestDialViaStreamsStopsAtAGreetingRefusal(t *testing.T) {
	desk := newFakeDesk(t, func(c net.Conn) error {
		if err := expectBytes(c, []byte{0x05, 0x01, 0x00}, "greeting"); err != nil {
			return err
		}
		if _, err := c.Write([]byte{0x05, 0xFF}); err != nil {
			return err
		}
		return expectClientClosed(c) // and nothing before the EOF: no request followed
	})
	_, err := DialViaStreams(dialCtx(t, 5*time.Second), desk.path, "phone:49152")
	se := streamsErr(t, err)
	if se.Word != StreamsSocksProtocol || se.Rep != -1 {
		t.Fatalf("got word %q rep %d, want socks_protocol -1", se.Word, se.Rep)
	}
	desk.wait(t, 1)
}

func TestDialViaStreamsRefusesMalformedReplies(t *testing.T) {
	cases := []struct {
		name   string
		server func(c net.Conn) error
	}{
		{"closed before the method selection", func(c net.Conn) error {
			return expectBytes(c, []byte{0x05, 0x01, 0x00}, "greeting")
		}},
		{"method selection is not version 5", func(c net.Conn) error {
			_ = expectBytes(c, []byte{0x05, 0x01, 0x00}, "greeting")
			_, err := c.Write([]byte{0x04, 0x00})
			return err
		}},
		{"a method that was not offered", func(c net.Conn) error {
			_ = expectBytes(c, []byte{0x05, 0x01, 0x00}, "greeting")
			_, err := c.Write([]byte{0x05, 0x02})
			return err
		}},
		{"reply is not version 5", func(c net.Conn) error {
			if _, err := readSocksRequest(c); err != nil {
				return err
			}
			_, err := c.Write([]byte{0x04, 0x5A, 0, 0, 0, 0, 0, 0})
			return err
		}},
		{"reply address type unknown", func(c net.Conn) error {
			if _, err := readSocksRequest(c); err != nil {
				return err
			}
			_, err := c.Write([]byte{0x05, 0x00, 0x00, 0x09, 0, 0})
			return err
		}},
		{"EOF in the middle of the reply", func(c net.Conn) error {
			if _, err := readSocksRequest(c); err != nil {
				return err
			}
			_, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			desk := newFakeDesk(t, tc.server)
			conn, err := DialViaStreams(dialCtx(t, 5*time.Second), desk.path, "phone:49152")
			if err == nil {
				_ = conn.Close()
				t.Fatal("dial succeeded")
			}
			se := streamsErr(t, err)
			if se.Word != StreamsSocksProtocol || se.Rep != -1 {
				t.Fatalf("got word %q rep %d (%v), want socks_protocol -1", se.Word, se.Rep, err)
			}
			desk.wait(t, 1)
		})
	}
}

// Other legal reply shapes are consumed by their declared address type, so the stream starts clean.
func TestDialViaStreamsConsumesEveryLegalReplyShape(t *testing.T) {
	for name, reply := range map[string][]byte{
		"ipv6":   append(append([]byte{0x05, 0x00, 0x00, 0x04}, make([]byte, 16)...), 0xC0, 0x00),
		"domain": {0x05, 0x00, 0x00, 0x03, 0x05, 'p', 'h', 'o', 'n', 'e', 0xC0, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			desk := newFakeDesk(t, func(c net.Conn) error {
				if _, err := readSocksRequest(c); err != nil {
					return err
				}
				_, err := c.Write(append(append([]byte(nil), reply...), 'Z'))
				return err
			})
			conn, err := DialViaStreams(dialCtx(t, 5*time.Second), desk.path, "phone:49152")
			if err != nil {
				t.Fatalf("DialViaStreams: %v", err)
			}
			defer func() { _ = conn.Close() }()
			b := make([]byte, 1)
			if _, err := io.ReadFull(conn, b); err != nil || b[0] != 'Z' {
				t.Fatalf("first stream byte %q, %v; want 'Z'", b, err)
			}
			desk.wait(t, 1)
		})
	}
}

// A DESK THAT NEVER ANSWERS MUST NOT HOLD THE CALLER. The desk holds a request while the phone is
// deciding; the caller's own deadline is what bounds it.
func TestDialViaStreamsGivesUpAtTheDeadlineMidHandshake(t *testing.T) {
	release := make(chan struct{})
	desk := newFakeDesk(t, func(c net.Conn) error {
		if _, err := readSocksRequest(c); err != nil {
			return err
		}
		<-release // never reply
		return nil
	})
	defer close(release)

	start := time.Now()
	_, err := DialViaStreams(dialCtx(t, 300*time.Millisecond), desk.path, "phone:49152")
	elapsed := time.Since(start)
	se := streamsErr(t, err)
	if se.Word != StreamsTimeout || se.Rep != -1 {
		t.Fatalf("got word %q rep %d (%v), want timeout -1", se.Word, se.Rep, err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("took %v to give up on a 300ms deadline", elapsed)
	}
}

// A cancel with no deadline must also unblock the read.
func TestDialViaStreamsGivesUpWhenCancelled(t *testing.T) {
	release := make(chan struct{})
	desk := newFakeDesk(t, func(c net.Conn) error {
		if _, err := readSocksRequest(c); err != nil {
			return err
		}
		<-release
		return nil
	})
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	_, err := DialViaStreams(ctx, desk.path, "phone:49152")
	if se := streamsErr(t, err); se.Word != StreamsTimeout {
		t.Fatalf("got word %q (%v), want timeout", se.Word, err)
	}
}

// THE HANDSHAKE DEADLINE MUST NOT OUTLIVE THE HANDSHAKE. The stream is long-lived (it carries the
// CoreDevice tunnel); a deadline left on it would cut the tunnel when the dial's timer ran out.
func TestDialViaStreamsClearsTheHandshakeDeadline(t *testing.T) {
	desk := newFakeDesk(t, func(c net.Conn) error {
		if _, err := readSocksRequest(c); err != nil {
			return err
		}
		if _, err := c.Write(socksReply(0x00)); err != nil {
			return err
		}
		time.Sleep(400 * time.Millisecond)
		_, err := c.Write([]byte("late"))
		return err
	})
	conn, err := DialViaStreams(dialCtx(t, 150*time.Millisecond), desk.path, "phone:49152")
	if err != nil {
		t.Fatalf("DialViaStreams: %v", err)
	}
	defer func() { _ = conn.Close() }()
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read after the dial deadline passed: %v", err)
	}
	desk.wait(t, 1)
}

func TestDialViaStreamsReportsAMissingSocket(t *testing.T) {
	path := filepath.Join(filepath.Dir(streamsSocketPath(t)), "absent.sock")
	_, err := DialViaStreams(dialCtx(t, time.Second), path, "phone:49152")
	if se := streamsErr(t, err); se.Word != StreamsSocketUnavailable || se.Rep != -1 {
		t.Fatalf("got word %q rep %d, want socket_unavailable -1", se.Word, se.Rep)
	}
}

// A TARGET THE DESK WOULD REFUSE IS REFUSED HERE, BEFORE THE SOCKET IS TOUCHED. The phone only ever
// connects to its own loopback, and only on 49152-65535.
func TestDialViaStreamsRejectsTargetsBeforeDialing(t *testing.T) {
	desk := newFakeDesk(t) // any connection at all is a failure
	for _, target := range []string{
		"10.71.0.2:49152", "localhost:49152", "[::1]:49152", "PHONE:49152", "phone:49151",
		"phone:22", "phone:0", "phone:65536", "phone:port", "phone", "", "127.0.0.2:49152",
	} {
		_, err := DialViaStreams(dialCtx(t, time.Second), desk.path, target)
		if se := streamsErr(t, err); se.Word != StreamsBadTarget {
			t.Fatalf("%q: got word %q, want bad_target", target, se.Word)
		}
		if ValidateStreamsTarget(target) == nil {
			t.Fatalf("%q: ValidateStreamsTarget accepted it", target)
		}
	}
	if n := desk.connections(); n != 0 {
		t.Fatalf("the socket was dialled %d times for targets that could never work", n)
	}
	for _, target := range []string{"phone:49152", "phone:65535", "127.0.0.1:62078", "[phone]:58783"} {
		if err := ValidateStreamsTarget(target); err != nil {
			t.Fatalf("%q: %v", target, err)
		}
	}
}
