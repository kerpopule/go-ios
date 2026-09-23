// Device-free tests for the RSD-port collision (rsdgate.go).
//
// Measured on the real phone on 2026-09-23: a second connection reaching the
// RSD port while a handshake is in flight makes the phone reset the handshake
// in flight. fakeRSD below does the same, over the real HTTP/2 + XPC handshake
// go-ios speaks, so these tests drive the real handshake code (the real
// handshake seams, the real liveness connect) against it. Same rule as the
// other test files: nothing here reaches a real iPhone.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/hid"
	"github.com/danielpaulus/go-ios/ios/tunnel"
	"github.com/danielpaulus/go-ios/ios/xpc"
	"golang.org/x/net/http2"
)

// --- the fake phone RSD port -------------------------------------------------

// fakeRSD answers the RSD handshake (HTTP/2 preface and settings, the three
// XPC setup messages, then the Handshake message with a UDID and a service
// table) on loopback, with the collision the phone showed: when a connection
// is accepted, every older connection still in flight is reset (RST). A
// handshake is in flight from its accept until its Handshake message is sent;
// a bare connection until the client closes it.
type fakeRSD struct {
	port     int
	udid     string
	services map[string]int
	delay    time.Duration // after the preface, before the first frame: the window a second connection lands in
	resetAll bool          // reset every handshake before its first frame (a phone that always does)

	mu         sync.Mutex
	open       map[*fakeRSDConn]bool
	accepted   int // every connection, bare ones included
	handshakes int // connections that sent the HTTP/2 preface
	completed  int // handshakes answered in full
	resetHS    int // handshakes reset in flight
	inFlight   int // handshakes past their preface, not yet answered or reset
	maxFlight  int
	prefaces   chan struct{} // one per preface read
}

type fakeRSDConn struct {
	c                          *net.TCPConn
	preface, flying, done, rst bool
}

func newFakeRSD(t *testing.T, udid string, services map[string]int, delay time.Duration) *fakeRSD {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeRSD{port: ln.Addr().(*net.TCPAddr).Port, udid: udid, services: services, delay: delay,
		open: map[*fakeRSDConn]bool{}, prefaces: make(chan struct{}, 64)}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		ln.Close()
		f.mu.Lock()
		for c := range f.open {
			c.c.Close()
		}
		f.mu.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fc := &fakeRSDConn{c: c.(*net.TCPConn)}
			f.mu.Lock()
			f.accepted++
			for o := range f.open {
				if !o.done && !o.rst {
					f.resetLocked(o)
				}
			}
			f.open[fc] = true
			f.mu.Unlock()
			wg.Add(1)
			go func() { defer wg.Done(); f.serve(fc) }()
		}
	}()
	return f
}

// resetLocked sends an RST on o. f.mu is held.
func (f *fakeRSD) resetLocked(o *fakeRSDConn) {
	o.rst = true
	if o.flying {
		o.flying = false
		f.inFlight--
		f.resetHS++
	}
	o.c.SetLinger(0)
	o.c.Close()
}

func (f *fakeRSD) serve(fc *fakeRSDConn) {
	defer func() {
		f.mu.Lock()
		if fc.flying {
			fc.flying = false
			f.inFlight--
		}
		delete(f.open, fc)
		f.mu.Unlock()
		fc.c.Close()
	}()
	pre := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(fc.c, pre); err != nil || string(pre) != http2.ClientPreface {
		return // a bare connect, or one reset before it spoke
	}
	f.mu.Lock()
	if fc.rst {
		f.mu.Unlock()
		return
	}
	fc.preface, fc.flying = true, true
	f.handshakes++
	f.inFlight++
	f.maxFlight = max(f.maxFlight, f.inFlight)
	f.mu.Unlock()
	select {
	case f.prefaces <- struct{}{}:
	default:
	}
	time.Sleep(f.delay)
	f.mu.Lock()
	if f.resetAll && !fc.rst {
		f.resetLocked(fc)
	}
	gone := fc.rst
	f.mu.Unlock()
	if gone {
		return
	}
	if err := f.answer(fc.c); err != nil {
		return
	}
	f.mu.Lock()
	if fc.flying {
		fc.flying = false
		f.inFlight--
	}
	fc.done = true
	f.completed++
	f.mu.Unlock()
	io.Copy(io.Discard, fc.c) // until the client closes
}

// answer is the device side of the RSD handshake after the preface.
func (f *fakeRSD) answer(c net.Conn) error {
	fr := http2.NewFramer(c, c)
	if err := fr.WriteSettings(); err != nil {
		return err
	}
	send := func(stream uint32, body map[string]any) error {
		buf := new(bytes.Buffer)
		if err := xpc.EncodeMessage(buf, xpc.Message{Flags: xpc.AlwaysSetFlag | xpc.DataFlag, Body: body}); err != nil {
			return err
		}
		return fr.WriteData(stream, false, buf.Bytes())
	}
	services := map[string]any{}
	for name, port := range f.services {
		services[name] = map[string]any{"Port": strconv.Itoa(port)}
	}
	streams := map[uint32]*bytes.Buffer{1: {}, 3: {}}
	got := map[uint32]int{}
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return err
		}
		df, ok := frame.(*http2.DataFrame)
		if !ok || streams[df.StreamID] == nil {
			continue
		}
		buf := streams[df.StreamID]
		buf.Write(df.Data())
		for buf.Len() >= 24 { // magic, flags, body length, message id
			n := 24 + int(binary.LittleEndian.Uint64(buf.Bytes()[8:16]))
			if buf.Len() < n {
				break
			}
			buf.Next(n)
			got[df.StreamID]++
			switch {
			case df.StreamID == 1 && got[1] == 1, df.StreamID == 3 && got[3] == 1:
				if err := send(df.StreamID, map[string]any{}); err != nil {
					return err
				}
			case df.StreamID == 1 && got[1] == 2:
				if err := send(1, map[string]any{}); err != nil {
					return err
				}
				return send(1, map[string]any{
					"MessageType": "Handshake",
					"Properties":  map[string]any{"UniqueDeviceID": f.udid},
					"Services":    services,
				})
			}
		}
	}
}

type fakeRSDStats struct{ accepted, handshakes, completed, resetHS, maxFlight int }

func (f *fakeRSD) stats() fakeRSDStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeRSDStats{f.accepted, f.handshakes, f.completed, f.resetHS, f.maxFlight}
}

// bareConnect is the keeper's old health check: connect to the RSD port, close.
func bareConnect(t *testing.T, port int) {
	t.Helper()
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("bare connect: %v", err)
	}
	c.Close()
}

// together runs fns at the same moment and waits for all of them.
func together(fns ...func()) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, fn := range fns {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; fn() }()
	}
	close(start)
	wg.Wait()
}

// collisionRoad pins no-mux mode at a fakeRSD whose table lists a healthy
// fake shim, with the REAL handshake seam and the REAL liveness connect.
func collisionRoad(t *testing.T, delay time.Duration) (*fakeRSD, *atomic.Int32) {
	t.Helper()
	shim, checkins := fakeAppsShim(t, shimHealthy)
	f := newFakeRSD(t, testUDID, map[string]int{svcScreenshot: 51000, svcHID: 51001, svcAppsShim: shim}, delay)
	realAlive := tunnelAlive
	noMuxMode(t, noMuxPin{addr: "127.0.0.1", rsd: f.port, udid: testUDID})
	tunnelAlive = realAlive
	return f, checkins
}

// --- the fake reproduces the defect ----------------------------------------

// Before any fix, straight through go-ios: handshakes one at a time all
// answer; three at once, at most one does, and the others fail the way the
// phone's did ("NewHttpConnection: could not read frame ... connection reset
// by peer"); a bare connect during a handshake kills it.
func TestFakeRSDResetsAHandshakeWhenASecondConnectionArrives(t *testing.T) {
	f := newFakeRSD(t, testUDID, map[string]int{svcHID: 51001}, 150*time.Millisecond)
	for i := 0; i < 5; i++ {
		if _, err := ios.RsdHandshakeWithTimeout("127.0.0.1", f.port, ios.DeviceEntry{}, 3*time.Second); err != nil {
			t.Fatalf("a handshake on its own must answer (%d/5): %v", i+1, err)
		}
	}
	errs := make([]error, 3)
	together(
		func() {
			_, errs[0] = ios.RsdHandshakeWithTimeout("127.0.0.1", f.port, ios.DeviceEntry{}, 3*time.Second)
		},
		func() {
			_, errs[1] = ios.RsdHandshakeWithTimeout("127.0.0.1", f.port, ios.DeviceEntry{}, 3*time.Second)
		},
		func() {
			_, errs[2] = ios.RsdHandshakeWithTimeout("127.0.0.1", f.port, ios.DeviceEntry{}, 3*time.Second)
		},
	)
	failed, resets := 0, 0
	for _, err := range errs {
		if err == nil {
			continue
		}
		failed++
		// Every one before the handshake's first frame (phone_tunnel_unreachable,
		// as the phone's /status said). On loopback the RST can also land while
		// connect() or its setsockopt is still running, so not every one reads
		// as a reset; over a real tunnel an RTT separates those.
		if !errors.Is(err, ios.ErrRsdConnect) {
			t.Fatalf("a collided handshake must fail before its first frame, got %v", err)
		}
		if handshakeReset(err) {
			resets++
		}
	}
	if failed < 2 || resets == 0 {
		t.Fatalf("three at once: wanted at most one answer and a reset, got %d failures, %d resets (%v)", failed, resets, errs)
	}
	for len(f.prefaces) > 0 { // the handshakes above signalled too
		<-f.prefaces
	}
	for i := 0; i < 5; i++ {
		done := make(chan error, 1)
		go func() {
			_, err := ios.RsdHandshakeWithTimeout("127.0.0.1", f.port, ios.DeviceEntry{}, 3*time.Second)
			done <- err
		}()
		<-f.prefaces
		bareConnect(t, f.port)
		// Past its preface, so this is the phone's own message: "NewHttpConnection:
		// could not read frame ... connection reset by peer".
		if err := <-done; err == nil || !handshakeReset(err) || !strings.Contains(err.Error(), "NewHttpConnection: could not read frame") {
			t.Fatalf("a bare connect during a handshake must reset it (%d/5), got %v", i+1, err)
		}
	}
}

// --- the fix ----------------------------------------------------------------

// Three /status calls at once, the defect's own reproduction: all answer, with
// one probe (one handshake, one shim checkin) between them, and the phone
// resets nothing.
func TestNoMuxConcurrentStatusCallsShareOneProbe(t *testing.T) {
	f, checkins := collisionRoad(t, 150*time.Millisecond)
	b := &bridge{}
	sts := make([]status, 3)
	together(
		func() { sts[0] = b.status() },
		func() { sts[1] = b.status() },
		func() { sts[2] = b.status() },
	)
	for i, st := range sts {
		if !st.OK || st.UDID != testUDID {
			t.Fatalf("status %d: wanted ok, got %+v", i, st)
		}
	}
	if s := f.stats(); s.handshakes != 1 || s.resetHS != 0 || checkins.Load() != 1 {
		t.Fatalf("wanted one handshake, one shim checkin and no reset, got %+v and %d checkins", s, checkins.Load())
	}
}

// Every RSD contact this process makes, at once: two probes that bypass the
// shared /status, a read path resolving a device, and the liveness connect.
// They queue on the tunnel's gate; none lands on another's handshake, and the
// ones that queued behind the handshake take its answer.
func TestNoMuxRSDContactsNeverOverlap(t *testing.T) {
	f, _ := collisionRoad(t, 150*time.Millisecond)
	b, reader := &bridge{}, &bridge{}
	b.aliveAt.Store(time.Now().Add(-time.Minute).UnixNano())
	var sts [2]status
	var devErr error
	var alive bool
	together(
		func() { sts[0] = b.probe() },
		func() { sts[1] = b.probe() },
		func() { _, devErr = reader.device() },
		func() { alive = b.tunnelAnswers() },
	)
	if !sts[0].OK || !sts[1].OK || devErr != nil || !alive {
		t.Fatalf("every caller must succeed: %+v / %+v / %v / alive=%v", sts[0], sts[1], devErr, alive)
	}
	if s := f.stats(); s.maxFlight != 1 || s.resetHS != 0 {
		t.Fatalf("contacts overlapped on the RSD port: %+v", s)
	}
	if s := f.stats(); s.handshakes != 1 {
		t.Fatalf("the callers queued behind the handshake must share it, got %d handshakes", s.handshakes)
	}
}

// A contact from outside this process (the old keeper's TCP probe) lands on a
// /status handshake in flight: the phone resets it, and phoned retries once,
// after a pause, and answers up.
func TestNoMuxAResetHandshakeIsRetriedOnce(t *testing.T) {
	f, _ := collisionRoad(t, 300*time.Millisecond)
	done := make(chan status, 1)
	go func() { done <- (&bridge{}).status() }()
	<-f.prefaces
	bareConnect(t, f.port)
	st := <-done
	if !st.OK {
		t.Fatalf("the retry must answer up, got %+v", st)
	}
	if s := f.stats(); s.resetHS != 1 || s.handshakes != 2 || s.completed != 1 {
		t.Fatalf("wanted one reset handshake and one retry that answered, got %+v", s)
	}
}

// A phone that resets every handshake is asked twice, not forever, and the
// answer names the tunnel.
func TestNoMuxAPersistentResetIsRetriedOnlyOnce(t *testing.T) {
	f, _ := collisionRoad(t, 20*time.Millisecond)
	f.mu.Lock()
	f.resetAll = true
	f.mu.Unlock()
	st := (&bridge{}).status()
	if st.OK || st.Reason != "phone_tunnel_unreachable" || !strings.Contains(st.Detail, "reset") {
		t.Fatalf("wanted phone_tunnel_unreachable naming the reset, got %+v", st)
	}
	if s := f.stats(); s.handshakes != 2 {
		t.Fatalf("wanted exactly two handshakes (one retry), got %+v", s)
	}
}

// The lan road (usbmux mode) had the same collision: concurrent /status calls
// share one handshake there too, through the real bounded handshake seam.
func TestMuxConcurrentStatusCallsShareOneHandshake(t *testing.T) {
	f := newFakeRSD(t, testUDID, map[string]int{svcScreenshot: 51000, svcHID: 51001}, 150*time.Millisecond)
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil }, nil)
	stubLockdown(t, func(ios.DeviceEntry) error { return nil })
	oldInfo := tunnelInfoForDevice
	tunnelInfoForDevice = func(string, string, int) (tunnel.Tunnel, error) {
		return tunnel.Tunnel{Address: "127.0.0.1", RsdPort: f.port, Udid: testUDID}, nil
	}
	t.Cleanup(func() { tunnelInfoForDevice = oldInfo })
	b := &bridge{}
	sts := make([]status, 3)
	together(
		func() { sts[0] = b.status() },
		func() { sts[1] = b.status() },
		func() { sts[2] = b.status() },
	)
	for i, st := range sts {
		if !st.OK {
			t.Fatalf("status %d: wanted ok, got %+v", i, st)
		}
	}
	if s := f.stats(); s.handshakes != 1 || s.resetHS != 0 {
		t.Fatalf("wanted one handshake and no reset, got %+v", s)
	}
	// Two probes that bypass the shared /status still never overlap.
	together(func() { b.probe() }, func() { b.probe() })
	if s := f.stats(); s.maxFlight != 1 || s.resetHS != 0 {
		t.Fatalf("mux-mode handshakes overlapped: %+v", s)
	}
}

// The mux-mode handshake is bounded now: a peer that accepts and says nothing
// used to hold it until TCP keepalive gave up, and it now holds the gate.
func TestMuxHandshakeIsBounded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(io.Discard, c) }()
		}
	}()
	start := time.Now()
	_, err = handshake(tunnel.Tunnel{Address: "127.0.0.1", RsdPort: ln.Addr().(*net.TCPAddr).Port}, ios.DeviceEntry{}, 300*time.Millisecond)
	if err == nil || reasonOf(err) != "phone_tunnel_unreachable" || time.Since(start) > 3*time.Second {
		t.Fatalf("wanted a bounded phone_tunnel_unreachable, got %v after %s", err, time.Since(start))
	}
	f := newFakeRSD(t, testUDID, map[string]int{svcHID: 51001}, 0)
	p, err := handshake(tunnel.Tunnel{Address: "127.0.0.1", RsdPort: f.port}, ios.DeviceEntry{}, 3*time.Second)
	if err != nil || p.GetPort(svcHID) != 51001 {
		t.Fatalf("the real mux handshake must read the table: %v %v", p, err)
	}
}

// --- the gate, with stubs ---------------------------------------------------

func opErr(op string, errno syscall.Errno) error {
	return &net.OpError{Op: op, Net: "tcp", Err: os.NewSyscallError(op, errno)}
}

// What counts as the phone resetting a handshake: RST, a broken pipe, or the
// connection closed before its answer. Not a refused dial and not a timeout:
// a retry cannot fix those, and on a dead tunnel it doubles the wait.
func TestOnlyAResetHandshakeIsRetried(t *testing.T) {
	noMuxMode(t, defaultPin())
	old := retryPause
	retryPause = func() time.Duration { return time.Millisecond }
	t.Cleanup(func() { retryPause = old })
	wrap := func(inner error) error {
		return fmt.Errorf("phone_tunnel_unreachable: RsdHandshakeWithTimeout: %w: NewHttpConnection: could not read frame. %w", ios.ErrRsdConnect, inner)
	}
	for name, c := range map[string]struct {
		err   error
		calls int
	}{
		"RST":            {wrap(opErr("read", syscall.ECONNRESET)), 2},
		"broken pipe":    {wrap(opErr("write", syscall.EPIPE)), 2},
		"closed early":   {wrap(io.EOF), 2},
		"closed midway":  {fmt.Errorf("phone_handshake_failed: Handshake: %w", io.ErrUnexpectedEOF), 2},
		"refused dial":   {wrap(opErr("dial", syscall.ECONNREFUSED)), 1},
		"dial timed out": {wrap(fmt.Errorf("%w after 6s", ios.ErrDialTimeout)), 1},
		"read deadline":  {wrap(os.ErrDeadlineExceeded), 1},
		"a plain word":   {errors.New("phone_handshake_failed: Handshake: could not read UDID"), 1},
	} {
		var calls atomic.Int32
		handshakeNoMux = func(tunnel.Tunnel, ios.DeviceEntry, time.Duration) (ios.RsdPortProvider, string, error) {
			calls.Add(1)
			return nil, "", c.err
		}
		if _, err := resolve(); err == nil || reasonOf(err) != reasonOf(c.err) {
			t.Fatalf("%s: wanted %s, got %v", name, reasonOf(c.err), err)
		}
		if int(calls.Load()) != c.calls {
			t.Fatalf("%s: wanted %d attempts, got %d", name, c.calls, calls.Load())
		}
	}
}

// The retry happens only if it still fits the handshake's budget.
func TestAResetIsNotRetriedPastTheBudget(t *testing.T) {
	noMuxMode(t, defaultPin())
	setDuration(t, &noMuxHandshakeTimeout, time.Second) // less than rsdRetryLeast
	var calls atomic.Int32
	handshakeNoMux = func(tunnel.Tunnel, ios.DeviceEntry, time.Duration) (ios.RsdPortProvider, string, error) {
		calls.Add(1)
		return nil, "", fmt.Errorf("phone_tunnel_unreachable: %w", opErr("read", syscall.ECONNRESET))
	}
	if _, err := resolve(); err == nil || calls.Load() != 1 {
		t.Fatalf("wanted one attempt and the reset, got %d / %v", calls.Load(), err)
	}
}

// The pause before the retry is short and jittered.
func TestTheRetryPauseIsShortAndJittered(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		p := retryPause()
		if p < rsdRetryMin || p >= rsdRetryMin+rsdRetrySpread {
			t.Fatalf("pause %s outside [%s, %s)", p, rsdRetryMin, rsdRetryMin+rsdRetrySpread)
		}
		seen[p] = true
	}
	if len(seen) < 10 {
		t.Fatalf("the pause is not jittered: %d distinct values in 200", len(seen))
	}
}

// Every attempt gets only what is left of the budget, the wait for the gate
// included, and a caller never waits for the gate past its budget.
func TestTheGateWaitCountsAgainstTheBudget(t *testing.T) {
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, fullRsd, testUDID)
	g := gateFor(noMuxAddr, noMuxRsd)
	if ok, _ := g.acquire(time.Now().Add(time.Second)); !ok {
		t.Fatal("the gate was not free at the start of the test")
	}
	setDuration(t, &noMuxHandshakeTimeout, 200*time.Millisecond)
	start := time.Now()
	_, err := resolve()
	g.release()
	if err == nil || reasonOf(err) != "phone_tunnel_unreachable" || !errors.Is(err, errRsdBusy) {
		t.Fatalf("wanted phone_tunnel_unreachable (busy), got %v", err)
	}
	if took := time.Since(start); took < 150*time.Millisecond || took > time.Second || h.calls != 0 {
		t.Fatalf("wanted the wait cut at the 200ms budget with no handshake, took %s, %d handshakes", took, h.calls)
	}
}

// Two tunnels are two gates.
func TestTheGateIsPerTunnel(t *testing.T) {
	g := gateFor("fd00::a", 58783)
	if ok, _ := g.acquire(time.Now().Add(time.Second)); !ok {
		t.Fatal("the gate was not free at the start of the test")
	}
	defer g.release()
	_, _, err := rsdHandshake("fd00::b", 58783, 200*time.Millisecond, func(time.Duration) (ios.RsdPortProvider, string, error) {
		return fullRsd, testUDID, nil
	})
	if err != nil {
		t.Fatalf("another tunnel's gate held this one: %v", err)
	}
}

// holdGate runs /status with a handshake that holds the tunnel's gate until
// the returned release is called (by the test, or at cleanup).
func holdGate(t *testing.T, udid string) (entered <-chan struct{}, release func(), statusDone <-chan status) {
	t.Helper()
	in, out, done := make(chan struct{}, 1), make(chan struct{}), make(chan status, 1)
	var once sync.Once
	release = func() { once.Do(func() { close(out) }) }
	handshakeNoMux = func(tunnel.Tunnel, ios.DeviceEntry, time.Duration) (ios.RsdPortProvider, string, error) {
		select {
		case in <- struct{}{}:
		default:
		}
		<-out
		return fullRsd, udid, nil
	}
	b := &bridge{}
	go func() { done <- b.status() }()
	t.Cleanup(func() { release(); <-done })
	return in, release, done
}

// Work never queues behind a status handshake: a screenshot and a tap on a
// tunnel proven moments ago run while /status holds the RSD gate.
func TestWorkIsNotSerialisedBehindAStatusHandshake(t *testing.T) {
	noMuxMode(t, defaultPin())
	entered, _, _ := holdGate(t, testUDID)
	<-entered
	b := &bridge{ready: true}
	d := entry(testUDID, 0, connNoMux)
	d.Address, d.Rsd = noMuxAddr, fullRsd
	cached(b, d)
	b.sawTunnel()
	start := time.Now()
	read, tapped := false, false
	if err := b.withDevice(func(ios.DeviceEntry) error { read = true; return nil }); err != nil || !read {
		t.Fatalf("the read did not run: %v", err)
	}
	if err := b.withHID(func(*hid.Session) error { tapped = true; return nil }); err != nil || !tapped {
		t.Fatalf("the tap did not run: %v", err)
	}
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Fatalf("work waited %s behind the status handshake", took)
	}
}

// The liveness test waits for the gate instead of connecting into a handshake
// in flight, and takes that handshake's success as its proof: no connect.
func TestLivenessUsesTheHandshakeItWaitedBehind(t *testing.T) {
	noMuxMode(t, defaultPin())
	var dials atomic.Int32
	tunnelAlive = func(string, int, time.Duration) error { dials.Add(1); return nil }
	entered, release, _ := holdGate(t, testUDID)
	<-entered
	time.AfterFunc(150*time.Millisecond, release)
	b := &bridge{}
	b.aliveAt.Store(time.Now().Add(-time.Minute).UnixNano())
	start := time.Now()
	if !b.tunnelAnswers() {
		t.Fatal("the handshake it waited behind succeeded; the tunnel answers")
	}
	if took := time.Since(start); took < 100*time.Millisecond || dials.Load() != 0 {
		t.Fatalf("wanted a wait for the handshake and no connect, took %s with %d connects", took, dials.Load())
	}
}

// ... and a gate held past liveCheckTimeout is a tunnel that did not answer in
// time, as a connect that took that long always was.
func TestLivenessGivesUpWhenThePortStaysBusy(t *testing.T) {
	noMuxMode(t, defaultPin())
	setDuration(t, &liveCheckTimeout, 200*time.Millisecond)
	var dials atomic.Int32
	tunnelAlive = func(string, int, time.Duration) error { dials.Add(1); return nil }
	entered, _, _ := holdGate(t, testUDID)
	<-entered
	b := &bridge{}
	b.aliveAt.Store(time.Now().Add(-time.Minute).UnixNano())
	start := time.Now()
	if b.tunnelAnswers() {
		t.Fatal("a port busy for the whole liveness budget proved nothing")
	}
	if took := time.Since(start); took > time.Second || dials.Load() != 0 {
		t.Fatalf("wanted a bounded give-up and no connect, took %s with %d connects", took, dials.Load())
	}
}

// --- /status: one probe at a time -------------------------------------------

// Counted at resolve, not at the handshake: callers that queue on the gate
// share a handshake anyway, so only this shows the probes themselves joined.
func TestStatusCallsInFlightJoinOneProbe(t *testing.T) {
	noMuxMode(t, defaultPin())
	var calls atomic.Int32
	out := make(chan struct{})
	handshakeNoMux = func(tunnel.Tunnel, ios.DeviceEntry, time.Duration) (ios.RsdPortProvider, string, error) {
		<-out
		return fullRsd, testUDID, nil
	}
	inner := resolve
	resolve = func() (ios.DeviceEntry, error) { calls.Add(1); return inner() }
	b := &bridge{}
	time.AfterFunc(100*time.Millisecond, func() { close(out) })
	sts := make([]status, 3)
	together(
		func() { sts[0] = b.status() },
		func() { sts[1] = b.status() },
		func() { sts[2] = b.status() },
	)
	if calls.Load() != 1 {
		t.Fatalf("wanted one probe for three calls, got %d", calls.Load())
	}
	for i, st := range sts {
		if !st.See.up() || st.See.AgeMs != 0 {
			t.Fatalf("status %d: a joined answer is fresh, got %+v", i, st.See)
		}
	}
}

// An answer younger than statusReuse is answered again, aged; an older one is
// asked again.
func TestStatusReusesAYoungAnswerAndSaysHowOld(t *testing.T) {
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, fullRsd, testUDID)
	b := &bridge{}
	first := b.status()
	time.Sleep(20 * time.Millisecond)
	second := b.status()
	if h.calls != 1 {
		t.Fatalf("wanted the young answer reused, got %d handshakes", h.calls)
	}
	if second.See.AgeMs < 20 || second.Act.AgeMs < 20 || second.Apps.AgeMs < 20 || first.See.AgeMs != 0 {
		t.Fatalf("a reused answer must say how old it is: first %+v, second %+v", first.See, second)
	}
	setDuration(t, &statusReuse, 10*time.Millisecond)
	if third := b.status(); h.calls != 2 || third.See.AgeMs != 0 {
		t.Fatalf("an answer older than statusReuse must be asked again: %d handshakes, %+v", h.calls, third.See)
	}
}

// A probe that never ends must not take every later /status with it.
func TestStatusAbandonsAProbeThatOutlivedEveryBudget(t *testing.T) {
	setDuration(t, &statusFlightLimit, 200*time.Millisecond)
	stuck, free := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			if calls.Add(1) == 1 {
				close(stuck)
				<-free
			}
			d := entry(testUDID, 3, "USB")
			d.Rsd = fullRsd
			return d, nil
		})
	stubLockdown(t, func(ios.DeviceEntry) error { return nil })
	b := &bridge{}
	first := make(chan status, 1)
	go func() { first <- b.status() }()
	t.Cleanup(func() { close(free); <-first })
	<-stuck
	second := make(chan status, 1)
	go func() { second <- b.status() }()
	select {
	case st := <-second:
		if !st.OK || calls.Load() != 2 {
			t.Fatalf("wanted a fresh probe once the stuck one outlived the limit: %+v, %d probes", st, calls.Load())
		}
	case <-time.After(2 * time.Second):
		close(free) // let both finish before cleanup
		<-second
		free = make(chan struct{}) // cleanup closes this one
		t.Fatal("a later /status joined a probe that never ends")
	}
}

// The handler's shared /status gives the incident state the same bytes as
// probe() (TestStatusBytesForTheIncidentState pins those).
func TestSharedStatusBytesForTheIncidentState(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 12, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			d := entry(testUDID, 12, "USB")
			d.Rsd = fullRsd
			return d, nil
		})
	stubLockdown(t, refusedLockdown)
	want, _ := json.Marshal((&bridge{}).probe())
	got, _ := json.Marshal((&bridge{}).status())
	if !bytes.Equal(got, want) {
		t.Fatalf("the shared status changed the bytes\n got: %s\nwant: %s", got, want)
	}
}
