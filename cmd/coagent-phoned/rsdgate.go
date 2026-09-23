package main

// One contact at a time with the phone's RSD port.
//
// Measured on Steve's iPhone Air (iOS 27.0) on 2026-09-23, over the tunnel
// road and the lan road alike: when a second connection reaches the phone's
// RSD port while an RSD handshake is in flight, the phone RESETS the handshake
// in flight ("NewHttpConnection: could not read frame ... connection reset by
// peer"), and /status reports see/act/apps down with phone_tunnel_unreachable.
// /status alone: 5/5 up. With one concurrent bare TCP connect: 0/5. Three
// /status calls at once: at most one up.
//
// The second connection came from this process as often as from outside it:
// the daemon's 30 s /status tick and a voice request's /status, the keeper's
// "is the phone seeing yet" /status and the daemon's, this process's own
// liveness connect (tunnelAnswers) against its own handshake. So:
//
//   - every contact this process makes with a tunnel's RSD port (the handshake
//     in either mode, and the no-mux liveness connect) holds that tunnel's
//     rsdGate, and waits for it inside its own budget;
//   - a caller that waited behind a handshake which then succeeded takes that
//     answer instead of opening the port again (the handshake was in flight
//     when it asked, so the answer is not older than its question);
//   - a handshake the phone reset (RST or EOF, not a refused dial, not a
//     timeout) is retried once, after a short jittered pause, if the retry
//     still fits the budget: a contact from outside this process (an old
//     keeper's TCP probe, another phoned during a re-point) can still land;
//   - concurrent /status calls share one probe, and an answer younger than
//     statusReuse is answered again (see bridge.status).
//
// Service connections that do the actual work (the screenshot's DTX service,
// display, HID, the installation_proxy shim) go to other ports and never take
// the gate: a tap is never queued behind a status handshake.

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/danielpaulus/go-ios/ios"
)

var (
	// muxHandshakeTimeout bounds the usbmux-mode (lan road) handshake, the wait
	// for the gate included. It used to be unbounded after a 15 s dial; with a
	// gate that every later contact queues behind, an unbounded hold would
	// wedge every /status of this process instead of just one.
	muxHandshakeTimeout = 10 * time.Second

	// The one retry of a reset handshake: a pause of rsdRetryMin plus up to
	// rsdRetrySpread (jittered, so two callers the phone reset together do not
	// collide again), and only if rsdRetryLeast still fits after it.
	rsdRetryMin    = 150 * time.Millisecond
	rsdRetrySpread = 250 * time.Millisecond
	rsdRetryLeast  = 1500 * time.Millisecond
	retryPause     = func() time.Duration { return rsdRetryMin + rand.N(rsdRetrySpread) }

	// errRsdBusy: another contact held the tunnel's RSD port for the caller's
	// whole budget. Every holder is bounded, so this means the port answered
	// nobody in that time, which is what phone_tunnel_unreachable says.
	errRsdBusy = errors.New("the phone's RSD port stayed busy with another contact")
)

// rsdGate serialises every contact with one tunnel's RSD port.
type rsdGate struct {
	sem chan struct{} // capacity 1: holding it is holding the port

	// Written by a holder before it releases, read by a later holder after it
	// acquires: the channel hand-off orders the two.
	okAt   time.Time // when a handshake here last succeeded
	okP    ios.RsdPortProvider
	okUDID string
	proved time.Time // when any contact here last succeeded (a handshake or a liveness connect)
}

var rsdGates sync.Map // "[addr]:port" -> *rsdGate

// gateFor returns the gate of the tunnel's RSD port at addr:port.
func gateFor(addr string, port int) *rsdGate {
	key := net.JoinHostPort(addr, strconv.Itoa(port))
	if g, ok := rsdGates.Load(key); ok {
		return g.(*rsdGate)
	}
	g, _ := rsdGates.LoadOrStore(key, &rsdGate{sem: make(chan struct{}, 1)})
	return g.(*rsdGate)
}

// acquire takes the gate, waiting at most until deadline. waited is false when
// the gate was free at once.
func (g *rsdGate) acquire(deadline time.Time) (ok, waited bool) {
	select {
	case g.sem <- struct{}{}:
		return true, false
	default:
	}
	wait := time.Until(deadline)
	if wait <= 0 {
		return false, true
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case g.sem <- struct{}{}:
		return true, true
	case <-t.C:
		return false, true
	}
}

func (g *rsdGate) release() { <-g.sem }

// handshakeReset: the phone closed the RSD connection on us (RST, or a FIN
// before its answer) during the handshake — what it does to a handshake in
// flight when a second connection reaches the port. A refused dial (nothing
// listening) and a timeout (nothing answering) are not resets: a retry cannot
// fix those, and on a dead tunnel it would only double the wait.
func handshakeReset(err error) bool {
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ios.ErrDialTimeout) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// rsdHandshake runs one RSD handshake with the tunnel at addr:port under that
// tunnel's gate, all within budget: the wait for the gate, the attempt, and the
// one retry of a reset. attempt gets the time it may take.
func rsdHandshake(addr string, port int, budget time.Duration,
	attempt func(timeout time.Duration) (ios.RsdPortProvider, string, error)) (ios.RsdPortProvider, string, error) {
	asked := time.Now()
	deadline := asked.Add(budget)
	g := gateFor(addr, port)
	ok, waited := g.acquire(deadline)
	if !ok {
		return nil, "", fmt.Errorf("phone_tunnel_unreachable: %w: [%s]:%d answered no one within %s", errRsdBusy, addr, port, budget)
	}
	defer g.release()
	if waited && g.okAt.After(asked) {
		// The handshake this caller queued behind was in flight when it asked.
		return g.okP, g.okUDID, nil
	}
	timeout := budget
	if waited {
		timeout = time.Until(deadline)
	}
	p, udid, err := attempt(timeout)
	if err != nil && handshakeReset(err) {
		pause := retryPause()
		if left := time.Until(deadline); left >= pause+rsdRetryLeast {
			log.Printf("rsd: [%s]:%d reset the handshake (%v); one retry in %s", addr, port, err, pause.Round(time.Millisecond))
			time.Sleep(pause)
			p, udid, err = attempt(time.Until(deadline))
			if err != nil {
				log.Printf("rsd: [%s]:%d the retry failed too: %v", addr, port, err)
			}
		}
	}
	if err == nil {
		now := time.Now()
		g.okAt, g.okP, g.okUDID, g.proved = now, p, udid, now
	}
	return p, udid, err
}

// rsdAlive is the no-mux liveness test (tunnelAlive, a TCP connect to the RSD
// port) under the tunnel's gate, all within budget. A contact that succeeded
// while this caller waited for the gate proves the tunnel answers, and nothing
// more is opened.
func rsdAlive(addr string, port int, budget time.Duration) error {
	asked := time.Now()
	deadline := asked.Add(budget)
	g := gateFor(addr, port)
	ok, waited := g.acquire(deadline)
	if !ok {
		return fmt.Errorf("phone_tunnel_unreachable: %w: [%s]:%d did not prove itself within %s", errRsdBusy, addr, port, budget)
	}
	defer g.release()
	timeout := budget
	if waited {
		if g.proved.After(asked) {
			return nil
		}
		if timeout = time.Until(deadline); timeout <= 0 {
			return fmt.Errorf("phone_tunnel_unreachable: %w: [%s]:%d did not prove itself within %s", errRsdBusy, addr, port, budget)
		}
	}
	if err := tunnelAlive(addr, port, timeout); err != nil {
		return err
	}
	g.proved = time.Now()
	return nil
}

// --- /status: one probe at a time -------------------------------------------

var (
	// statusReuse: a /status answer this young is answered again rather than
	// asking the phone twice (the daemon's tick and a voice request, or the
	// keeper and the daemon, land within a second of each other).
	statusReuse = time.Second
	// statusFlightLimit: no probe legitimately runs this long (no-mux: 10 s;
	// lan: the 10 s handshake plus local calls). A caller that finds a probe
	// older than this starts its own instead of joining one that may never end.
	statusFlightLimit = 20 * time.Second
)

// statusFlight is one /status probe, in flight or finished.
type statusFlight struct {
	start    time.Time
	done     chan struct{}
	st       status    // set before done is closed
	end      time.Time // set before done is closed
	panicked bool      // set before done is closed: the probe measured nothing, so it is never answered again
}

// status answers /status. Concurrent callers share one probe, and an answer
// younger than statusReuse is given again, its capabilities aged by how long
// ago it was measured (ageMs, as the apps answer already does). A fresh
// answer is exactly probe().
func (b *bridge) status() status {
	b.flightMu.Lock()
	if f := b.flight; f != nil {
		select {
		case <-f.done:
			if age := time.Since(f.end); age < statusReuse && !f.panicked {
				b.flightMu.Unlock()
				return f.st.aged(age)
			}
		default:
			if wait := time.Until(f.start.Add(statusFlightLimit)); wait > 0 {
				b.flightMu.Unlock()
				t := time.NewTimer(wait)
				defer t.Stop()
				select {
				case <-f.done:
					return f.st
				case <-t.C:
				}
				b.flightMu.Lock()
				if b.flight == f {
					b.flight = nil
				}
				b.flightMu.Unlock()
				log.Printf("status: a probe outlived %s; starting another", statusFlightLimit)
				return b.status()
			}
		}
	}
	f := &statusFlight{start: time.Now(), done: make(chan struct{})}
	b.flight = f
	b.flightMu.Unlock()
	return b.fly(f)
}

// fly runs f's probe and finishes f whatever happens, a panic included.
//
// Before the probe was shared, a panic in it failed only its own call (net/http
// recovers a handler). Left unfinished, f would hold every later /status until
// statusFlightLimit ran out: 20 s, past the bridge's 12 s alarm and level with
// the daemon's 20 s abort. go-ios's RSD handshake type-asserts the phone's
// answer unchecked, so one malformed answer is enough. So the panic is
// recovered here and its stack logged (it is still a bug to find), the caller
// and every caller that joined get probePanicked's answer at once, and the
// answer is never given again: the next /status probes afresh.
func (b *bridge) fly(f *statusFlight) (st status) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("status: the probe panicked: %v\n%s", r, debug.Stack())
			st = probePanicked(r)
			f.panicked = true
		}
		f.st, f.end = st, time.Now()
		close(f.done)
	}()
	return b.probe()
}

// probePanicked is the /status answer of a probe that panicked. Nothing was
// measured, so all three capabilities are unknown (not ok, and not a claim
// that anything is down), under phone_bridge_error: this process failed in a
// way it cannot name, which is exactly that reason's words to the user (try
// once more; if it fails again, restart the bridge). It is not a road reason,
// so the daemon does not go re-measuring a road that is fine. The cause leads
// the detail, where the logs can still tell it apart.
func probePanicked(r any) status {
	c := capability{State: capUnknown, Reason: reasonBridgeError,
		Detail: fmt.Sprintf("%s: %s: %v", reasonBridgeError, causeProbePanicked, r)}
	return status{See: c, Act: c, Apps: c}.summarize()
}

// aged is st answered again age after it was measured.
func (st status) aged(age time.Duration) status {
	ms := age.Milliseconds()
	if ms <= 0 {
		return st
	}
	for _, c := range []*capability{&st.See, &st.Act, &st.Apps} {
		c.AgeMs += ms
	}
	return st
}
