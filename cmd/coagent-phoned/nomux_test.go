// Device-free tests for coagent-phoned's no-mux mode (the relay tunnel road).
//
// The same rule as main_test.go: nothing here may reach a real iPhone. The
// RSD handshake is stubbed; the installation_proxy shim is a fake served on
// 127.0.0.1 by this test process, reached through the real shim code.
//
// Every test runs with listDevices and the 28100 tunnel-info lookup wired to
// t.Fatal, which is the proof that no route, probe or cache check in this
// mode consults usbmux or the `ios tunnel start` agent.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/tunnel"
	"howett.net/plist"
)

const (
	noMuxAddr = "127.0.0.1" // the fake shim listens here; stands in for fd..::1
	noMuxRsd  = 50921
)

// noMuxMode puts the package into no-mux mode for one test, exactly as main()
// would, then makes every usbmux and tunnel-agent seam fail the test if used.
func noMuxMode(t *testing.T, pin noMuxPin) {
	t.Helper()
	oldPin, oldResolve, oldList, oldApps, oldInfo := noMux, resolve, listDevices, listApps, tunnelInfoForDevice
	oldLockdown, oldShim, oldHS, oldAlive := probeLockdown, probeShim, handshakeNoMux, tunnelAlive
	t.Cleanup(func() {
		noMux, resolve, listDevices, listApps, tunnelInfoForDevice = oldPin, oldResolve, oldList, oldApps, oldInfo
		probeLockdown, probeShim, handshakeNoMux, tunnelAlive = oldLockdown, oldShim, oldHS, oldAlive
	})
	useNoMux(pin)
	// The stand-in tunnel (the fake shim on loopback) has nothing on its RSD
	// port, so the liveness test answers "alive" unless a test says otherwise.
	tunnelAlive = func(string, int, time.Duration) error { return nil }
	listDevices = func() (ios.DeviceList, error) {
		t.Fatal("no-mux mode consulted usbmux")
		return ios.DeviceList{}, nil
	}
	tunnelInfoForDevice = func(string, string, int) (tunnel.Tunnel, error) {
		t.Fatal("no-mux mode asked the 127.0.0.1:28100 tunnel agent")
		return tunnel.Tunnel{}, nil
	}
	probeLockdown = func(ios.DeviceEntry) error {
		t.Fatal("no-mux mode opened a lockdown session")
		return nil
	}
}

func defaultPin() noMuxPin { return noMuxPin{addr: noMuxAddr, rsd: noMuxRsd, udid: testUDID} }

// handshakes stubs the no-mux handshake and counts calls. The table and UDID
// can be changed between calls through the returned pointers.
type handshakeStub struct {
	calls int
	table ios.RsdPortProvider
	udid  string
	err   error
	got   tunnel.Tunnel
}

func stubNoMuxHandshake(t *testing.T, table ios.RsdPortProvider, udid string) *handshakeStub {
	t.Helper()
	h := &handshakeStub{table: table, udid: udid}
	handshakeNoMux = func(info tunnel.Tunnel, d ios.DeviceEntry, _ time.Duration) (ios.RsdPortProvider, string, error) {
		h.calls++
		h.got = info
		if d.DeviceID != 0 || d.Properties.ConnectionType == "USB" {
			t.Fatalf("the no-mux entry pretends to be a usbmux row: %+v", d)
		}
		if h.err != nil {
			return nil, "", h.err
		}
		return h.table, h.udid, nil
	}
	return h
}

// withShim returns fullRsd plus the installation_proxy shim at port.
func withShim(port int) fakeRsd {
	return fakeRsd{svcScreenshot: 51000, svcHID: 51001, svcAppsShim: port}
}

// --- the fake installation_proxy shim ---------------------------------------

func shimFrame(w io.Writer, v any) error {
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

func shimUnframe(r io.Reader) (map[string]any, error) {
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

type shimBehaviour int

const (
	shimHealthy     shimBehaviour = iota // checks in, answers every Browse
	shimRefuses                          // answers the checkin with an Error
	shimWedgedList                       // checks in, then never answers Browse
	shimWedgedCheck                      // accepts, never answers the checkin
	shimFlakyOnce                        // drops the first connection mid-checkin, then is healthy
)

// fakeAppsShim serves the device side of com.apple.mobile.installation_proxy.
// shim.remote on loopback and counts the connections it accepted.
func fakeAppsShim(t *testing.T, how shimBehaviour) (port int, accepted *atomic.Int32) {
	t.Helper()
	port, accepted, _ = fakeAppsShimRecording(t, how)
	return port, accepted
}

// fakeAppsShimRecording is fakeAppsShim that also hands every Browse request
// it read to browses.
func fakeAppsShimRecording(t *testing.T, how shimBehaviour) (port int, accepted *atomic.Int32, browses chan map[string]any) {
	t.Helper()
	browses = make(chan map[string]any, 16)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted = &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n := accepted.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				req, err := shimUnframe(c)
				if err != nil || req["Request"] != "RSDCheckin" {
					return
				}
				if how == shimFlakyOnce && n == 1 {
					return
				}
				switch how {
				case shimWedgedCheck:
					io.Copy(io.Discard, c)
					return
				case shimRefuses:
					shimFrame(c, map[string]any{"Request": "RSDCheckin", "Error": "ServiceProhibited"})
					shimFrame(c, map[string]any{"Request": "StartService"})
					io.Copy(io.Discard, c)
					return
				}
				shimFrame(c, map[string]any{"Request": "RSDCheckin"})
				shimFrame(c, map[string]any{"Request": "StartService"})
				for {
					req, err := shimUnframe(c)
					if err != nil {
						return
					}
					select {
					case browses <- req:
					default:
					}
					if how == shimWedgedList {
						io.Copy(io.Discard, c)
						return
					}
					kind := ""
					if opts, ok := req["ClientOptions"].(map[string]any); ok {
						kind, _ = opts["ApplicationType"].(string)
					}
					app := map[string]any{"CFBundleIdentifier": "com.apple.mobilemail", "CFBundleName": "Mail",
						"ApplicationType": kind, "CFBundleIcons": map[string]any{}}
					if kind == "User" {
						app = map[string]any{"CFBundleIdentifier": "com.example.notes", "CFBundleName": "Notes",
							"ApplicationType": kind, "CFBundleIcons": map[string]any{}}
					}
					shimFrame(c, map[string]any{"Status": "Complete", "CurrentIndex": uint64(0), "CurrentAmount": uint64(1),
						"CurrentList": []any{app}})
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, accepted, browses
}

// --- the switch -------------------------------------------------------------

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestParseNoMuxIsOffUnlessTheSwitchIsOne(t *testing.T) {
	for _, v := range []string{"", "0", " "} {
		pin, err := parseNoMux(envOf(map[string]string{envNoMux: v, envAddr: "fd00::1", envRsd: "50000"}))
		if err != nil || pin.on {
			t.Fatalf("%s=%q must leave no-mux off, got %+v %v", envNoMux, v, pin, err)
		}
	}
}

func TestParseNoMuxReadsThePin(t *testing.T) {
	pin, err := parseNoMux(envOf(map[string]string{envNoMux: "1", envAddr: " fd0b:a682:6f11::1 ", envRsd: "50921", envUDID: testUDID}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pin.on || pin.addr != "fd0b:a682:6f11::1" || pin.rsd != 50921 || pin.udid != testUDID {
		t.Fatalf("pin read wrong: %+v", pin)
	}
	pin, err = parseNoMux(envOf(map[string]string{envNoMux: "1", envAddr: "fd00::1", envRsd: "50000"}))
	if err != nil || pin.udid != "" {
		t.Fatalf("the expected UDID is optional: %+v %v", pin, err)
	}
}

// A switch or pin that will not parse is refused by name, never run as the
// usbmux mode on a road that has no usbmux.
func TestParseNoMuxRefusesWhatItCannotUse(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"switch yes":   {envNoMux: "yes", envAddr: "fd00::1", envRsd: "50000"},
		"no address":   {envNoMux: "1", envRsd: "50000"},
		"hostname":     {envNoMux: "1", envAddr: "iphone.local", envRsd: "50000"},
		"bracketed":    {envNoMux: "1", envAddr: "[fd00::1]", envRsd: "50000"},
		"no port":      {envNoMux: "1", envAddr: "fd00::1"},
		"port garbage": {envNoMux: "1", envAddr: "fd00::1", envRsd: "x"},
		"port zero":    {envNoMux: "1", envAddr: "fd00::1", envRsd: "0"},
		"port too big": {envNoMux: "1", envAddr: "fd00::1", envRsd: "70000"},
	} {
		if _, err := parseNoMux(envOf(env)); err == nil || reasonOf(err) != reasonTunnelEnvInvalid {
			t.Fatalf("%s: wanted %s, got %v", name, reasonTunnelEnvInvalid, err)
		}
	}
}

// The switch is read in main() only. A developer shell with it exported must
// not change what the usbmux-mode code does: this is the incident-state test
// again, byte for byte, with the whole no-mux environment set.
func TestAnExportedNoMuxSwitchDoesNotFlipTheMuxPath(t *testing.T) {
	t.Setenv(envNoMux, "1")
	t.Setenv(envUDID, "someone-else")
	TestStatusBytesForTheIncidentState(t)
	if noMux.on {
		t.Fatal("the package switch turned itself on from the environment")
	}
}

// --- the resolver -----------------------------------------------------------

func TestNoMuxResolveTakesTheDeviceFromThePinAndTheUDIDFromTheHandshake(t *testing.T) {
	noMuxMode(t, noMuxPin{addr: "fd0b:a682:6f11::1", rsd: 50921})
	h := stubNoMuxHandshake(t, fullRsd, testUDID)
	d, err := resolve()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.got.Address != "fd0b:a682:6f11::1" || h.got.RsdPort != 50921 {
		t.Fatalf("handshook somewhere other than the pin: %+v", h.got)
	}
	if d.Properties.SerialNumber != testUDID {
		t.Fatalf("the UDID must be the one the handshake reported, got %q", d.Properties.SerialNumber)
	}
	if d.Address != "fd0b:a682:6f11::1" || d.Rsd == nil || d.Rsd.GetPort(svcHID) != fullRsd[svcHID] {
		t.Fatalf("address or RSD table dropped: %+v", d)
	}
	if d.DeviceID != 0 || d.Properties.ConnectionType == "USB" {
		t.Fatalf("a no-mux entry must not look like a usbmux row: %+v", d)
	}
}

func TestNoMuxResolveRefusesAnotherPhone(t *testing.T) {
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, fullRsd, "00008150-0000000000000000")
	_, err := resolve()
	if err == nil || reasonOf(err) != reasonDeviceFailed || !errors.Is(err, errWrongDevice) {
		t.Fatalf("wanted %s (%s), got %v", reasonDeviceFailed, causeWrongDevice, err)
	}
	if !strings.Contains(err.Error(), testUDID) || !strings.Contains(err.Error(), "00008150-0000000000000000") {
		t.Fatalf("the detail must name both phones: %v", err)
	}
}

func TestNoMuxResolveComparesTheUDIDWithoutCase(t *testing.T) {
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, fullRsd, strings.ToLower(testUDID))
	if _, err := resolve(); err != nil {
		t.Fatalf("the same UDID in another case is the same phone: %v", err)
	}
}

func TestNoMuxResolveWithoutAnExpectedUDIDAcceptsWhoeverAnswers(t *testing.T) {
	noMuxMode(t, noMuxPin{addr: noMuxAddr, rsd: noMuxRsd})
	stubNoMuxHandshake(t, fullRsd, "00008150-0000000000000000")
	d, err := resolve()
	if err != nil || d.Properties.SerialNumber != "00008150-0000000000000000" {
		t.Fatalf("got %+v %v", d, err)
	}
}

func TestNoMuxResolveKeepsTheHandshakeReasons(t *testing.T) {
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, fullRsd, testUDID)
	for _, reason := range []string{"phone_tunnel_unreachable", "phone_handshake_failed"} {
		h.err = fmt.Errorf("%s: boom", reason)
		if _, err := resolve(); err == nil || reasonOf(err) != reason {
			t.Fatalf("wanted %s, got %v", reason, err)
		}
	}
}

// The real handshake seam, against a port nothing listens on: the reason must
// be the tunnel one, and it must come back inside the no-mux budget.
func TestNoMuxRealHandshakeNamesAnUnreachableTunnel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	noMuxMode(t, noMuxPin{addr: "127.0.0.1", rsd: port, udid: testUDID})
	old := noMuxHandshakeTimeout
	noMuxHandshakeTimeout = time.Second
	t.Cleanup(func() { noMuxHandshakeTimeout = old })
	start := time.Now()
	_, err = resolve()
	if err == nil || reasonOf(err) != "phone_tunnel_unreachable" {
		t.Fatalf("wanted phone_tunnel_unreachable, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("the handshake was not bounded: %s", time.Since(start))
	}
}

// --- the cache --------------------------------------------------------------

// Without usbmux there is nothing local to re-check, so an entry for the
// pinned tunnel is trusted: no handshake per call and, above all, no
// condemned gesture session per call.
func TestNoMuxCacheIsTrustedWithoutUsbmux(t *testing.T) {
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, fullRsd, testUDID)
	b := &bridge{ready: true}
	first, err := b.device()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := b.device()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.calls != 1 {
		t.Fatalf("wanted one handshake for two calls, got %d", h.calls)
	}
	if !sameDevice(first, second) || b.stale.Load() {
		t.Fatalf("a trusted cache condemned the gesture session: stale=%v", b.stale.Load())
	}
}

func TestNoMuxCacheRejectsAnEntryForAnotherTunnel(t *testing.T) {
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, fullRsd, testUDID)
	b := &bridge{}
	old := entry(testUDID, 0, connNoMux)
	old.Address, old.Rsd = "fd00::old", fullRsd
	cached(b, old)
	d, err := b.device()
	if err != nil || h.calls != 1 || d.Address != noMuxAddr {
		t.Fatalf("an entry for another tunnel was trusted: %+v calls=%d err=%v", d, h.calls, err)
	}
}

// A dead tunnel is still caught without usbmux: the retry re-resolves, the
// re-resolve fails, and only then is the gesture session condemned.
func TestNoMuxDeadTunnelCondemnsTheSessionThroughTheRetry(t *testing.T) {
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, fullRsd, testUDID)
	b := &bridge{ready: true}
	err := b.withDevice(func(ios.DeviceEntry) error {
		h.err = errors.New("phone_tunnel_unreachable: dial timed out")
		return errors.New("phone_capture_failed: dtx gone")
	})
	if err == nil || reasonOf(err) != "phone_tunnel_unreachable" {
		t.Fatalf("wanted the tunnel reason, got %v", err)
	}
	if !b.stale.Load() {
		t.Fatal("the tunnel is gone; the gesture session must be condemned")
	}
}

func TestNoMuxTransientFailureLeavesTheSessionAlone(t *testing.T) {
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, fullRsd, testUDID)
	b := &bridge{ready: true}
	calls := 0
	err := b.withDevice(func(ios.DeviceEntry) error {
		calls++
		if calls == 1 {
			return errors.New("phone_capture_failed: dtx hiccup")
		}
		return nil
	})
	if err != nil || calls != 2 || b.stale.Load() {
		t.Fatalf("wanted a clean retry on the same tunnel, got err=%v calls=%d stale=%v", err, calls, b.stale.Load())
	}
}

// --- /status ----------------------------------------------------------------

// The whole road green: see/act from the RSD table, apps from a real RSDCheckin
// on the fake shim, over the real shim code.
func TestNoMuxProbeProvesAppsOverTheShim(t *testing.T) {
	port, accepted := fakeAppsShim(t, shimHealthy)
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, withShim(port), testUDID)
	st := (&bridge{}).probe()
	if !st.OK || !st.See.up() || !st.Act.up() || !st.Apps.up() {
		t.Fatalf("wanted every capability up, got %+v", st)
	}
	if st.Apps.Proof != proofShim || st.See.Proof != proofRSD {
		t.Fatalf("wrong proofs: %+v", st)
	}
	if st.UDID != testUDID || st.Reason != "" {
		t.Fatalf("wanted udid %s and no reason, got %+v", testUDID, st)
	}
	if accepted.Load() != 1 {
		t.Fatalf("wanted exactly one shim connection, got %d", accepted.Load())
	}
}

// If the phone's RSD does not list the shim, see and act still come up and
// apps says why it cannot, without opening anything.
func TestNoMuxProbeWithoutTheShimKeepsSeeAndAct(t *testing.T) {
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, fullRsd, testUDID)
	probeShim = func(ios.DeviceEntry) error {
		t.Fatal("opened a shim the RSD table does not list")
		return nil
	}
	st := (&bridge{}).probe()
	if !st.See.up() || !st.Act.up() {
		t.Fatalf("see/act must come up without the shim, got %+v", st)
	}
	if st.Apps.State != capDown || st.Apps.Reason != reasonAppsUnreadable || st.Apps.Proof != proofRSD {
		t.Fatalf("wanted apps down/%s proven by the table, got %+v", reasonAppsUnreadable, st.Apps)
	}
	if !strings.HasPrefix(st.Apps.Detail, reasonAppsUnreadable+": "+causeAppsRemoteUnavailable+": ") {
		t.Fatalf("the precise cause must lead the detail: %q", st.Apps.Detail)
	}
	if st.OK || st.Reason != reasonAppsUnreadable {
		t.Fatalf("wanted ok=false reason=%s, got %+v", reasonAppsUnreadable, st)
	}
}

func TestNoMuxProbeReportsARefusedCheckin(t *testing.T) {
	port, _ := fakeAppsShim(t, shimRefuses)
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, withShim(port), testUDID)
	st := (&bridge{}).probe()
	if st.Apps.State != capDown || st.Apps.Reason != reasonAppsUnreadable || st.Apps.Proof != proofShim {
		t.Fatalf("wanted apps down/%s via the shim, got %+v", reasonAppsUnreadable, st.Apps)
	}
	if !strings.Contains(st.Apps.Detail, "ServiceProhibited") {
		t.Fatalf("the phone's own refusal must reach the detail: %q", st.Apps.Detail)
	}
	if !st.See.up() || !st.Act.up() || st.OK {
		t.Fatalf("got %+v", st)
	}
}

// A shim that accepts and says nothing must not hold /status past its budget.
func TestNoMuxProbeBoundsAWedgedShim(t *testing.T) {
	port, _ := fakeAppsShim(t, shimWedgedCheck)
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, withShim(port), testUDID)
	old := shimCheckinTimeout
	shimCheckinTimeout = 300 * time.Millisecond
	t.Cleanup(func() { shimCheckinTimeout = old })
	start := time.Now()
	st := (&bridge{}).probe()
	if time.Since(start) > 3*time.Second {
		t.Fatalf("/status waited %s on a wedged shim", time.Since(start))
	}
	if st.Apps.State != capDown || st.Apps.Reason != reasonAppsUnreadable {
		t.Fatalf("wanted apps down/%s, got %+v", reasonAppsUnreadable, st.Apps)
	}
}

// One tunnel carries everything, so when it does not answer all three are down
// for that one reason and no UDID is claimed. And because the gesture session
// rides that same tunnel, the probe condemns it (see probeNoMux).
func TestNoMuxProbeWithTheTunnelDown(t *testing.T) {
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, fullRsd, testUDID)
	h.err = errors.New("phone_tunnel_unreachable: dial timed out")
	b := &bridge{ready: true}
	st := b.probe()
	for name, c := range map[string]capability{"see": st.See, "act": st.Act, "apps": st.Apps} {
		if c.State != capDown || c.Reason != "phone_tunnel_unreachable" {
			t.Fatalf("%s: wanted down/phone_tunnel_unreachable, got %+v", name, c)
		}
	}
	if st.OK || st.UDID != "" || st.Reason != "phone_tunnel_unreachable" {
		t.Fatalf("got %+v", st)
	}
	if !b.stale.Load() {
		t.Fatal("the tunnel the gesture session rides did not answer; the session must be condemned")
	}
}

func TestNoMuxProbeWithAnotherPhoneClaimsNothing(t *testing.T) {
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, fullRsd, "00008150-0000000000000000")
	st := (&bridge{}).probe()
	if st.OK || st.UDID != "" || st.See.up() || st.Apps.Reason != reasonDeviceFailed || st.Reason != reasonDeviceFailed {
		t.Fatalf("wanted everything down/%s and no udid, got %+v", reasonDeviceFailed, st)
	}
	if !strings.Contains(st.Detail, causeWrongDevice) {
		t.Fatalf("the detail must name the cause: %q", st.Detail)
	}
}

func TestNoMuxProbeCachesTheShimAnswerBriefly(t *testing.T) {
	port, accepted := fakeAppsShim(t, shimHealthy)
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, withShim(port), testUDID)
	b := &bridge{}
	b.probe()
	b.probe()
	if accepted.Load() != 1 {
		t.Fatalf("wanted the second poll to reuse the answer, got %d checkins", accepted.Load())
	}
	old := appsProbeTTL
	appsProbeTTL = time.Nanosecond
	t.Cleanup(func() { appsProbeTTL = old })
	if st := b.probe(); accepted.Load() != 2 || !st.Apps.up() {
		t.Fatalf("wanted a fresh checkin once the answer aged out, got %d / %+v", accepted.Load(), st.Apps)
	}
}

// DeviceID is 0 for every no-mux entry, so the tunnel has to be in the key: a
// re-armed tunnel is a new question, the same tunnel is the same one.
func TestNoMuxAppsKeyFollowsTheTunnel(t *testing.T) {
	noMuxMode(t, defaultPin())
	a := entry(testUDID, 0, connNoMux)
	a.Address = "fd0b:a682:6f11::1"
	b := a
	if appsKey(a) != appsKey(b) {
		t.Fatal("the same tunnel produced two keys")
	}
	b.Address = "fd28:70af:d64e::1"
	if appsKey(a) == appsKey(b) {
		t.Fatal("a re-armed tunnel inherited the old tunnel's apps answer")
	}
	k := appsKey(a)
	noMux.rsd = noMuxRsd + 1
	if appsKey(a) == k {
		t.Fatal("a new RSD port inherited the old tunnel's apps answer")
	}
}

func TestNoMuxProbeOffSaysUnknownAndNamesTheShim(t *testing.T) {
	t.Setenv(envAppsProbe, "off")
	port, accepted := fakeAppsShim(t, shimHealthy)
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, withShim(port), testUDID)
	st := (&bridge{}).probe()
	if st.Apps.State != capUnknown || st.Apps.Reason != reasonAppsUnprobed || st.OK {
		t.Fatalf("wanted apps unknown/%s, got %+v", reasonAppsUnprobed, st)
	}
	if !strings.Contains(st.Apps.Detail, "installation_proxy shim") || accepted.Load() != 0 {
		t.Fatalf("the probe is off: nothing may be opened (%d) and the detail must say what was not: %q", accepted.Load(), st.Apps.Detail)
	}
}

// The status body keeps the one shape the bridge and daemon parse.
func TestNoMuxStatusBytes(t *testing.T) {
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, fullRsd, testUDID)
	raw, err := json.Marshal((&bridge{}).probe())
	if err != nil {
		t.Fatal(err)
	}
	detail := "phone_apps_unreadable: phone_apps_unavailable_remote: com.apple.mobile.installation_proxy.shim.remote is not in the phone's RSD service table"
	want := `{"ok":false,"udid":"` + testUDID + `",` +
		`"see":{"state":"up","proof":"rsd_service_table"},` +
		`"act":{"state":"up","proof":"rsd_service_table"},` +
		`"apps":{"state":"down","proof":"rsd_service_table","reason":"phone_apps_unreadable","detail":"` + detail + `"},` +
		`"reason":"phone_apps_unreadable","detail":"` + detail + `"}`
	if string(raw) != want {
		t.Fatalf("no-mux status body\n got: %s\nwant: %s", raw, want)
	}
}

// --- /apps ------------------------------------------------------------------

func TestNoMuxAppsListsOverTheShim(t *testing.T) {
	port, _ := fakeAppsShim(t, shimHealthy)
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, withShim(port), testUDID)
	b := &bridge{}
	out, err := b.apps()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 || out[0]["bundleId"] != "com.example.notes" || out[1]["bundleId"] != "com.apple.mobilemail" {
		t.Fatalf("wanted the user app then the system app, got %v", out)
	}
	if out[1]["openable"] != true {
		t.Fatalf("rows must be built exactly as on the usbmux road: %v", out[1])
	}
	// And /status uses that listing as its proof without opening the shim again.
	probeShim = func(ios.DeviceEntry) error {
		t.Fatal("re-probed the shim although /apps had just answered")
		return nil
	}
	if st := b.probe(); !st.Apps.up() || st.Apps.Proof != proofListed || !st.OK {
		t.Fatalf("wanted apps up proven by the listing, got %+v", st)
	}
}

func TestNoMuxAppsWithoutTheShimSaysSo(t *testing.T) {
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, fullRsd, testUDID)
	_, err := (&bridge{}).apps()
	if err == nil || reasonOf(err) != reasonAppsUnreadable || !errors.Is(err, errShimNotListed) {
		t.Fatalf("wanted %s (%s), got %v", reasonAppsUnreadable, causeAppsRemoteUnavailable, err)
	}
}

// A shim that checks in and then never finishes the listing gives a named
// failure inside the budget, not a hung request.
func TestNoMuxAppsListingIsBounded(t *testing.T) {
	port, _ := fakeAppsShim(t, shimWedgedList)
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, withShim(port), testUDID)
	old := shimListTimeout
	shimListTimeout = 300 * time.Millisecond
	t.Cleanup(func() { shimListTimeout = old })
	start := time.Now()
	_, err := listAppsShim(func() ios.DeviceEntry { d, _ := resolve(); return d }())
	if err == nil || reasonOf(err) != reasonAppsFailed || !strings.Contains(err.Error(), "within") {
		t.Fatalf("wanted a bounded %s, got %v", reasonAppsFailed, err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("the listing was not bounded: %s", time.Since(start))
	}
}

func TestNoMuxAppsFailureLeavesTheGestureSessionAlone(t *testing.T) {
	port, _ := fakeAppsShim(t, shimRefuses)
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, withShim(port), testUDID)
	b := &bridge{ready: true}
	if _, err := b.apps(); err == nil || reasonOf(err) != reasonAppsUnreadable {
		t.Fatalf("wanted %s, got %v", reasonAppsUnreadable, err)
	}
	if b.stale.Load() {
		t.Fatal("a refused app listing condemned the gesture session")
	}
}

// --- words ------------------------------------------------------------------

func TestNoMuxReasonsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range []string{reasonNotConnected, reasonMuxUnreachable, reasonAppsUnreadable, reasonAppsFailed,
		reasonAppsUnprobed, reasonDeviceFailed, causeWrongDevice, causeAppsRemoteUnavailable, reasonTunnelEnvInvalid, reasonNoMux,
		"phone_tunnel_unreachable", "phone_handshake_failed", "phone_tunnel_down"} {
		if seen[r] {
			t.Fatalf("reason %q is used for two different states", r)
		}
		seen[r] = true
	}
	for _, p := range []string{proofRSD, proofLockdown, proofListed} {
		if p == proofShim {
			t.Fatalf("proof %q is used for two different channels", p)
		}
	}
}

// useNoMux itself leaves the usbmux seam refusing, so a branch that forgot to
// check the switch fails loudly instead of reading usbmux.
func TestUseNoMuxLeavesUsbmuxRefusing(t *testing.T) {
	oldPin, oldResolve, oldList, oldApps := noMux, resolve, listDevices, listApps
	t.Cleanup(func() { noMux, resolve, listDevices, listApps = oldPin, oldResolve, oldList, oldApps })
	useNoMux(defaultPin())
	if _, err := listDevices(); err == nil || reasonOf(err) != reasonNoMux {
		t.Fatalf("wanted %s, got %v", reasonNoMux, err)
	}
	if !noMux.on {
		t.Fatal("useNoMux did not switch the mode on")
	}
}
