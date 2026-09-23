// Device-free tests for no-mux mode when the relay tunnel dies or slows down.
//
// Over the relay the tunnel can die while its utun stays up ("black-holed"):
// nothing answers, and nothing fails fast either. Two things must hold then:
// a gesture never claims success into it, and every route still answers inside
// the installed daemon's 20 s, because past that the user hears "locked or
// asleep" whatever really failed. Same rule as the other test files: nothing
// here reaches a real iPhone.
package main

import (
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/display"
	"github.com/danielpaulus/go-ios/ios/hid"
	"github.com/danielpaulus/go-ios/ios/installationproxy"
	"github.com/danielpaulus/go-ios/ios/instruments"
	"github.com/danielpaulus/go-ios/ios/tunnel"
	"github.com/google/uuid"
)

// setDuration changes a package budget for one test.
func setDuration(t *testing.T, v *time.Duration, d time.Duration) {
	t.Helper()
	old := *v
	*v = d
	t.Cleanup(func() { *v = old })
}

func tunnelDown() error { return errors.New("phone_tunnel_unreachable: dial timed out") }

// --- a dead tunnel and the gesture session ----------------------------------

// A /status probe whose handshake fails condemns the gesture session: the HID
// session rides that same tunnel, and its writes expect no reply, so reusing
// it answered {"ok":true} for taps that went nowhere. The next tap rebuilds,
// and fails with the tunnel's own reason.
func TestNoMuxFailedProbeCondemnsTheGestureSession(t *testing.T) {
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, fullRsd, testUDID)
	b := &bridge{ready: true}
	b.sawTunnel()
	h.err = tunnelDown()
	b.probe()
	if !b.stale.Load() {
		t.Fatal("the probe found the tunnel dead but left the gesture session live")
	}
	before, sent := h.calls, false
	err := b.withHID(func(*hid.Session) error { sent = true; return nil })
	if sent {
		t.Fatal("a tap was sent on the session the probe had found dead")
	}
	if err == nil || reasonOf(err) != "phone_tunnel_unreachable" {
		t.Fatalf("wanted phone_tunnel_unreachable, got %v", err)
	}
	if h.calls != before+1 {
		t.Fatalf("the tap must re-resolve once, got %d handshakes", h.calls-before)
	}
}

// A ready session whose tunnel has not answered within liveProofTTL is
// re-proved before a tap uses it, even when no /status poll came in between.
func TestNoMuxTapReprovesTheTunnelBeforeReusingASession(t *testing.T) {
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, fullRsd, testUDID)
	h.err = tunnelDown()
	dials := 0
	tunnelAlive = func(addr string, port int, timeout time.Duration) error {
		dials++
		if addr != noMuxAddr || port != noMuxRsd || timeout != liveCheckTimeout {
			t.Fatalf("liveness asked [%s]:%d within %s, not the pinned RSD port within %s", addr, port, timeout, liveCheckTimeout)
		}
		return errors.New("phone_tunnel_unreachable: no answer")
	}
	b := &bridge{ready: true}
	b.aliveAt.Store(time.Now().Add(-time.Minute).UnixNano())
	sent := false
	err := b.withHID(func(*hid.Session) error { sent = true; return nil })
	if sent {
		t.Fatal("a tap was sent into a tunnel that did not answer")
	}
	if err == nil || reasonOf(err) != "phone_tunnel_unreachable" {
		t.Fatalf("wanted phone_tunnel_unreachable, got %v", err)
	}
	if dials != 1 || h.calls != 1 {
		t.Fatalf("wanted one liveness connect and one re-resolve, got %d and %d", dials, h.calls)
	}
}

// A tunnel that answers keeps its session, and one connect proves it for
// liveProofTTL: three quick taps pay for one connect and no rebuild.
func TestNoMuxTapReusesASessionWhoseTunnelAnswers(t *testing.T) {
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, fullRsd, testUDID)
	dials := 0
	tunnelAlive = func(string, int, time.Duration) error { dials++; return nil }
	b := &bridge{ready: true}
	b.aliveAt.Store(time.Now().Add(-time.Minute).UnixNano())
	taps := 0
	for i := 0; i < 3; i++ {
		if err := b.withHID(func(*hid.Session) error { taps++; return nil }); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if taps != 3 || dials != 1 || h.calls != 0 || b.stale.Load() {
		t.Fatalf("wanted 3 taps, 1 connect, no handshake, no rebuild; got %d, %d, %d, stale=%v", taps, dials, h.calls, b.stale.Load())
	}
}

// The usbmux mode's gesture path is unchanged: it never runs the liveness test.
func TestUsbmuxTapNeverRunsTheTunnelLivenessTest(t *testing.T) {
	old := tunnelAlive
	t.Cleanup(func() { tunnelAlive = old })
	tunnelAlive = func(string, int, time.Duration) error {
		t.Fatal("usbmux mode ran the no-mux liveness test")
		return nil
	}
	b := &bridge{ready: true}
	taps := 0
	if err := b.withHID(func(*hid.Session) error { taps++; return nil }); err != nil || taps != 1 {
		t.Fatalf("wanted one tap on the ready session, got %d, %v", taps, err)
	}
}

// Rebuilding a condemned session stops its video stream first. Over a dead
// tunnel the phone never answers that stop, and it used to wait without a
// deadline while holding mu, so every later gesture queued behind it.
func TestTeardownBoundsTheStreamStop(t *testing.T) {
	oldStop := stopStream
	t.Cleanup(func() { stopStream = oldStop })
	setDuration(t, &streamStopTimeout, 100*time.Millisecond)
	bounded := false
	stopStream = func(ctx context.Context, _ *display.Service, _ uuid.UUID) {
		_, bounded = ctx.Deadline()
		select { // a phone that never answers; the test gives up at 3 s instead of hanging
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
		}
	}
	b := &bridge{svc: &display.Service{}, ready: true}
	start := time.Now()
	b.teardown()
	if !bounded || time.Since(start) > 2*time.Second {
		t.Fatalf("the stream stop was not bounded: deadline=%v took %s", bounded, time.Since(start))
	}
	if b.svc != nil || b.ready {
		t.Fatal("teardown left the session in place")
	}
}

// --- a dead tunnel and the read routes --------------------------------------

// A cached device is re-proved before a read uses it. A dead tunnel is then
// caught by one short connect instead of a service dial plus a re-handshake
// (about 21 s on the real road), the read never runs, and the gesture session
// riding that tunnel is condemned.
func TestNoMuxReadReprovesTheCachedTunnel(t *testing.T) {
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, fullRsd, testUDID)
	b := &bridge{ready: true}
	if _, err := b.device(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b.aliveAt.Store(time.Now().Add(-time.Minute).UnixNano())
	tunnelAlive = func(string, int, time.Duration) error { return errors.New("phone_tunnel_unreachable: no answer") }
	h.err = tunnelDown()
	ran := false
	err := b.withDevice(func(ios.DeviceEntry) error { ran = true; return nil })
	if ran {
		t.Fatal("the read ran on a tunnel that did not answer")
	}
	if err == nil || reasonOf(err) != "phone_tunnel_unreachable" {
		t.Fatalf("wanted phone_tunnel_unreachable, got %v", err)
	}
	if !b.stale.Load() || h.calls != 2 {
		t.Fatalf("wanted the session condemned after one re-resolve, got stale=%v handshakes=%d", b.stale.Load(), h.calls)
	}
}

// A fresh proof (a handshake, a started session, a connect) is trusted for
// liveProofTTL: a read right after one costs no connect.
func TestNoMuxReadTrustsAFreshProof(t *testing.T) {
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, fullRsd, testUDID)
	tunnelAlive = func(string, int, time.Duration) error {
		t.Fatal("a proof younger than liveProofTTL was checked again")
		return nil
	}
	b := &bridge{}
	for i := 0; i < 2; i++ {
		if err := b.withDevice(func(ios.DeviceEntry) error { return nil }); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if h.calls != 1 {
		t.Fatalf("wanted one handshake for two reads, got %d", h.calls)
	}
}

// The liveness test is a plain TCP connect: a listener answers it, a closed
// port fails it with the tunnel's reason, and neither waits for the bound.
func TestTunnelAliveIsATCPConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := tunnelAlive("127.0.0.1", ln.Addr().(*net.TCPAddr).Port, time.Second); err != nil {
		t.Fatalf("a listening port must count as alive: %v", err)
	}
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	start := time.Now()
	err = tunnelAlive("127.0.0.1", port, time.Second)
	if err == nil || reasonOf(err) != "phone_tunnel_unreachable" {
		t.Fatalf("wanted phone_tunnel_unreachable, got %v", err)
	}
	if time.Since(start) > 900*time.Millisecond {
		t.Fatalf("a refused connect took %s", time.Since(start))
	}
}

// The whole read and gesture routes against a real black hole, through the
// real liveness test, the real bounded dials and the real handshake, on the
// real budgets. It needs an address this Mac routes but nothing answers, named
// by COAGENT_PHONED_BLACKHOLE (the review used 10.255.255.1); it takes about
// 30 s, so it is not part of the default run.
func TestNoMuxBlackholedRoutesAnswerInsideTheDaemonBudget(t *testing.T) {
	hole := os.Getenv("COAGENT_PHONED_BLACKHOLE")
	if hole == "" {
		t.Skip("set COAGENT_PHONED_BLACKHOLE to a black-holed address to run")
	}
	const daemonBudget = 20 * time.Second
	realAlive := tunnelAlive
	pin := noMuxPin{addr: hole, rsd: 58783, udid: testUDID}
	noMuxMode(t, pin)
	tunnelAlive = realAlive
	t.Setenv("USBMUXD_SOCKET_ADDRESS", muxGuard)
	ios.SetTunnelDialTimeout(noMuxDialTimeout)
	t.Cleanup(func() { ios.SetTunnelDialTimeout(0) })
	d := entry(testUDID, 0, connNoMux)
	d.Address, d.Rsd = hole, fullRsd
	screenshot := func(d ios.DeviceEntry) error {
		ss, err := instruments.NewScreenshotService(d)
		if err != nil {
			return errors.New("phone_capture_failed: " + err.Error())
		}
		ss.Close()
		return nil
	}

	for name, fresh := range map[string]bool{"already dead": false, "died after the last proof": true} {
		b := &bridge{}
		cached(b, d)
		if fresh {
			b.sawTunnel()
		}
		start := time.Now()
		err := b.withDevice(screenshot)
		took := time.Since(start)
		t.Logf("read, %s: %v in %s", name, err, took.Round(100*time.Millisecond))
		if err == nil || reasonOf(err) != "phone_tunnel_unreachable" || took > daemonBudget-5*time.Second {
			t.Fatalf("read, %s: wanted phone_tunnel_unreachable well inside %s, got %v after %s", name, daemonBudget, err, took)
		}
	}

	b := &bridge{ready: true}
	b.aliveAt.Store(time.Now().Add(-time.Minute).UnixNano())
	start := time.Now()
	err := b.withHID(func(*hid.Session) error {
		t.Fatal("a tap was sent into the black hole")
		return nil
	})
	took := time.Since(start)
	t.Logf("tap: %v in %s", err, took.Round(100*time.Millisecond))
	if err == nil || reasonOf(err) != "phone_tunnel_unreachable" || took > daemonBudget-5*time.Second {
		t.Fatalf("tap: wanted phone_tunnel_unreachable well inside %s, got %v after %s", daemonBudget, err, took)
	}
}

// --- /apps inside one deadline ----------------------------------------------

// A listing that ran out of time is not retried: the address is pinned, so a
// retry asks the same slow tunnel again. Before, it was: two listings and two
// handshakes, about 36 s on the real limits against the daemon's 20 s.
func TestNoMuxAppsDoesNotRetryAListingThatRanOutOfTime(t *testing.T) {
	port, accepted := fakeAppsShim(t, shimWedgedList)
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, withShim(port), testUDID)
	setDuration(t, &shimListTimeout, 300*time.Millisecond)
	start := time.Now()
	_, err := (&bridge{}).apps()
	if err == nil || reasonOf(err) != reasonAppsFailed || !errors.Is(err, errAppsDeadline) {
		t.Fatalf("wanted %s (out of time), got %v", reasonAppsFailed, err)
	}
	if accepted.Load() != 1 || h.calls != 1 {
		t.Fatalf("wanted one listing and one handshake, got %d and %d", accepted.Load(), h.calls)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the request took %s", took)
	}
}

// One deadline covers the whole request, the handshake included: a slow
// handshake leaves the listing less time, and the listing is cut at appsBudget
// even though shimListTimeout alone would let it run on.
func TestNoMuxAppsFitsOneDeadline(t *testing.T) {
	port, _ := fakeAppsShim(t, shimWedgedList)
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, withShim(port), testUDID)
	inner := handshakeNoMux
	handshakeNoMux = func(info tunnel.Tunnel, d ios.DeviceEntry, timeout time.Duration) (ios.RsdPortProvider, string, error) {
		time.Sleep(200 * time.Millisecond)
		return inner(info, d, timeout)
	}
	setDuration(t, &appsBudget, 500*time.Millisecond)
	start := time.Now()
	_, err := (&bridge{}).apps()
	took := time.Since(start)
	if err == nil || !errors.Is(err, errAppsDeadline) {
		t.Fatalf("wanted the request's deadline, got %v", err)
	}
	if took < 450*time.Millisecond || took > 1500*time.Millisecond {
		t.Fatalf("wanted the request cut at its 500ms budget, took %s", took)
	}
}

// A failure that came fast (a dropped checkin) is retried once, inside the
// same deadline, against a freshly handshaken device.
func TestNoMuxAppsRetriesAFastFailureOnce(t *testing.T) {
	port, accepted := fakeAppsShim(t, shimFlakyOnce)
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, withShim(port), testUDID)
	out, err := (&bridge{}).apps()
	if err != nil || len(out) != 2 {
		t.Fatalf("wanted the retry to list both apps, got %v, %v", out, err)
	}
	if accepted.Load() != 2 || h.calls != 2 {
		t.Fatalf("wanted two checkins and two handshakes, got %d and %d", accepted.Load(), h.calls)
	}
}

// ... but not when a handshake, a checkin and a short listing no longer fit.
func TestNoMuxAppsSkipsARetryThatCannotFit(t *testing.T) {
	port, accepted := fakeAppsShim(t, shimFlakyOnce)
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, withShim(port), testUDID)
	setDuration(t, &appsBudget, time.Second)
	_, err := (&bridge{}).apps()
	if err == nil || reasonOf(err) != reasonAppsUnreadable {
		t.Fatalf("wanted the first failure, %s, got %v", reasonAppsUnreadable, err)
	}
	if accepted.Load() != 1 || h.calls != 1 {
		t.Fatalf("wanted no retry, got %d checkins and %d handshakes", accepted.Load(), h.calls)
	}
}

// A phone whose RSD does not list the shim would list the same services on a
// fresh handshake, so it is asked once.
func TestNoMuxAppsDoesNotRetryAMissingShim(t *testing.T) {
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, fullRsd, testUDID)
	_, err := (&bridge{}).apps()
	if err == nil || !errors.Is(err, errShimNotListed) || h.calls != 1 {
		t.Fatalf("wanted %s after one handshake, got %v after %d", causeAppsRemoteUnavailable, err, h.calls)
	}
}

// The listing asks the phone only for the keys appRow reads.
func TestNoMuxAppsAsksOnlyForTheKeysAppRowReads(t *testing.T) {
	port, _, browses := fakeAppsShimRecording(t, shimHealthy)
	noMuxMode(t, defaultPin())
	stubNoMuxHandshake(t, withShim(port), testUDID)
	if _, err := (&bridge{}).apps(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := make([]any, len(shimAttributes))
	for i, k := range shimAttributes {
		want[i] = k
	}
	for _, kind := range []string{"User", "System"} {
		req := <-browses
		opts, _ := req["ClientOptions"].(map[string]any)
		if opts["ApplicationType"] != kind || !reflect.DeepEqual(opts["ReturnAttributes"], want) {
			t.Fatalf("%s browse asked for %v, want %v", kind, opts["ReturnAttributes"], want)
		}
	}
}

// And those keys are enough: the row built from an app cut down to them is the
// row built from everything the phone knows about it.
func TestShimAttributesCoverAppRow(t *testing.T) {
	extra := map[string]any{
		"Path": "/Applications/X.app", "Container": "/private/var/mobile/Containers/Data/Application/1",
		"Entitlements": map[string]any{"application-identifier": "x"}, "CFBundleVersion": "1", "UIDeviceFamily": []any{1},
		"CFBundleExecutable": "X", "IsAppClip": false, "SignerIdentity": "Apple iPhone OS Application Signing",
	}
	for name, app := range map[string]map[string]any{
		"openable": {"CFBundleIdentifier": "com.apple.mobilemail", "CFBundleName": "MobileMail",
			"CFBundleDisplayName": "Mail", "ApplicationType": "System", "CFBundleIcons": map[string]any{}},
		"hidden": {"CFBundleIdentifier": "com.apple.MailCompositionService", "CFBundleName": "Mail",
			"ApplicationType": "System", "SBAppTags": []any{"hidden"}, "CFBundleIcons": map[string]any{}},
		"icon files only": {"CFBundleIdentifier": "com.example.old", "CFBundleName": "Old",
			"ApplicationType": "User", "CFBundleIconFiles": []any{"Icon.png"}},
		"no icons": {"CFBundleIdentifier": "com.apple.ext", "CFBundleName": "Ext", "ApplicationType": "System"},
	} {
		full, cut := installationproxy.AppInfo{}, installationproxy.AppInfo{}
		for k, v := range extra {
			full[k] = v
		}
		for k, v := range app {
			full[k] = v
		}
		for _, k := range shimAttributes {
			if v, ok := full[k]; ok {
				cut[k] = v
			}
		}
		if got, want := appRow(cut), appRow(full); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: the row needs a key the listing does not ask for:\n cut: %v\nfull: %v", name, got, want)
		}
	}
}

// --- words the installed daemon knows ---------------------------------------

// daemon0567Reasons is PHONE_REASONS in Co-Agent 0.5.67's
// daemon/src/phone-device-bridge.mjs, the daemon every no-mux answer goes to.
// It turns any reason missing from this list into phone_bridge_error, and it
// cannot be changed from this binary, so the list is frozen here.
var daemon0567Reasons = []string{
	"phone_control_disabled", "phone_bridge_offline", "phone_bridge_unauthorized", "phone_not_connected",
	"phone_tunnel_down", "phone_tunnel_unreachable", "phone_handshake_failed", "phone_device_failed",
	"phone_stream_receiver_failed", "phone_display_service_failed", "phone_stream_start_failed", "phone_hid_failed",
	"phone_capture_failed", "phone_touch_failed", "phone_launch_failed", "phone_apps_failed", "phone_point_invalid",
	"phone_bundle_invalid", "phone_app_unknown", "phone_app_ambiguous", "phone_text_unreadable", "phone_bridge_timeout",
	"phone_usbmuxd_unreachable", "phone_apps_unreadable", "phone_apps_unprobed", "phone_tunnel_env_invalid",
	"phone_no_transport", "phone_lan_gate_closed", "phone_tunnel_waiting", "phone_tunnel_lockdown_refused",
	"phone_tunnel_peer_down", "phone_tunnel_relay_refused", "phone_tunnel_build_refused",
	"phone_tunnel_relay_unreachable", "phone_tunnel_room_taken", "phone_tunnel_room_owned", "phone_tunnel_not_on_plan",
	"phone_tunnel_licence_missing", "phone_bridge_starting", "phone_bridge_error",
}

// noMuxReasons is every reason a no-mux route or /status can put first.
var noMuxReasons = []string{
	reasonDeviceFailed, reasonAppsUnreadable, reasonAppsFailed, reasonAppsUnprobed, reasonTunnelEnvInvalid,
	"phone_tunnel_unreachable", "phone_handshake_failed", "phone_capture_failed", "phone_launch_failed",
	"phone_hid_failed", "phone_touch_failed", "phone_stream_receiver_failed", "phone_display_service_failed",
	"phone_stream_start_failed", "phone_bridge_unauthorized", "phone_point_invalid", "phone_bundle_invalid",
	reasonBridgeError,
}

func TestNoMuxReasonsAreOnesTheInstalledDaemonKnows(t *testing.T) {
	known := map[string]bool{}
	for _, r := range daemon0567Reasons {
		known[r] = true
	}
	for _, r := range noMuxReasons {
		if !known[r] {
			t.Fatalf("%s would reach the user as phone_bridge_error: the installed daemon does not know it", r)
		}
	}
	for _, c := range []string{causeWrongDevice, causeAppsRemoteUnavailable, causeProbePanicked} {
		if known[c] {
			t.Fatalf("%s is a daemon reason now; report it as one", c)
		}
	}
}

// The frozen list against the daemon installed on this Mac, when there is one.
func TestDaemon0567ReasonsMatchTheInstalledDaemon(t *testing.T) {
	src, err := os.ReadFile("/Applications/Co-Agent.app/Contents/Resources/engine/daemon/src/phone-device-bridge.mjs")
	if err != nil {
		t.Skip("no installed Co-Agent daemon here")
	}
	for _, r := range noMuxReasons {
		if !strings.Contains(string(src), "'"+r+"'") {
			t.Fatalf("the installed daemon does not list %s", r)
		}
	}
}

// The two causes lead the detail under a known reason, where logs (and a later
// daemon) can still tell them apart.
func TestNoMuxCausesLeadTheDetail(t *testing.T) {
	noMuxMode(t, defaultPin())
	h := stubNoMuxHandshake(t, fullRsd, "00008150-0000000000000000")
	st := (&bridge{}).probe()
	if st.Reason != reasonDeviceFailed || !strings.HasPrefix(st.Detail, reasonDeviceFailed+": "+causeWrongDevice+": ") {
		t.Fatalf("wrong device: got %q / %q", st.Reason, st.Detail)
	}
	h.udid = testUDID
	st = (&bridge{}).probe()
	if st.Reason != reasonAppsUnreadable || !strings.HasPrefix(st.Detail, reasonAppsUnreadable+": "+causeAppsRemoteUnavailable+": ") {
		t.Fatalf("no shim: got %q / %q", st.Reason, st.Detail)
	}
}
