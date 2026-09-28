// Device-free tests for the coagent-phoned bridge.
//
// Every test here drives the code with fakes. NOTHING in this file may reach a
// real iPhone: the only phone this daemon has ever run against is the user's
// own, and a unit test must never tap, launch, screenshot or wake it. The two
// seams that touch hardware, listDevices and resolve, are package vars for
// exactly that reason; anything past them (video stream, HID session, DTX) is
// device-dependent and belongs in test/e2e per AGENTS.md.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/tunnel"
)

const testUDID = "00008150-000A1BCD0E2A401C"

// fakeRsd stands in for the RSD service table the tunnel handshake returns.
type fakeRsd map[string]int

func (f fakeRsd) GetPort(service string) int { return f[service] }

func (f fakeRsd) GetService(p int) string {
	for name, port := range f {
		if port == p {
			return name
		}
	}
	return ""
}

func (f fakeRsd) GetServices() map[string]ios.RsdServiceEntry {
	out := map[string]ios.RsdServiceEntry{}
	for name, port := range f {
		out[name] = ios.RsdServiceEntry{Port: uint32(port)}
	}
	return out
}

var fullRsd = fakeRsd{svcScreenshot: 51000, svcHID: 51001}

func entry(udid string, deviceID int, conn string) ios.DeviceEntry {
	return ios.DeviceEntry{
		DeviceID:   deviceID,
		Properties: ios.DeviceProperties{SerialNumber: udid, DeviceID: deviceID, ConnectionType: conn},
	}
}

func list(entries ...ios.DeviceEntry) ios.DeviceList { return ios.DeviceList{DeviceList: entries} }

// stub swaps the hardware seams for the duration of one test.
func stub(t *testing.T, ld func() (ios.DeviceList, error), rs func() (ios.DeviceEntry, error)) {
	t.Helper()
	oldList, oldResolve := listDevices, resolve
	if ld != nil {
		listDevices = ld
	}
	if rs != nil {
		resolve = rs
	}
	t.Cleanup(func() { listDevices, resolve = oldList, oldResolve })
}

// stubLockdown swaps the app-channel probe. The real one opens a lockdown
// session on the user's own iPhone, so no test may ever call it.
func stubLockdown(t *testing.T, fn func(ios.DeviceEntry) error) {
	t.Helper()
	old := probeLockdown
	probeLockdown = fn
	t.Cleanup(func() { probeLockdown = old })
}

// refusedLockdown is what the real probe returns when usbmuxd will not connect
// this DeviceID to lockdown. The inner sentence is go-ios's own text
// (ios/connect.go ConnectLockdown / ConnectLockdownWithSession); the wrapping is
// what main.go's probeLockdown does with it.
func refusedLockdown(ios.DeviceEntry) error {
	return fmt.Errorf("%s: %w", reasonAppsUnreadable,
		errors.New("Lockdown connection failed with: Failed connecting to Lockdown with error code:2"))
}

func stubApps(t *testing.T, fn func(ios.DeviceEntry) ([]map[string]any, error)) {
	t.Helper()
	old := listApps
	listApps = fn
	t.Cleanup(func() { listApps = old })
}

func cached(b *bridge, d ios.DeviceEntry) {
	b.devMu.Lock()
	b.devCopy, b.devReady = d, true
	b.devMu.Unlock()
}

func isCached(b *bridge) bool {
	b.devMu.RLock()
	defer b.devMu.RUnlock()
	return b.devReady
}

// --- pickDevice: the cable wins -------------------------------------------

func TestPickDevicePrefersUSBOverNetwork(t *testing.T) {
	got, err := pickDevice(list(entry(testUDID, 2, "Network"), entry(testUDID, 7, "USB")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.DeviceID != 7 {
		t.Fatalf("wanted the USB entry (DeviceID 7), got DeviceID %d (%s)", got.DeviceID, got.Properties.ConnectionType)
	}
}

func TestPickDeviceFallsBackWhenNothingIsOnUSB(t *testing.T) {
	got, err := pickDevice(list(entry(testUDID, 4, "Network")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.DeviceID != 4 {
		t.Fatalf("wanted the only entry, got DeviceID %d", got.DeviceID)
	}
}

func TestPickDeviceEmptyListIsNotConnected(t *testing.T) {
	_, err := pickDevice(list())
	if err == nil || reasonOf(err) != reasonNotConnected {
		t.Fatalf("wanted %s, got %v", reasonNotConnected, err)
	}
}

func TestMuxEntryReturnsCurrentDeviceID(t *testing.T) {
	got, found := muxEntry(list(entry("other", 1, "USB"), entry(testUDID, 9, "USB")), testUDID)
	if !found || got.DeviceID != 9 {
		t.Fatalf("wanted DeviceID 9 found, got %d found=%v", got.DeviceID, found)
	}
	if _, found := muxEntry(list(entry("other", 1, "USB")), testUDID); found {
		t.Fatal("matched a udid that is not in the list")
	}
}

// One phone, two rows: usbmuxd keeps a Network row alive next to the USB one.
// pickDevice and muxEntry disagreeing meant lockdown got one DeviceID while the
// tunnel got another, which is the incident's own mechanism.
func TestMuxEntryPrefersTheCableLikePickDevice(t *testing.T) {
	l := list(entry(testUDID, 12, "Network"), entry(testUDID, 11, "USB"))
	picked, err := pickDevice(l)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, found := muxEntry(l, testUDID)
	if !found {
		t.Fatal("did not find the phone at all")
	}
	if got.DeviceID != picked.DeviceID {
		t.Fatalf("two selectors, two devices: pickDevice -> %d (%s), muxEntry -> %d (%s)",
			picked.DeviceID, picked.Properties.ConnectionType, got.DeviceID, got.Properties.ConnectionType)
	}
	if got.Properties.ConnectionType != "USB" {
		t.Fatalf("the cable must win, got %s", got.Properties.ConnectionType)
	}
}

// --- the cache is never trusted blind --------------------------------------

func TestDeviceKeepsCacheWhenUsbmuxAgrees(t *testing.T) {
	resolved := 0
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil },
		func() (ios.DeviceEntry, error) { resolved++; return entry(testUDID, 3, "USB"), nil })
	b := &bridge{}
	cached(b, entry(testUDID, 3, "USB"))
	if _, err := b.device(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != 0 {
		t.Fatalf("re-resolved %d times when the cache was still valid", resolved)
	}
}

// The incident's mechanism: the phone re-attached, usbmuxd issued a new
// DeviceID, and the cached one made lockdown answer "error code:2" forever.
func TestDeviceDropsCacheWhenDeviceIDChanged(t *testing.T) {
	resolved := 0
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 11, "USB")), nil },
		func() (ios.DeviceEntry, error) { resolved++; return entry(testUDID, 11, "USB"), nil })
	b := &bridge{}
	cached(b, entry(testUDID, 3, "USB"))
	got, err := b.device()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != 1 {
		t.Fatalf("wanted exactly one re-resolve, got %d", resolved)
	}
	if got.DeviceID != 11 {
		t.Fatalf("still handing out the stale DeviceID %d", got.DeviceID)
	}
	if !b.stale.Load() {
		t.Fatal("gesture side was not told to rebuild")
	}
}

func TestDeviceDropsCacheWhenPhoneIsGone(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(), nil },
		func() (ios.DeviceEntry, error) { return ios.DeviceEntry{}, errors.New(reasonNotConnected) })
	b := &bridge{}
	cached(b, entry(testUDID, 3, "USB"))
	if _, err := b.device(); err == nil || reasonOf(err) != reasonNotConnected {
		t.Fatalf("wanted %s, got %v", reasonNotConnected, err)
	}
	if isCached(b) {
		t.Fatal("kept a cache entry for a phone that is not attached")
	}
}

// usbmuxd not answering does not prove the phone is gone, and the tunnel routes
// may still work. Guessing "gone" here would be its own false claim.
func TestDeviceKeepsCacheWhenUsbmuxdItselfIsUnreachable(t *testing.T) {
	resolved := 0
	stub(t, func() (ios.DeviceList, error) { return ios.DeviceList{}, errors.New("socket refused") },
		func() (ios.DeviceEntry, error) { resolved++; return ios.DeviceEntry{}, errors.New("should not happen") })
	b := &bridge{}
	cached(b, entry(testUDID, 3, "USB"))
	got, err := b.device()
	if err != nil || got.DeviceID != 3 {
		t.Fatalf("wanted the cached device back, got %+v err=%v", got, err)
	}
	if resolved != 0 {
		t.Fatal("re-resolved on an inconclusive usbmuxd answer")
	}
}

// --- withDevice: no route may latch a dead device ---------------------------

func TestWithDeviceRetriesOnceAfterFailure(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 5, "USB")), nil },
		func() (ios.DeviceEntry, error) { return entry(testUDID, 5, "USB"), nil })
	b := &bridge{}
	calls := 0
	err := b.withDevice(func(ios.DeviceEntry) error {
		calls++
		if calls == 1 {
			return errors.New("phone_capture_failed: dtx gone")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retry should have succeeded, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("wanted exactly 2 attempts, got %d", calls)
	}
}

func TestWithDeviceGivesUpAfterTwoAttempts(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 5, "USB")), nil },
		func() (ios.DeviceEntry, error) { return entry(testUDID, 5, "USB"), nil })
	b := &bridge{}
	calls := 0
	err := b.withDevice(func(ios.DeviceEntry) error {
		calls++
		return errors.New("phone_capture_failed: dtx gone")
	})
	if err == nil || reasonOf(err) != "phone_capture_failed" {
		t.Fatalf("wanted phone_capture_failed, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("wanted exactly 2 attempts, got %d", calls)
	}
}

// "your iPhone is not connected" is better words than "capture failed", so when
// the re-resolve explains the failure, that explanation wins.
func TestWithDeviceReportsWhyTheReResolveFailed(t *testing.T) {
	first := true
	stub(t, func() (ios.DeviceList, error) {
		if first {
			first = false
			return list(entry(testUDID, 5, "USB")), nil
		}
		return list(), nil
	}, func() (ios.DeviceEntry, error) { return ios.DeviceEntry{}, errors.New(reasonNotConnected) })
	b := &bridge{}
	err := b.withDevice(func(ios.DeviceEntry) error { return errors.New("phone_capture_failed: dtx gone") })
	if err == nil || reasonOf(err) != reasonNotConnected {
		t.Fatalf("wanted %s, got %v", reasonNotConnected, err)
	}
}

// --- /apps takes the usbmux route, not the tunnel ---------------------------

func TestAppsDeviceUsesTheCurrentDeviceIDNotTheCachedOne(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 11, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			t.Fatal("/apps must not need the tunnel")
			return ios.DeviceEntry{}, nil
		})
	b := &bridge{}
	cached(b, entry(testUDID, 3, "USB"))
	got, err := b.appsDevice()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.DeviceID != 11 {
		t.Fatalf("handed lockdown the stale DeviceID %d", got.DeviceID)
	}
}

func TestAppsDeviceSaysNotConnectedWhenThePhoneIsAbsent(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(), nil }, nil)
	b := &bridge{}
	cached(b, entry(testUDID, 3, "USB"))
	_, err := b.appsDevice()
	if err == nil || reasonOf(err) != reasonNotConnected {
		t.Fatalf("wanted %s, got %v", reasonNotConnected, err)
	}
	if isCached(b) {
		t.Fatal("kept the cache for a phone that is not attached")
	}
}

func TestAppsDeviceDistinguishesABrokenUsbmuxd(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return ios.DeviceList{}, errors.New("socket refused") }, nil)
	b := &bridge{}
	_, err := b.appsDevice()
	if err == nil || reasonOf(err) != reasonMuxUnreachable {
		t.Fatalf("wanted %s, got %v", reasonMuxUnreachable, err)
	}
}

// The three app-list failures the user hears different sentences for.
func TestAppsReasonsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range []string{reasonNotConnected, reasonMuxUnreachable, reasonAppsUnreadable, reasonAppsFailed} {
		if seen[r] {
			t.Fatalf("reason %q is used for two different states", r)
		}
		seen[r] = true
	}
}

// --- a failed operation must not condemn the gesture session ---------------

// R4: the HID session and the video stream cost 600 ms + a 15 s StartVideoStream
// to rebuild. One transient DTX failure on a phone that has not moved is not
// evidence that they died, so the next tap must not pay for it.
func TestTransientCaptureFailureLeavesTheGestureSessionAlone(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 5, "USB")), nil },
		func() (ios.DeviceEntry, error) { return entry(testUDID, 5, "USB"), nil })
	b := &bridge{ready: true}
	calls := 0
	err := b.withDevice(func(ios.DeviceEntry) error {
		calls++
		if calls == 1 {
			return errors.New("phone_capture_failed: dtx hiccup")
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("wanted a successful retry, got err=%v calls=%d", err, calls)
	}
	if b.stale.Load() {
		t.Fatal("one transient screenshot failure condemned the gesture session")
	}
}

// The failure that DOES condemn it: the phone re-attached, so the session was
// built on a device that no longer exists.
func TestCaptureFailureOnAReattachedPhoneCondemnsTheSession(t *testing.T) {
	cur := entry(testUDID, 5, "USB")
	stub(t, func() (ios.DeviceList, error) { return list(cur), nil },
		func() (ios.DeviceEntry, error) { return cur, nil })
	b := &bridge{ready: true}
	first := true
	err := b.withDevice(func(ios.DeviceEntry) error {
		if first {
			first = false
			cur = entry(testUDID, 12, "USB") // re-attached under a new DeviceID
			return errors.New("phone_capture_failed: dtx gone")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !b.stale.Load() {
		t.Fatal("the session was built on a device that is gone and was not condemned")
	}
}

func TestUnreachablePhoneCondemnsTheSession(t *testing.T) {
	first := true
	stub(t, func() (ios.DeviceList, error) {
		if first {
			first = false
			return list(entry(testUDID, 5, "USB")), nil
		}
		return list(), nil
	}, func() (ios.DeviceEntry, error) { return ios.DeviceEntry{}, errors.New(reasonNotConnected) })
	b := &bridge{ready: true}
	cached(b, entry(testUDID, 5, "USB"))
	if err := b.withDevice(func(ios.DeviceEntry) error { return errors.New("phone_capture_failed: x") }); err == nil {
		t.Fatal("wanted the re-resolve failure")
	}
	if !b.stale.Load() {
		t.Fatal("phone is gone; the gesture session must be condemned")
	}
}

// A locked phone answers usbmux but not the app list. That is a fact about one
// channel, and it must not close the HID session.
func TestAppListFailureLeavesTheGestureSessionAlone(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 5, "USB")), nil }, nil)
	tries := 0
	stubApps(t, func(ios.DeviceEntry) ([]map[string]any, error) {
		tries++
		if tries == 1 {
			return nil, fmt.Errorf("%s: device is passcode protected", reasonAppsUnreadable)
		}
		return []map[string]any{{"bundleId": "com.apple.mobilemail"}}, nil
	})
	b := &bridge{ready: true}
	cached(b, entry(testUDID, 5, "USB"))
	out, err := b.apps()
	if err != nil || len(out) != 1 {
		t.Fatalf("wanted the retry to succeed, got %v / %d rows", err, len(out))
	}
	if tries != 2 {
		t.Fatalf("wanted exactly one retry, got %d attempts", tries)
	}
	if b.stale.Load() {
		t.Fatal("a failed app listing condemned the gesture session")
	}
}

// --- /status is a probe, not a latch ---------------------------------------

// R1, the real incident world: the phone IS on the bus (under a new DeviceID),
// the tunnel is healthy with both RSD services, and lockdown refuses with error
// code:2. Presence alone answered {ok:true,see:true,act:true,apps:true} here.
func TestProbeWillNotClaimAppsFromBusPresenceAlone(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 12, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			d := entry(testUDID, 12, "USB")
			d.Rsd = fullRsd
			return d, nil
		})
	stubLockdown(t, refusedLockdown)
	st := (&bridge{}).probe()
	if !st.See.up() || !st.Act.up() {
		t.Fatalf("the tunnel was fine; got see=%+v act=%+v", st.See, st.Act)
	}
	if st.Apps.State != capDown || st.Apps.Reason != reasonAppsUnreadable {
		t.Fatalf("lockdown refused; wanted apps down/%s, got %+v", reasonAppsUnreadable, st.Apps)
	}
	if st.OK || st.Reason != reasonAppsUnreadable {
		t.Fatalf("wanted ok=false reason=%s, got %+v", reasonAppsUnreadable, st)
	}
}

// apps:up is only ever "I opened the lockdown channel and the phone answered".
func TestProbeAllGreenProvesAppsByOpeningLockdown(t *testing.T) {
	opened := 0
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			d := entry(testUDID, 3, "USB")
			d.Rsd = fullRsd
			return d, nil
		})
	stubLockdown(t, func(d ios.DeviceEntry) error {
		opened++
		if d.DeviceID != 3 {
			t.Fatalf("probed a device the app list would not use: %d", d.DeviceID)
		}
		return nil
	})
	st := (&bridge{}).probe()
	if !st.OK || !st.See.up() || !st.Act.up() || !st.Apps.up() {
		t.Fatalf("wanted every capability up, got %+v", st)
	}
	if opened != 1 {
		t.Fatalf("wanted exactly one lockdown open, got %d", opened)
	}
	if st.Apps.Proof != proofLockdown || st.See.Proof != proofRSD {
		t.Fatalf("a capability claimed up without saying what proved it: %+v", st)
	}
	if st.Reason != "" || st.Detail != "" {
		t.Fatalf("a healthy probe must carry no reason, got %+v", st)
	}
}

// Tunnel fine, phone not on the bus at all.
func TestProbeReportsAppsDownWhenThePhoneIsAbsent(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(), nil }, func() (ios.DeviceEntry, error) {
		d := entry(testUDID, 3, "USB")
		d.Rsd = fullRsd
		return d, nil
	})
	stubLockdown(t, func(ios.DeviceEntry) error {
		t.Fatal("opened lockdown for a phone that is not on the bus")
		return nil
	})
	st := (&bridge{}).probe()
	if !st.See.up() || !st.Act.up() {
		t.Fatalf("tunnel was fine; got see=%+v act=%+v", st.See, st.Act)
	}
	if st.Apps.State != capDown || st.Apps.Reason != reasonNotConnected || st.OK {
		t.Fatalf("wanted apps down/%s and ok=false, got %+v", reasonNotConnected, st)
	}
}

// The mirror image: phone on the bus and answering lockdown, tunnel down.
func TestProbeReportsTunnelDeadWhileAppsWork(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil },
		func() (ios.DeviceEntry, error) { return ios.DeviceEntry{}, errors.New("phone_tunnel_down: no tunnel") })
	stubLockdown(t, func(ios.DeviceEntry) error { return nil })
	st := (&bridge{}).probe()
	if !st.Apps.up() {
		t.Fatalf("lockdown answered; apps must be up, got %+v", st.Apps)
	}
	if st.See.up() || st.Act.up() || st.OK {
		t.Fatalf("tunnel is down; got %+v", st)
	}
	if st.See.Reason != "phone_tunnel_down" || st.Reason != "phone_tunnel_down" {
		t.Fatalf("wanted phone_tunnel_down, got %+v", st)
	}
	if st.UDID != testUDID {
		t.Fatalf("lost the udid when the tunnel was down: %q", st.UDID)
	}
}

// A mounted-but-outdated developer image drops the HID service from RSD: you can
// still see the phone and cannot touch it. That must not read as "all good".
func TestProbeSeparatesSeeFromAct(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			d := entry(testUDID, 3, "USB")
			d.Rsd = fakeRsd{svcScreenshot: 51000}
			return d, nil
		})
	stubLockdown(t, func(ios.DeviceEntry) error { return nil })
	st := (&bridge{}).probe()
	if !st.See.up() || st.Act.up() || st.OK {
		t.Fatalf("wanted see up, act down, ok false, got %+v", st)
	}
	if st.Act.Reason != "phone_hid_failed" {
		t.Fatalf("wanted act=phone_hid_failed, got %+v", st.Act)
	}
}

// usbmuxd is the only road to installationproxy, so its absence is a certain no.
func TestProbeReportsAppsDownWhenUsbmuxdIsUnreachable(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return ios.DeviceList{}, errors.New("socket refused") },
		func() (ios.DeviceEntry, error) { return ios.DeviceEntry{}, errors.New("phone_tunnel_down: no tunnel") })
	st := (&bridge{}).probe()
	if st.Apps.State != capDown || st.Apps.Reason != reasonMuxUnreachable {
		t.Fatalf("wanted apps down/%s, got %+v", reasonMuxUnreachable, st.Apps)
	}
}

// If the probe is switched off, nothing has been established — so "unknown",
// never "up", and never ok.
func TestProbeSaysUnknownRatherThanTrueWhenTheProbeIsOff(t *testing.T) {
	t.Setenv(envAppsProbe, "off")
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			d := entry(testUDID, 3, "USB")
			d.Rsd = fullRsd
			return d, nil
		})
	stubLockdown(t, func(ios.DeviceEntry) error {
		t.Fatal("opened lockdown although the probe is off")
		return nil
	})
	st := (&bridge{}).probe()
	if st.Apps.State != capUnknown || st.Apps.Reason != reasonAppsUnprobed {
		t.Fatalf("wanted apps unknown/%s, got %+v", reasonAppsUnprobed, st.Apps)
	}
	if st.OK {
		t.Fatal("unknown is not ok: a caller reading only ok must fail closed")
	}
}

// Cheap: a watchdog polling /status must not open a lockdown session per poll.
func TestProbeCachesTheLockdownAnswerBriefly(t *testing.T) {
	opened := 0
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			d := entry(testUDID, 3, "USB")
			d.Rsd = fullRsd
			return d, nil
		})
	stubLockdown(t, func(ios.DeviceEntry) error { opened++; return nil })
	b := &bridge{}
	b.probe()
	b.probe()
	if opened != 1 {
		t.Fatalf("wanted the second poll to reuse the answer, got %d opens", opened)
	}
	old := appsProbeTTL
	appsProbeTTL = time.Nanosecond
	t.Cleanup(func() { appsProbeTTL = old })
	if st := b.probe(); opened != 2 || !st.Apps.up() {
		t.Fatalf("wanted a fresh open once the answer aged out, got %d opens / %+v", opened, st.Apps)
	}
}

// A re-attach retires the cached answer: a new DeviceID is a new question.
func TestProbeReprobesAfterAReattach(t *testing.T) {
	cur := entry(testUDID, 3, "USB")
	opened := []int{}
	stub(t, func() (ios.DeviceList, error) { return list(cur), nil },
		func() (ios.DeviceEntry, error) {
			d := cur
			d.Rsd = fullRsd
			return d, nil
		})
	stubLockdown(t, func(d ios.DeviceEntry) error { opened = append(opened, d.DeviceID); return nil })
	b := &bridge{}
	b.probe()
	cur = entry(testUDID, 12, "USB")
	b.probe()
	if len(opened) != 2 || opened[1] != 12 {
		t.Fatalf("wanted a second probe against DeviceID 12, got %v", opened)
	}
}

// A real /apps answer is better evidence than any probe, so /status uses it.
func TestStatusUsesARealAppListingAsProof(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			d := entry(testUDID, 3, "USB")
			d.Rsd = fullRsd
			return d, nil
		})
	stubApps(t, func(ios.DeviceEntry) ([]map[string]any, error) { return []map[string]any{}, nil })
	stubLockdown(t, func(ios.DeviceEntry) error {
		t.Fatal("re-probed lockdown although /apps had just answered")
		return nil
	})
	b := &bridge{}
	if _, err := b.apps(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	st := b.probe()
	if !st.Apps.up() || st.Apps.Proof != proofListed {
		t.Fatalf("wanted apps up proven by the listing, got %+v", st.Apps)
	}
}

// And a listing that just failed is what /status must say, without asking again.
func TestStatusReportsAFailedAppListing(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			d := entry(testUDID, 3, "USB")
			d.Rsd = fullRsd
			return d, nil
		})
	stubApps(t, func(ios.DeviceEntry) ([]map[string]any, error) {
		return nil, fmt.Errorf("%s: browse failed", reasonAppsFailed)
	})
	stubLockdown(t, func(ios.DeviceEntry) error { return nil })
	b := &bridge{}
	if _, err := b.apps(); err == nil {
		t.Fatal("wanted the listing to fail")
	}
	st := b.probe()
	if st.Apps.State != capDown || st.Apps.Reason != reasonAppsFailed || st.OK {
		t.Fatalf("wanted apps down/%s and ok=false, got %+v", reasonAppsFailed, st)
	}
}

// probe() must not build the gesture session: it never calls ensure(), so no
// video stream and no HID session are started by a status poll. (The seams it
// does use are resolve() and probeLockdown(), both stubbed here; what those do
// on real hardware is documented at their definitions and covered in test/e2e.)
func TestProbeNeverCallsEnsure(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			d := entry(testUDID, 3, "USB")
			d.Rsd = fullRsd
			return d, nil
		})
	stubLockdown(t, func(ios.DeviceEntry) error { return nil })
	b := &bridge{}
	b.probe()
	if b.ready || b.hid != nil || b.svc != nil || b.recv != nil {
		t.Fatal("probe started a session on the phone")
	}
}

// A status poll is an observer. A dead tunnel is reported, not acted on: the
// user's next tap must not pay a rebuild because a watchdog asked a question.
// (The one thing a probe may still condemn is a session whose device has left
// the bus entirely — that session is gone whatever anyone polls.)
func TestProbeDoesNotCondemnTheGestureSessionWhenTheTunnelIsDown(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil },
		func() (ios.DeviceEntry, error) { return ios.DeviceEntry{}, errors.New("phone_tunnel_down: no tunnel") })
	stubLockdown(t, func(ios.DeviceEntry) error { return nil })
	b := &bridge{ready: true}
	b.probe()
	if b.stale.Load() {
		t.Fatal("a /status poll condemned the gesture session")
	}
}

// --- ensure honours the stale flag the read path sets -----------------------

func TestEnsureShortCircuitsWhenReadyAndFresh(t *testing.T) {
	stub(t, nil, func() (ios.DeviceEntry, error) {
		t.Fatal("ensure rebuilt a healthy session")
		return ios.DeviceEntry{}, nil
	})
	b := &bridge{ready: true}
	if err := b.ensure(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnsureRebuildsWhenTheReadPathMarkedItStale(t *testing.T) {
	stub(t, nil, func() (ios.DeviceEntry, error) { return ios.DeviceEntry{}, errors.New(reasonNotConnected) })
	b := &bridge{ready: true}
	b.stale.Store(true)
	if err := b.ensure(); err == nil || reasonOf(err) != reasonNotConnected {
		t.Fatalf("stale session was not rebuilt: %v", err)
	}
	if b.ready {
		t.Fatal("ready latched on after a failed rebuild")
	}
}

func TestReasonOfSplitsOnTheFirstColon(t *testing.T) {
	if got := reasonOf(errors.New("phone_apps_unreadable: Failed connecting to Lockdown with error code:2")); got != reasonAppsUnreadable {
		t.Fatalf("got %q", got)
	}
	if got := reasonOf(errors.New(reasonNotConnected)); got != reasonNotConnected {
		t.Fatalf("got %q", got)
	}
}

// --- evidence -------------------------------------------------------------

// The exact bytes /status puts on the wire for the world of 2026-09-19: the
// phone present on the usbmux bus under a NEW DeviceID, the tunnel healthy with
// both RSD services, and lockdown refusing with error code:2 so /apps is dead.
//
// There is no hand-written "old" line here. The previous handler is not in this
// tree any more, and a string typed by an author is not evidence of what a
// binary printed; what the old shape was is recorded in main.go's header.
func TestStatusBytesForTheIncidentState(t *testing.T) {
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 12, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			d := entry(testUDID, 12, "USB")
			d.Rsd = fullRsd
			return d, nil
		})
	stubLockdown(t, refusedLockdown)
	raw, err := json.Marshal((&bridge{}).probe())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("/status in the incident state: %s", raw)
	want := `{"ok":false,"udid":"` + testUDID + `",` +
		`"see":{"state":"up","proof":"rsd_service_table"},` +
		`"act":{"state":"up","proof":"rsd_service_table"},` +
		`"apps":{"state":"down","proof":"lockdown_session","reason":"phone_apps_unreadable",` +
		`"detail":"phone_apps_unreadable: Lockdown connection failed with: Failed connecting to Lockdown with error code:2"},` +
		`"reason":"phone_apps_unreadable",` +
		`"detail":"phone_apps_unreadable: Lockdown connection failed with: Failed connecting to Lockdown with error code:2"}`
	if string(raw) != want {
		t.Fatalf("status body changed shape\n got: %s\nwant: %s", raw, want)
	}
}

// --- resolveDevice must use the ONE selector, through the stubbable seam ----

// tunnelEnv makes resolveDevice take the COAGENT_PHONE_ADDR branch, so it never
// looks for a real tunnel, and stubHandshake replaces the one remaining call
// that would reach the phone. Together they let a test run the REAL
// resolveDevice — which is the only way to see which entry it actually caches.
func tunnelEnv(t *testing.T) {
	t.Helper()
	t.Setenv("COAGENT_PHONE_ADDR", "fd00::1")
	t.Setenv("COAGENT_PHONE_RSD", "50000")
}

func stubHandshake(t *testing.T, p ios.RsdPortProvider, err error) {
	t.Helper()
	old := handshake
	handshake = func(tunnel.Tunnel, ios.DeviceEntry, time.Duration) (ios.RsdPortProvider, error) { return p, err }
	t.Cleanup(func() { handshake = old })
}

// The test TestMuxEntryPrefersTheCableLikePickDevice should have been: it asked
// whether muxEntry agrees with pickDevice, but never asked what resolveDevice
// CACHES — and cacheLive compares the cached entry against muxEntry. One phone,
// two usbmux rows, the stale Network row listed first: if resolveDevice answers
// with anything other than the row muxEntry picks, then device() caches an entry
// that cacheLive immediately rejects, and every successful call invalidates the
// gesture session.
func TestResolveDeviceAnswersWithTheEntryCacheLiveAccepts(t *testing.T) {
	tunnelEnv(t)
	stub(t, func() (ios.DeviceList, error) {
		return list(entry(testUDID, 12, "Network"), entry(testUDID, 11, "USB")), nil
	}, nil)
	stubHandshake(t, fullRsd, nil)

	d, err := resolveDevice()
	if err != nil {
		t.Fatalf("resolveDevice failed with both seams stubbed, so it reached past them: %v", err)
	}
	if d.Properties.ConnectionType != "USB" || d.DeviceID != 11 {
		t.Fatalf("resolveDevice must apply the cable-wins rule: got DeviceID %d (%s), wanted 11 (USB)",
			d.DeviceID, d.Properties.ConnectionType)
	}
	if !cacheLive(d) {
		t.Fatal("resolveDevice answered with an entry cacheLive rejects: two selectors, two devices")
	}
	if d.Address != "fd00::1" {
		t.Fatalf("the tunnel address was dropped: %q", d.Address)
	}
	if d.Rsd == nil || d.Rsd.GetPort(svcHID) != fullRsd[svcHID] {
		t.Fatal("the handshaken RSD table was dropped")
	}
}

// The consequence, end to end and through the real resolve: a cache filled by a
// successful resolve must survive the very next cacheLive check. Before the fix
// this condemned the gesture session on every single successful call.
func TestASuccessfulResolveDoesNotCondemnTheGestureSession(t *testing.T) {
	tunnelEnv(t)
	stub(t, func() (ios.DeviceList, error) {
		return list(entry(testUDID, 12, "Network"), entry(testUDID, 11, "USB")), nil
	}, nil) // resolve stays REAL: the defect lives inside it
	stubHandshake(t, fullRsd, nil)

	b := &bridge{}
	first, err := b.device()
	if err != nil {
		t.Fatalf("first device() failed: %v", err)
	}
	second, err := b.device()
	if err != nil {
		t.Fatalf("second device() failed: %v", err)
	}
	if first.DeviceID != second.DeviceID {
		t.Fatalf("the cache was thrown away between two identical calls: %d then %d", first.DeviceID, second.DeviceID)
	}
	if b.stale.Load() {
		t.Fatal("a successful call condemned the gesture session")
	}
	if !isCached(b) {
		t.Fatal("the device selection was dropped after a successful call")
	}
}

// resolveDevice must also refuse to invent a device when the phone left the bus
// between the first listing and the re-selection after the handshake.
func TestResolveDeviceSaysNotConnectedWhenThePhoneLeavesMidHandshake(t *testing.T) {
	tunnelEnv(t)
	calls := 0
	stub(t, func() (ios.DeviceList, error) {
		calls++
		if calls == 1 {
			return list(entry(testUDID, 11, "USB")), nil
		}
		return list(), nil
	}, nil)
	stubHandshake(t, fullRsd, nil)

	_, err := resolveDevice()
	if err == nil || reasonOf(err) != reasonNotConnected {
		t.Fatalf("wanted %s, got %v", reasonNotConnected, err)
	}
}

// --- B3: the probe switch must not discard proof already in hand ------------

// COAGENT_PHONE_APPS_PROBE=off means "do not OPEN the lockdown channel". It was
// read before the remembered answer, so an /apps listing that had just answered
// — the strongest evidence there is — was thrown away and apps was pinned
// unknown/unprobed forever. The switch bounds what the probe does; it does not
// un-happen what the phone already said.
func TestProbeOffStillReportsAnAppListingThatJustAnswered(t *testing.T) {
	t.Setenv(envAppsProbe, "off")
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			d := entry(testUDID, 3, "USB")
			d.Rsd = fullRsd
			return d, nil
		})
	stubApps(t, func(ios.DeviceEntry) ([]map[string]any, error) { return []map[string]any{}, nil })
	stubLockdown(t, func(ios.DeviceEntry) error {
		t.Fatal("opened lockdown although the probe is off")
		return nil
	})
	b := &bridge{}
	if _, err := b.apps(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	st := b.probe()
	if !st.Apps.up() || st.Apps.Proof != proofListed {
		t.Fatalf("a listing that just succeeded was discarded: got %+v", st.Apps)
	}
	if !st.OK {
		t.Fatalf("all three are proven up, yet ok=false: %+v", st)
	}
}

// The same in the other direction: a listing that JUST FAILED is the truth
// /status must report, probe switch or not.
func TestProbeOffStillReportsAnAppListingThatJustFailed(t *testing.T) {
	t.Setenv(envAppsProbe, "off")
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			d := entry(testUDID, 3, "USB")
			d.Rsd = fullRsd
			return d, nil
		})
	stubApps(t, func(ios.DeviceEntry) ([]map[string]any, error) {
		return nil, fmt.Errorf("%s: browse failed", reasonAppsFailed)
	})
	stubLockdown(t, func(ios.DeviceEntry) error {
		t.Fatal("opened lockdown although the probe is off")
		return nil
	})
	b := &bridge{}
	if _, err := b.apps(); err == nil {
		t.Fatal("wanted the listing to fail")
	}
	st := b.probe()
	if st.Apps.State != capDown || st.Apps.Reason != reasonAppsFailed {
		t.Fatalf("a failure that just happened was reported as %+v", st.Apps)
	}
}

// And with nothing established, off still means unknown — never up.
func TestProbeOffWithNoAnswerInHandStaysUnprobed(t *testing.T) {
	t.Setenv(envAppsProbe, "off")
	stub(t, func() (ios.DeviceList, error) { return list(entry(testUDID, 3, "USB")), nil },
		func() (ios.DeviceEntry, error) {
			d := entry(testUDID, 3, "USB")
			d.Rsd = fullRsd
			return d, nil
		})
	stubLockdown(t, func(ios.DeviceEntry) error {
		t.Fatal("opened lockdown although the probe is off")
		return nil
	})
	st := (&bridge{}).probe()
	if st.Apps.State != capUnknown || st.Apps.Reason != reasonAppsUnprobed || st.OK {
		t.Fatalf("wanted apps unknown/%s and ok=false, got %+v", reasonAppsUnprobed, st)
	}
}

// A replugged phone gets a new tunnel address. The bridge must follow it rather
// than keep dialling the one pinned in its environment at launch.
func TestChooseTunnelPrefersTheLiveAnswerOverThePinnedOne(t *testing.T) {
	live := tunnel.Tunnel{Address: "fd00::new", RsdPort: 61000, Udid: "U"}
	got, err := chooseTunnel("U", live, nil, "fd00::stale", "50809")
	if err != nil || got.Address != "fd00::new" || got.RsdPort != 61000 {
		t.Fatalf("a live tunnel lost to the pinned one: %+v %v", got, err)
	}
}

func TestChooseTunnelFallsBackToThePinnedAddressWhenTheInfoServiceIsDead(t *testing.T) {
	got, err := chooseTunnel("U", tunnel.Tunnel{}, fmt.Errorf("connection refused"), "fd00::pinned", "50809")
	if err != nil || got.Address != "fd00::pinned" || got.RsdPort != 50809 || got.Udid != "U" {
		t.Fatalf("the pinned fallback was not used: %+v %v", got, err)
	}
	if _, err := chooseTunnel("U", tunnel.Tunnel{}, fmt.Errorf("refused"), "fd00::pinned", "not-a-port"); err == nil || err.Error() != "phone_tunnel_env_invalid" {
		t.Fatalf("a bad pinned port must be named, got %v", err)
	}
	if _, err := chooseTunnel("U", tunnel.Tunnel{}, fmt.Errorf("refused"), "", ""); err == nil {
		t.Fatalf("no live tunnel and nothing pinned must be an error")
	}
	// An info service that answers with an EMPTY tunnel is not an answer.
	got, err = chooseTunnel("U", tunnel.Tunnel{}, nil, "fd00::pinned", "50809")
	if err != nil || got.Address != "fd00::pinned" {
		t.Fatalf("an empty live answer beat the pinned address: %+v %v", got, err)
	}
}

// The live tunnel lookup must ask the go-ios agent that `ios tunnel start`
// actually runs (60105 by default), never the retired 28100: asking a port
// nobody listens on made every lookup fail, so the bridge stayed pinned to a
// Wi-Fi tunnel address that had long since been replaced (2026-09-28).
func TestTunnelAgentIsTheGoIosAgentAPI(t *testing.T) {
	t.Setenv("GO_IOS_AGENT_HOST", "")
	t.Setenv("GO_IOS_AGENT_PORT", "")
	host, port := tunnelAgent()
	if host != "127.0.0.1" || port != 60105 {
		t.Fatalf("tunnelAgent() = %s:%d, want 127.0.0.1:60105", host, port)
	}
	t.Setenv("GO_IOS_AGENT_PORT", "60200")
	if _, port := tunnelAgent(); port != 60200 {
		t.Fatalf("GO_IOS_AGENT_PORT ignored: got %d", port)
	}
}

func TestLaunchReasonNamesALockedPhone(t *testing.T) {
	locked := errors.New("Request to launch com.apple.mobilemail failed. Unable to launch com.apple.mobilemail because the device was not, or could not be, unlocked. (FBSOpenApplicationErrorDomain error 7 Locked)")
	if got := launchReason(locked); got != "phone_locked" {
		t.Fatalf("locked launch: got %q, want phone_locked", got)
	}
	if got := launchReason(errors.New("no app with bundle id com.example.gone")); got != "phone_launch_failed" {
		t.Fatalf("other launch failure: got %q, want phone_launch_failed", got)
	}
	if got := reasonOf(fmt.Errorf("%s: %w", launchReason(locked), locked)); got != "phone_locked" {
		t.Fatalf("reasonOf: got %q, want phone_locked", got)
	}
}
