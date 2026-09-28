// coagent-phoned: resident see/act bridge to one iPhone over CoreDevice (iOS 27+).
// Loopback HTTP only, bearer token required. Fails closed: every error is a
// specific reason string, never a silent success and never another route.
//
// Two transports reach the phone and they fail independently:
//
//	tunnel (RSD/DTX)  -> /screenshot, /launch, /tap, /swipe
//	usbmux + lockdown -> /apps
//
// On 2026-09-19 the second was dead while the first was fine, and /status still
// answered {ok:true, see:true, act:true} because it only proved the tunnel. The
// user asked to open Mail on his phone and got "I was unable to". So /status is
// now a probe that reports the three capabilities separately, and no route is
// allowed to latch a device that has stopped answering.
//
// Each capability says what actually established it. "apps" is NOT presence on
// the usbmux bus: on 2026-09-19 the phone was present under a new DeviceID and
// lockdown refused every connect with error code:2, so presence would still
// have sworn everything was fine. It means "I opened the lockdown channel
// installationproxy opens first and the phone answered", or else down/unknown.
//
// # No-mux mode (the relay tunnel road)
//
// On the relay tunnel road there is no usbmux row for the phone at all: the
// phone is reached only through a CoreDevice tunnel that coagent-rppair holds
// open, and lockdown on the phone's relay address always resets. With
// COAGENT_PHONE_NO_MUX=1 (plus COAGENT_PHONE_ADDR, COAGENT_PHONE_RSD and,
// optionally, COAGENT_PHONE_UDID) this binary runs with no usbmux dependency:
//
//	tunnel (RSD/DTX)                     -> /screenshot, /launch, /tap, /swipe
//	tunnel (installation_proxy RSD shim) -> /apps
//
// The device is resolved from the pinned tunnel address and an RSD handshake
// alone; the UDID is the one the handshake reports, checked against
// COAGENT_PHONE_UDID when that is set. usbmuxd and the go-ios tunnel agent
// (tunnelAgent) are never asked. The switch is read once in main(), never at call
// time, so a developer shell with it exported cannot flip the unit tests.
// The /status wire shape is the same in both modes.
//
// Over the relay the tunnel can die while its utun stays up ("black-holed"),
// so in no-mux mode every route is bounded as a whole to fit the daemon's
// 20 s (see the budgets), a cached device or a ready gesture session is reused
// only after the tunnel is shown to answer, and a failed /status handshake
// condemns the gesture session. Reasons the installed daemon does not know are
// reported under the nearest one it does, with the precise cause in the detail
// (see the causes).
//
// # One contact at a time with the RSD port
//
// The phone resets an RSD handshake in flight when a second connection reaches
// its RSD port (measured 2026-09-23, both roads). Every contact this process
// makes with that port is serialised per tunnel, concurrent /status calls share
// one probe, and a reset handshake is retried once: see rsdgate.go.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/display"
	"github.com/danielpaulus/go-ios/ios/hid"
	"github.com/danielpaulus/go-ios/ios/installationproxy"
	"github.com/danielpaulus/go-ios/ios/instruments"
	"github.com/danielpaulus/go-ios/ios/tunnel"
	"github.com/google/uuid"
)

// RSD service names. Presence of a port for these in the handshake table is what
// "see" and "act" actually depend on. Reading the table is a map lookup, but
// probe() deliberately does NOT hold an old table: it re-resolves, and
// resolveDevice performs a live RSD Handshake over the tunnel every call. That
// is one control-channel round trip to the phone's tunnel endpoint — it starts
// no service, draws nothing and does not wake the screen — but it is not free,
// so poll /status on the order of seconds, not milliseconds. (Callers within
// statusReuse of each other share one probe: see bridge.status.)
const (
	svcScreenshot = "com.apple.instruments.dtservicehub"
	svcHID        = "com.apple.coredevice.hid.universalhidservice"

	// svcAppsShim is what /apps and the apps probe open in no-mux mode.
	svcAppsShim = installationproxy.ShimServiceName
)

// Reasons. The daemon turns these into the words the user hears, so states that
// need different words must never share a string.
const (
	reasonNotConnected   = "phone_not_connected"       // no usbmux entry: the phone is not on this Mac
	reasonMuxUnreachable = "phone_usbmuxd_unreachable" // usbmuxd on THIS Mac did not answer
	reasonAppsUnreadable = "phone_apps_unreadable"     // phone is here, but lockdown/installationproxy would not open
	reasonAppsFailed     = "phone_apps_failed"         // proxy opened, the app listing itself failed
	reasonAppsUnprobed   = "phone_apps_unprobed"       // the lockdown probe is switched off: nothing was established

	// No-mux mode only.
	reasonDeviceFailed     = "phone_device_failed"      // the pinned tunnel answers as another phone (cause: causeWrongDevice)
	reasonTunnelEnvInvalid = "phone_tunnel_env_invalid" // the no-mux switch or its tunnel pin will not parse
	reasonNoMux            = "phone_no_mux"             // something tried to read usbmux in no-mux mode (a bug, never a phone state)

	// Either mode: this process failed in a way it cannot name (a /status probe
	// that panicked; see bridge.fly). The daemon's own catch-all, used as such.
	reasonBridgeError = "phone_bridge_error"
)

// Causes: no-mux states the installed daemon has no word for. Co-Agent 0.5.67
// turns any reason missing from its PHONE_REASONS list into phone_bridge_error
// ("an error it could not name"), in /apps answers and in the top-level /status
// reason alike, and that daemon cannot be changed from here. So each of these
// is reported under the nearest reason the daemon DOES know, whose words and
// road handling fit it, and the precise cause leads the detail, where the logs
// and a later daemon can still tell it apart:
//
//	phone_device_failed: phone_wrong_device: the tunnel at ... answers as X, not Y
//	  (a road reason: the daemon re-measures the road and restarts the bridge,
//	  which re-pins the tunnel; the words say the bridge lost the phone)
//	phone_apps_unreadable: phone_apps_unavailable_remote: ... is not in the phone's RSD service table
//	  (the words say sight and touch work but the app list cannot be read)
const (
	causeWrongDevice           = "phone_wrong_device"            // the tunnel answers, but as a different phone than COAGENT_PHONE_UDID
	causeAppsRemoteUnavailable = "phone_apps_unavailable_remote" // the phone's RSD table does not list the installation_proxy shim
	causeProbePanicked         = "phone_probe_panicked"          // a /status probe panicked (under phone_bridge_error)
)

var (
	errWrongDevice   = errors.New(causeWrongDevice)
	errShimNotListed = errors.New(causeAppsRemoteUnavailable)
	// errAppsDeadline: the app listing ran out of time. Re-asking the same
	// pinned tunnel is no faster, so it is never retried.
	errAppsDeadline = errors.New("no complete app list")
)

// reasonMuxUnreachable replaced an earlier reason string, phone_list_failed,
// which is gone from this binary. Nothing referenced it, but a reason string is
// a word the user eventually hears, so its removal is recorded here rather than
// discovered later by diffing two binaries.

// How a capability was established. "up" without a proof would be exactly the
// claim that caused the incident, so every up/down carries one.
const (
	capUp      = "up"
	capDown    = "down"
	capUnknown = "unknown"

	proofRSD      = "rsd_service_table" // the freshly handshaken RSD service table
	proofLockdown = "lockdown_session"  // the lockdown channel installationproxy opens first
	proofListed   = "apps_listed"       // a real /apps listing already answered
	proofShim     = "rsd_shim_checkin"  // no-mux: the installation_proxy shim accepted an RSDCheckin

	// envAppsProbe=off turns the lockdown probe off. Then "apps" is reported
	// unknown — never up — because nothing has been established.
	envAppsProbe = "COAGENT_PHONE_APPS_PROBE"
)

// appsProbeTTL bounds how often the lockdown channel is opened. A watchdog
// polling /status must not open a new lockdown session every poll, and a
// seconds-old answer is still an answer the phone actually gave.
var appsProbeTTL = 5 * time.Second

// No-mux budgets. The bridge gives a /status call 12 s and the installed daemon
// aborts every route at 20 s (PhoneDeviceBridge timeoutMs), after which the
// user hears "locked or asleep" whatever really failed. So it is each whole
// ROUTE over the relay tunnel that must fit, not each step. A handshake's 6 s
// and the liveness test's 2 s include waiting for the tunnel's RSD gate and
// the one retry of a reset handshake (rsdgate.go):
//
//	/status  handshake 6 + shim checkin 4                              = 10 s
//	/apps    one appsBudget deadline covers the device, the checkin, the
//	         listing and the one retry allowed                         <= 17 s
//	read     tunnel already dead: liveness 2 + handshake 6             =  8 s
//	         dies mid-call: service dial 5 + re-resolve handshake 6    = 11 s (+ liveness)
//	gesture  tunnel dead: liveness 2 + stream stop 2 + handshake 6     = 10 s
var (
	noMuxHandshakeTimeout = 6 * time.Second
	shimCheckinTimeout    = 4 * time.Second
	shimListTimeout       = 15 * time.Second // one listing, at most
	appsBudget            = 17 * time.Second // one whole /apps request
	appsRetryListing      = 2 * time.Second  // the least listing time a retry must still have
	noMuxDialTimeout      = 5 * time.Second  // every service dial (DTX, display, HID) over the pinned tunnel

	// The liveness test: a TCP connect to the RSD port, under the tunnel's RSD
	// gate. A proof younger than liveProofTTL is trusted without a new connect.
	liveCheckTimeout = 2 * time.Second
	liveProofTTL     = 3 * time.Second
)

// streamStopTimeout bounds the video-stream stop in teardown, in both modes: a
// dead tunnel never answers it, and teardown runs under mu.
var streamStopTimeout = 2 * time.Second

// Environment for no-mux mode. Read once, in main(), by parseNoMux.
const (
	envNoMux = "COAGENT_PHONE_NO_MUX"
	envAddr  = "COAGENT_PHONE_ADDR"
	envRsd   = "COAGENT_PHONE_RSD"
	envUDID  = "COAGENT_PHONE_UDID"

	// connNoMux labels a device resolved without usbmux. It must never be
	// "USB": nothing in no-mux mode may look like the cable to cable-wins code.
	connNoMux = "Tunnel"

	// muxGuard is where go-ios's own usbmux lookups are pointed in no-mux
	// mode: a path under /dev/null can never be a socket, so a library path
	// that reaches for usbmux (instruments' failure-path version check, for
	// one) fails at once instead of asking Apple's usbmuxd or lanmux.
	muxGuard = "unix:///dev/null/coagent-phoned-no-mux"
)

// noMuxPin is the no-mux switch and the tunnel it pins. It is fixed for the
// life of the process: the bridge restarts phoned when the tunnel moves.
type noMuxPin struct {
	on   bool
	addr string // tunnel address of the phone, e.g. fd0b:a682:6f11::1
	rsd  int    // RSD port on that address
	udid string // expected UDID; empty accepts whichever phone answers
}

// noMux is set once by main() (and by tests through useNoMux). Its zero value
// is the usbmux mode every pre-existing test runs in.
var noMux noMuxPin

// parseNoMux reads the no-mux switch and its pin through getenv. Off unless
// the switch is exactly "1"; any other non-empty value except "0" is refused
// rather than quietly running the usbmux mode on a road that has no usbmux.
func parseNoMux(getenv func(string) string) (noMuxPin, error) {
	switch v := strings.TrimSpace(getenv(envNoMux)); v {
	case "", "0":
		return noMuxPin{}, nil
	case "1":
	default:
		return noMuxPin{}, fmt.Errorf("%s: %s must be 1 or unset, got %q", reasonTunnelEnvInvalid, envNoMux, v)
	}
	addr := strings.TrimSpace(getenv(envAddr))
	if net.ParseIP(addr) == nil {
		return noMuxPin{}, fmt.Errorf("%s: %s=1 needs %s to be the tunnel's IP address, got %q", reasonTunnelEnvInvalid, envNoMux, envAddr, addr)
	}
	rsd, err := strconv.Atoi(strings.TrimSpace(getenv(envRsd)))
	if err != nil || rsd <= 0 || rsd > 65535 {
		return noMuxPin{}, fmt.Errorf("%s: %s=1 needs %s to be the tunnel's RSD port, got %q", reasonTunnelEnvInvalid, envNoMux, envRsd, getenv(envRsd))
	}
	return noMuxPin{on: true, addr: addr, rsd: rsd, udid: strings.TrimSpace(getenv(envUDID))}, nil
}

// useNoMux switches the process into no-mux mode: the device comes from the
// pinned tunnel, the usbmux seam refuses, and apps() (which checks the switch)
// lists over the RSD shim under one deadline.
func useNoMux(pin noMuxPin) {
	pin.on = true
	noMux = pin
	resolve = resolveNoMux
	listDevices = func() (ios.DeviceList, error) {
		return ios.DeviceList{}, fmt.Errorf("%s: usbmux is not consulted on this road", reasonNoMux)
	}
}

// listDevices and resolve are indirected so tests can drive every branch with a
// fake. Nothing in a test may touch the user's actual phone.
var (
	listDevices = ios.ListDevices
	resolve     = resolveDevice
	listApps    = listAppsOn

	// probeLockdown opens exactly the channel installationproxy opens first —
	// usbmux Connect to the lockdown port, then StartSession with the stored
	// pair record — and closes it again. It starts no service, launches
	// nothing, draws nothing, and neither unlocks nor wakes the phone: it is
	// the same control channel Finder holds while the phone sits locked in a
	// pocket. It is the only way to learn what /apps would do without asking
	// the phone for its whole app list.
	probeLockdown = func(d ios.DeviceEntry) error {
		c, err := ios.ConnectLockdownWithSession(d)
		if err != nil {
			return fmt.Errorf("%s: %w", reasonAppsUnreadable, err)
		}
		c.Close()
		return nil
	}

	// handshake opens the RSD control channel over the tunnel and hands back
	// the freshly read service table. It is indirected for the same reason as
	// listDevices: the device SELECTION that follows it lives inside
	// resolveDevice, so a test that swaps `resolve` wholesale can never see
	// which entry resolveDevice actually caches. With this seam a test can run
	// the real resolveDevice with no tunnel and no phone.
	//
	// It is one attempt, finished within timeout; resolveDevice runs it under
	// the tunnel's RSD gate (rsdHandshake). It used to be unbounded after its
	// 15 s dial, which a gate every later contact queues behind cannot afford.
	// Same two reasons: setup failures are phone_tunnel_unreachable, a failed
	// handshake exchange phone_handshake_failed.
	handshake = func(info tunnel.Tunnel, d ios.DeviceEntry, timeout time.Duration) (ios.RsdPortProvider, error) {
		res, err := ios.RsdHandshakeWithTimeout(info.Address, info.RsdPort, d, timeout)
		if errors.Is(err, ios.ErrRsdConnect) {
			return nil, fmt.Errorf("phone_tunnel_unreachable: %w", err)
		}
		if err != nil {
			return nil, fmt.Errorf("phone_handshake_failed: %w", err)
		}
		return res, nil
	}

	// handshakeNoMux is the no-mux handshake: the same two reasons as
	// handshake, bounded end to end, and it keeps the UDID the phone reports,
	// because in no-mux mode nothing else can say which phone this is. One
	// attempt within timeout; resolveNoMux runs it under the tunnel's gate.
	handshakeNoMux = func(info tunnel.Tunnel, d ios.DeviceEntry, timeout time.Duration) (ios.RsdPortProvider, string, error) {
		res, err := ios.RsdHandshakeWithTimeout(info.Address, info.RsdPort, d, timeout)
		if errors.Is(err, ios.ErrRsdConnect) {
			return nil, "", fmt.Errorf("phone_tunnel_unreachable: %w", err)
		}
		if err != nil {
			return nil, "", fmt.Errorf("phone_handshake_failed: %w", err)
		}
		return res, res.Udid, nil
	}

	// probeShim is the no-mux apps probe: it opens the installation_proxy shim
	// over the tunnel, does the RSDCheckin with both replies checked, and
	// closes it again, all inside shimCheckinTimeout. Like probeLockdown it
	// lists nothing, launches nothing and draws nothing.
	probeShim = func(d ios.DeviceEntry) error {
		if err := shimListed(d); err != nil {
			return err
		}
		c, err := ios.ConnectToShimServiceWithTimeout(d, svcAppsShim, shimCheckinTimeout)
		if err != nil {
			return fmt.Errorf("%s: %w", reasonAppsUnreadable, err)
		}
		c.Close()
		return nil
	}

	// tunnelAlive is the no-mux liveness test: a TCP connect to the RSD port on
	// the pinned tunnel, closed at once. It starts no service and costs the
	// phone one SYN. It exists because a black-holed tunnel (utun still up,
	// nobody answering) is otherwise found only by a 15 s service dial, and a
	// HID report, which expects no reply, is "sent" into it without any error
	// at all. It is a contact with the RSD port, so it only ever runs under the
	// tunnel's gate (rsdAlive): a connect landing on a handshake in flight is
	// exactly what made the phone reset it. (The bridge's keeper no longer
	// connects here at all: it pings the tunnel address.)
	tunnelAlive = func(addr string, port int, timeout time.Duration) error {
		c, err := ios.DialTunnelTCPWithTimeout(net.JoinHostPort(addr, strconv.Itoa(port)), timeout)
		if err != nil {
			return fmt.Errorf("phone_tunnel_unreachable: [%s]:%d did not accept a connection: %w", addr, port, err)
		}
		c.Close()
		return nil
	}

	// stopStream stops the video stream and closes the display service. The
	// stop honours ctx (display closes its connection when ctx ends).
	stopStream = func(ctx context.Context, svc *display.Service, id uuid.UUID) {
		svc.StopMediaStream(ctx, id)
		svc.Close()
	}
)

// shimListed: does this device's RSD table offer the installation_proxy shim?
func shimListed(d ios.DeviceEntry) error {
	if d.Rsd == nil || d.Rsd.GetPort(svcAppsShim) == 0 {
		return fmt.Errorf("%s: %w: %s is not in the phone's RSD service table", reasonAppsUnreadable, errShimNotListed, svcAppsShim)
	}
	return nil
}

// shimSeen remembers whether the last no-mux handshake listed the shim
// (0 = not yet known, 1 = listed, 2 = absent), so the log says it once per
// change instead of once per /status poll.
var shimSeen atomic.Int32

func logShimListing(p ios.RsdPortProvider) {
	port, now := p.GetPort(svcAppsShim), int32(2)
	if port != 0 {
		now = 1
	}
	if shimSeen.Swap(now) != now {
		if now == 1 {
			log.Printf("no-mux: RSD lists %s on port %d", svcAppsShim, port)
		} else {
			log.Printf("no-mux: RSD does not list %s; /apps will report %s (%s)", svcAppsShim, reasonAppsUnreadable, causeAppsRemoteUnavailable)
		}
	}
}

type bridge struct {
	mu     sync.Mutex
	dev    ios.DeviceEntry
	ready  bool
	recv   *display.Receiver
	svc    *display.Service
	stream uuid.UUID
	hid    *hid.Session
	lastOK time.Time

	// Read path (screenshot, launch, apps) must never wait on a gesture: a 3 s
	// drag held mu, so a "mid-drag" screenshot was really taken after release.
	devMu    sync.RWMutex
	devReady bool
	devCopy  ios.DeviceEntry

	// Set ONLY when the device the gesture session was built on is proven gone
	// or different — never because an operation on it failed. The read path
	// cannot take mu (see above), so this is how it tells the gesture side to
	// rebuild instead of driving a dead session.
	stale atomic.Bool

	// No-mux only: when the pinned tunnel last proved it answers (unix nanos;
	// 0 = never). Set by a handshake, a started session or a liveness connect.
	// A HID write proves nothing: it expects no reply.
	aliveAt atomic.Int64

	// What the app-list channel last did, and when. Filled by the /status
	// probe and by every real /apps call, so the two answer each other.
	probeMu   sync.Mutex
	appsProof appsProof

	// The /status probe in flight, or the last one (bridge.status).
	flightMu sync.Mutex
	flight   *statusFlight
}

// appsProof is one remembered answer from the app-list channel.
type appsProof struct {
	at    time.Time
	key   string // appsKey of the device the answer belongs to; a re-attach (or a new tunnel) retires it
	err   error
	proof string
}

// pickDevice chooses which attached device is "the phone". The cable wins: a
// Network entry for the same phone can linger in usbmuxd after the Wi-Fi sync
// association goes stale, and DeviceList[0] happily handed us that corpse.
func pickDevice(list ios.DeviceList) (ios.DeviceEntry, error) {
	if len(list.DeviceList) == 0 {
		return ios.DeviceEntry{}, fmt.Errorf(reasonNotConnected)
	}
	for _, d := range list.DeviceList {
		if d.Properties.ConnectionType == "USB" {
			return d, nil
		}
	}
	return list.DeviceList[0], nil
}

// muxEntry finds udid in a usbmux device list. The returned entry carries the
// CURRENT DeviceID, which is the whole point: usbmuxd hands out a new DeviceID
// every time the phone re-attaches, and a cached one makes lockdown answer
// "Failed connecting to Lockdown with error code:2" while the tunnel routes,
// which key off Address and not DeviceID, keep working perfectly.
// It also honours the same cable-wins rule as pickDevice, by running pickDevice
// over the entries for this udid: usbmuxd lists one phone twice (Network + USB)
// and picking the Network row here while pickDevice picked USB handed lockdown
// one DeviceID and the tunnel another.
func muxEntry(list ios.DeviceList, udid string) (ios.DeviceEntry, bool) {
	mine := ios.DeviceList{}
	for _, d := range list.DeviceList {
		if d.Properties.SerialNumber == udid {
			mine.DeviceList = append(mine.DeviceList, d)
		}
	}
	d, err := pickDevice(mine)
	if err != nil {
		return ios.DeviceEntry{}, false
	}
	return d, true
}

// sameDevice: is this the device a session was built on, or a different one?
func sameDevice(a, b ios.DeviceEntry) bool {
	return a.Properties.SerialNumber == b.Properties.SerialNumber &&
		a.DeviceID == b.DeviceID && a.Address == b.Address
}

func resolveDevice() (ios.DeviceEntry, error) {
	list, err := listDevices()
	if err != nil {
		return ios.DeviceEntry{}, fmt.Errorf("%s: %w", reasonMuxUnreachable, err)
	}
	dev, err := pickDevice(list)
	if err != nil {
		return ios.DeviceEntry{}, err
	}
	udid := dev.Properties.SerialNumber
	host, port := tunnelAgent()
	live, liveErr := tunnelInfoForDevice(udid, host, port)
	info, err := chooseTunnel(udid, live, liveErr, os.Getenv("COAGENT_PHONE_ADDR"), os.Getenv("COAGENT_PHONE_RSD"))
	if err != nil {
		return dev, err
	}
	provider, _, err := rsdHandshake(info.Address, info.RsdPort, muxHandshakeTimeout,
		func(timeout time.Duration) (ios.RsdPortProvider, string, error) {
			p, err := handshake(info, dev, timeout)
			return p, "", err
		})
	if err != nil {
		return dev, err
	}
	// Re-select through the SAME seam and the SAME selector cacheLive uses.
	// This used to be ios.GetDeviceWithAddress, which returns the FIRST entry
	// whose SerialNumber matches with no cable-wins rule, and which calls
	// ios.ListDevices() itself rather than the listDevices seam. With a stale
	// Network row listed ahead of the USB row that handed device() a Network
	// entry while cacheLive's muxEntry picked the USB one; they disagreed, and
	// every successful call therefore invalidated the gesture session.
	d, err := selectDevice(udid)
	if err != nil {
		return dev, err
	}
	d.Address = info.Address
	d.Rsd = provider
	return d, nil
}

// resolveNoMux is resolveDevice for the road with no usbmux row: the device is
// the pinned tunnel and whatever phone answers an RSD handshake on it. It never
// calls listDevices and never asks the go-ios tunnel agent (tunnelAgent), whose
// registry belongs to `ios tunnel start` and can still hold a dead tunnel for
// the same UDID (chooseTunnel would prefer that live-looking answer).
func resolveNoMux() (ios.DeviceEntry, error) {
	pin := noMux
	d := ios.DeviceEntry{Address: pin.addr, Properties: ios.DeviceProperties{ConnectionType: connNoMux}}
	info := tunnel.Tunnel{Address: pin.addr, RsdPort: pin.rsd, Udid: pin.udid}
	p, udid, err := rsdHandshake(pin.addr, pin.rsd, noMuxHandshakeTimeout,
		func(timeout time.Duration) (ios.RsdPortProvider, string, error) {
			return handshakeNoMux(info, d, timeout)
		})
	if err != nil {
		return d, err
	}
	if pin.udid != "" && !strings.EqualFold(udid, pin.udid) {
		return d, fmt.Errorf("%s: %w: the tunnel at [%s]:%d answers as %s, not %s", reasonDeviceFailed, errWrongDevice, pin.addr, pin.rsd, udid, pin.udid)
	}
	logShimListing(p)
	d.Properties.SerialNumber = udid
	d.Rsd = p
	return d, nil
}

// selectDevice is the one device selector: read usbmuxd through the listDevices
// seam, then apply the cable-wins rule via muxEntry — exactly what cacheLive
// re-checks against. Nothing else in this binary may pick a device.
func selectDevice(udid string) (ios.DeviceEntry, error) {
	list, err := listDevices()
	if err != nil {
		return ios.DeviceEntry{}, fmt.Errorf("%s: %w", reasonMuxUnreachable, err)
	}
	d, found := muxEntry(list, udid)
	if !found {
		return ios.DeviceEntry{}, fmt.Errorf("%s: %s is no longer on the usbmux bus", reasonNotConnected, udid)
	}
	return d, nil
}

func (b *bridge) teardown() {
	if b.hid != nil {
		b.hid.Close()
		b.hid = nil
	}
	if b.svc != nil {
		// Bounded: this used to wait with context.Background(), and over a dead
		// or black-holed tunnel the device never answers, so a rebuild held mu
		// (every gesture) until TCP keepalive gave up on the connection.
		ctx, cancel := context.WithTimeout(context.Background(), streamStopTimeout)
		stopStream(ctx, b.svc, b.stream)
		cancel()
		b.svc = nil
	}
	if b.recv != nil {
		b.recv.Close()
		b.recv = nil
	}
	b.ready = false
	b.devMu.Lock()
	b.devReady = false
	b.devMu.Unlock()
}

// dropDevice forgets which device the read path should use, so the next call
// re-selects one. It does NOT condemn the gesture session: closing the HID
// session and the video stream costs the user's next tap a 600 ms sleep plus a
// StartVideoStream with a 15 s timeout, and a locked phone or one failed app
// listing must never buy that. It takes devMu only, never mu, so a read path
// can call it while a 3 s drag runs.
func (b *bridge) dropDevice() {
	b.devMu.Lock()
	b.devReady = false
	b.devMu.Unlock()
}

// markStale condemns the gesture session. Reserved for the one thing that
// really does kill it: the device it was built on is gone or is now a
// different device.
func (b *bridge) markStale() { b.stale.Store(true) }

// invalidate is both: the cached device is wrong AND the session built on it is
// dead. Use it only where the device identity itself changed or vanished — or,
// in no-mux mode, where the one tunnel every session rides stopped answering.
func (b *bridge) invalidate() {
	b.dropDevice()
	b.markStale()
}

// sawTunnel records that the pinned tunnel just answered. Only no-mux mode
// reads it (tunnelAnswers).
func (b *bridge) sawTunnel() { b.aliveAt.Store(time.Now().UnixNano()) }

// tunnelAnswers: in no-mux mode, did the pinned tunnel answer within
// liveProofTTL, or does it accept a connection now (bounded by
// liveCheckTimeout)? Always true in usbmux mode, where the usbmux re-checks
// (cacheLive, appsEntry) are what catch a phone that went away.
//
// The connect waits for the tunnel's RSD gate inside liveCheckTimeout, and a
// handshake that succeeded while it waited is its proof. A handshake that holds
// the gate past liveCheckTimeout counts as not answering in time, as a connect
// that took that long always did.
func (b *bridge) tunnelAnswers() bool {
	if !noMux.on {
		return true
	}
	if at := b.aliveAt.Load(); at != 0 && time.Since(time.Unix(0, at)) < liveProofTTL {
		return true
	}
	if err := rsdAlive(noMux.addr, noMux.rsd, liveCheckTimeout); err != nil {
		log.Printf("no-mux: %v", err)
		return false
	}
	b.sawTunnel()
	return true
}

// ensure brings up device + video stream + HID. Caller holds mu.
func (b *bridge) ensure() error {
	if b.ready && !b.stale.Load() {
		return nil
	}
	b.teardown()
	// Cleared before the rebuild, not after: an invalidation raised while we are
	// rebuilding then costs one extra rebuild instead of being silently lost.
	b.stale.Store(false)
	d, err := resolve()
	if err != nil {
		return err
	}
	b.dev = d
	recv, err := display.OpenReceiver(d)
	if err != nil {
		return fmt.Errorf("phone_stream_receiver_failed: %w", err)
	}
	b.recv = recv
	go func(r *display.Receiver) {
		buf := make([]byte, 65536)
		for {
			if _, e := r.Read(buf); e != nil {
				return
			}
		}
	}(recv)
	svc, err := display.New(d)
	if err != nil {
		b.teardown()
		return fmt.Errorf("phone_display_service_failed: %w", err)
	}
	b.svc = svc
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sid, err := svc.StartVideoStream(ctx, display.VideoStreamRequest{ReceiverIP: recv.IP(), ReceiverPort: recv.Port(), SenderIP: d.Address})
	if err != nil {
		b.teardown()
		return fmt.Errorf("phone_stream_start_failed: %w", err)
	}
	b.stream = sid
	time.Sleep(600 * time.Millisecond)
	s, err := hid.NewSession(d)
	if err != nil {
		b.teardown()
		return fmt.Errorf("phone_hid_failed: %w", err)
	}
	b.hid = s
	b.ready = true
	b.sawTunnel()
	b.devMu.Lock()
	b.devCopy, b.devReady = d, true
	b.devMu.Unlock()
	return nil
}

func pt(x, y float64) hid.Point { return hid.Point{X: uint16(x * 65535), Y: uint16(y * 65535)} }

func unit(v float64) bool { return v >= 0 && v <= 1 }

// withHID runs fn once, and on failure rebuilds the session and retries once.
//
// In no-mux mode a ready session is reused only after the tunnel it rides is
// shown to answer (tunnelAnswers). HID reports expect no reply and a small
// write into a black-holed tunnel succeeds, so without this a tap after the
// relay died answered {"ok":true} for as long as this process lived.
func (b *bridge) withHID(fn func(*hid.Session) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ready && !b.stale.Load() && !b.tunnelAnswers() {
		b.invalidate()
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := b.ensure(); err != nil {
			return err
		}
		if err := fn(b.hid); err != nil {
			b.teardown()
			if attempt == 1 {
				return fmt.Errorf("phone_touch_failed: %w", err)
			}
			continue
		}
		b.lastOK = time.Now()
		return nil
	}
	return nil
}

// cacheLive re-checks the cached entry against the local usbmux list. If usbmuxd
// itself will not answer we have not DISPROVED the cache, so we keep it: the
// tunnel routes may well still work and guessing "gone" would be its own lie.
//
// In no-mux mode there is no local list to check against, so this only asks
// whether the entry belongs to the pinned tunnel (address and, because the pin
// is fixed for the process, its RSD port). Consulting usbmux here instead would
// find nothing and throw the gesture session away on every call. Whether that
// tunnel still ANSWERS is device()'s second question (tunnelAnswers): trusting
// it blind made a read on a black-holed tunnel pay the full service dial and
// then a re-handshake, about 21 s, past the daemon's 20 s.
func cacheLive(d ios.DeviceEntry) bool {
	if noMux.on {
		return d.Address == noMux.addr && d.Rsd != nil && d.Properties.SerialNumber != ""
	}
	live, err := listDevices()
	if err != nil {
		return true
	}
	cur, found := muxEntry(live, d.Properties.SerialNumber)
	return found && cur.DeviceID == d.DeviceID
}

// device returns a device for the tunnel routes. The cache is never trusted
// blind: it is re-checked against usbmuxd on this Mac first, which is a unix
// socket round trip to a local daemon and never reaches the phone, so it can
// never wake or interrupt it. In no-mux mode it is re-checked against the
// pinned tunnel instead: a TCP connect to its RSD port, at most once per
// liveProofTTL, which likewise starts nothing on the phone.
func (b *bridge) device() (ios.DeviceEntry, error) {
	b.devMu.RLock()
	d, cached := b.devCopy, b.devReady
	b.devMu.RUnlock()
	if cached {
		if cacheLive(d) && b.tunnelAnswers() {
			return d, nil
		}
		b.invalidate()
	}
	nd, err := resolve()
	if err != nil {
		return nd, err
	}
	b.sawTunnel()
	b.devMu.Lock()
	b.devCopy, b.devReady = nd, true
	b.devMu.Unlock()
	return nd, nil
}

// withDevice runs fn against the current device and, on failure, drops the cache
// and retries once against a freshly resolved one. Latching a dead device is the
// defect this exists to prevent.
func (b *bridge) withDevice(fn func(ios.DeviceEntry) error) error {
	d, err := b.device()
	if err != nil {
		return err
	}
	if err = fn(d); err == nil {
		return nil
	}
	// A failed DTX call does not prove the phone changed, and the HID session
	// does not ride on this call. So drop the device selection, re-resolve, and
	// condemn the gesture session only if the device really is gone or
	// different — one transient screenshot failure must not cost the next tap
	// a full rebuild.
	b.dropDevice()
	fresh, rerr := b.device()
	if rerr != nil {
		// The re-resolve explains WHY the first call failed, and in better
		// words: "no phone attached" beats "capture failed".
		b.markStale()
		return rerr
	}
	if !sameDevice(d, fresh) {
		b.markStale()
	}
	return fn(fresh)
}

// appsDevice returns the usbmux entry the app list needs. /apps talks lockdown +
// installationproxy over usbmux and never uses the tunnel, so it must not be made
// to fail on a tunnel handshake it does not need — and it must use the CURRENT
// DeviceID, not the one cached when the tunnel was first built.
//
// In no-mux mode the app list rides the tunnel (the installation_proxy RSD
// shim), so the device it needs IS the tunnel device: the cached one, or a
// freshly handshaken one.
func (b *bridge) appsDevice() (ios.DeviceEntry, error) {
	if noMux.on {
		return b.device()
	}
	live, err := listDevices()
	if err != nil {
		return ios.DeviceEntry{}, fmt.Errorf("%s: %w", reasonMuxUnreachable, err)
	}
	return b.appsEntry(live)
}

// appsEntry picks that entry out of a list already in hand, so /status probes
// the very entry /apps would use instead of a second, differently chosen one.
func (b *bridge) appsEntry(live ios.DeviceList) (ios.DeviceEntry, error) {
	b.devMu.RLock()
	udid, known := b.devCopy.Properties.SerialNumber, b.devReady
	b.devMu.RUnlock()
	if known {
		if cur, found := muxEntry(live, udid); found {
			return cur, nil
		}
		// The phone we were using is no longer on the bus: identity gone, so
		// the gesture session built on it is dead too.
		b.invalidate()
	}
	return pickDevice(live)
}

func appRow(a installationproxy.AppInfo) map[string]any {
	// Half of what the device reports is not an app you can open: extensions
	// and internal services carry SBAppTags "hidden" and have no icon. Two
	// of them are literally called "Mail", which is why "open the mail app"
	// came back ambiguous with two identical choices.
	hidden := false
	if tags, ok := a["SBAppTags"].([]interface{}); ok {
		for _, t := range tags {
			if s, ok := t.(string); ok && s == "hidden" {
				hidden = true
			}
		}
	}
	_, hasIcons := a["CFBundleIcons"]
	if !hasIcons {
		_, hasIcons = a["CFBundleIconFiles"]
	}
	name := a.CFBundleName()
	if d, ok := a["CFBundleDisplayName"].(string); ok && d != "" {
		name = d
	}
	kind, _ := a["ApplicationType"].(string)
	return map[string]any{
		"bundleId":   a.CFBundleIdentifier(),
		"name":       name,
		"bundleName": a.CFBundleName(),
		"type":       kind,
		"openable":   hasIcons && !hidden,
	}
}

func listAppsOn(d ios.DeviceEntry) ([]map[string]any, error) {
	ip, err := installationproxy.New(d)
	if err != nil {
		// The phone IS on this Mac (we just read it out of usbmuxd) but lockdown
		// or the install proxy would not open: not trusted, locked, or the mux
		// entry went stale under us. Different words from "not connected".
		return nil, fmt.Errorf("%s: %w", reasonAppsUnreadable, err)
	}
	defer ip.Close()
	return browseRows(ip)
}

// shimAttributes are the only keys appRow reads, and all the shim listing asks
// the phone for (ReturnAttributes). Without them a Browse returns every
// attribute of every app — paths, containers, entitlements — which over a
// cellular relay is what pushed a working listing toward its time limit.
var shimAttributes = []string{
	installationproxy.CFBundleIdentifier, installationproxy.CFBundleName, "CFBundleDisplayName",
	"ApplicationType", "SBAppTags", "CFBundleIcons", "CFBundleIconFiles",
}

// listAppsShim is listAppsOn for no-mux mode: the same listing, over the
// installation_proxy RSD shim instead of usbmux + lockdown, and bounded by
// shimListTimeout. Only the connection differs, so the rows and the two
// failure words are the same.
func listAppsShim(d ios.DeviceEntry) ([]map[string]any, error) {
	return listAppsShimBy(d, time.Now().Add(shimListTimeout))
}

// listAppsShimBy is listAppsShim finishing by deadline (and never taking more
// than shimListTimeout): the checkin and the listing both fit before it.
func listAppsShimBy(d ios.DeviceEntry, deadline time.Time) ([]map[string]any, error) {
	if err := shimListed(d); err != nil {
		return nil, err
	}
	start := time.Now()
	if limit := start.Add(shimListTimeout); limit.Before(deadline) {
		deadline = limit
	}
	left := time.Until(deadline)
	if left <= 0 {
		return nil, fmt.Errorf("%s: %w: the request's time was already spent", reasonAppsFailed, errAppsDeadline)
	}
	conn, err := ios.ConnectToShimServiceWithTimeout(d, svcAppsShim, min(shimCheckinTimeout, left))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", reasonAppsUnreadable, err)
	}
	ip := installationproxy.NewWithConnection(conn)
	var once sync.Once
	closeIP := func() { once.Do(ip.Close) }
	defer closeIP()
	// installationproxy has no deadline of its own. Closing the connection
	// from a timer is what unblocks a browse the phone stopped answering.
	var expired atomic.Bool
	timer := time.AfterFunc(time.Until(deadline), func() { expired.Store(true); closeIP() })
	defer timer.Stop()
	out, err := browseRowsWith(ip, shimAttributes)
	if err != nil && expired.Load() {
		return nil, fmt.Errorf("%s: %w within %s: %w", reasonAppsFailed, errAppsDeadline, deadline.Sub(start).Round(time.Millisecond), err)
	}
	return out, err
}

func browseRows(ip *installationproxy.Connection) ([]map[string]any, error) {
	return collectRows(ip.BrowseUserApps, ip.BrowseSystemApps)
}

// browseRowsWith is browseRows asking only for attributes.
func browseRowsWith(ip *installationproxy.Connection, attributes []string) ([]map[string]any, error) {
	return collectRows(
		func() ([]installationproxy.AppInfo, error) { return ip.BrowseUserAppsWithAttributes(attributes) },
		func() ([]installationproxy.AppInfo, error) { return ip.BrowseSystemAppsWithAttributes(attributes) },
	)
}

func collectRows(browses ...func() ([]installationproxy.AppInfo, error)) ([]map[string]any, error) {
	out := []map[string]any{}
	for _, browse := range browses {
		apps, err := browse()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", reasonAppsFailed, err)
		}
		for _, a := range apps {
			out = append(out, appRow(a))
		}
	}
	return out, nil
}

// apps lists the phone's apps, retrying once against a re-selected device. Every
// outcome is remembered: a listing that just worked is the best possible proof
// for /status, and one that just failed is the truth /status must report.
func (b *bridge) apps() ([]map[string]any, error) {
	if noMux.on {
		return b.appsNoMux()
	}
	d, err := b.appsDevice()
	if err != nil {
		return nil, err
	}
	out, err := listApps(d)
	b.noteApps(d, err, proofListed)
	if err == nil {
		return out, nil
	}
	// The app-list channel failed. That is no evidence about the gesture
	// session — a merely locked phone lands here — so the HID session and the
	// video stream stay up and only the device selection is dropped.
	b.dropDevice()
	fresh, rerr := b.appsDevice()
	if rerr != nil {
		return nil, rerr
	}
	out, err = listApps(fresh)
	b.noteApps(fresh, err, proofListed)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// appsNoMux is apps() over the relay tunnel. The two-attempt shape above, with
// a full listing limit per attempt and a handshake between them, cost up to
// about 36 s there, while the installed daemon aborts /apps at 20 s, so a slow
// listing could never succeed and the user heard "locked or asleep" instead of
// what failed. Here one deadline (appsBudget) covers the whole request, and the
// second attempt is made only when it can help and still fit:
//   - never after the listing ran out of time: the address is pinned for the
//     life of this process, so a retry asks the same slow tunnel again;
//   - never when the RSD table does not list the shim: a fresh handshake of the
//     same phone lists the same services;
//   - only if a handshake, a checkin and appsRetryListing still fit.
func (b *bridge) appsNoMux() ([]map[string]any, error) {
	deadline := time.Now().Add(appsBudget)
	d, err := b.appsDevice()
	if err != nil {
		return nil, err
	}
	out, err := listAppsShimBy(d, deadline)
	b.noteApps(d, err, proofListed)
	if err == nil {
		return out, nil
	}
	if errors.Is(err, errAppsDeadline) || errors.Is(err, errShimNotListed) ||
		time.Until(deadline) < noMuxHandshakeTimeout+shimCheckinTimeout+appsRetryListing {
		return nil, err
	}
	// As in apps(): an app-list failure is no evidence about the gesture
	// session, so only the device selection is dropped.
	b.dropDevice()
	fresh, rerr := b.appsDevice()
	if rerr != nil {
		return nil, rerr
	}
	out, err = listAppsShimBy(fresh, deadline)
	b.noteApps(fresh, err, proofListed)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// noteApps remembers what the app-list channel last did, for this exact device.
func (b *bridge) noteApps(d ios.DeviceEntry, err error, proof string) {
	b.probeMu.Lock()
	b.appsProof = appsProof{at: time.Now(), key: appsKey(d), err: err, proof: proof}
	b.probeMu.Unlock()
}

func appsKey(d ios.DeviceEntry) string {
	if noMux.on {
		// DeviceID is always 0 without usbmux, so the tunnel is what tells one
		// answer from the next: a re-armed tunnel is a new question.
		return d.Properties.SerialNumber + "#" + d.Address + "#" + strconv.Itoa(noMux.rsd)
	}
	return d.Properties.SerialNumber + "#" + strconv.Itoa(d.DeviceID)
}

// status is a probe, not a latch: it re-asks all three transports every time and
// reports them separately, because the incident was one of them being dead while
// the other answered for it.
//
// The shape is what a caller must ACT on, so each capability carries its own
// state and its own reason: the daemon needs to say "your iPhone is not
// connected to this Mac" for one and "I can see it but cannot open its app
// list" for another, and a single bool cannot carry that.
type capability struct {
	State  string `json:"state"`            // capUp, capDown or capUnknown
	Proof  string `json:"proof,omitempty"`  // what was actually opened or read
	Reason string `json:"reason,omitempty"` // set whenever State is not capUp
	Detail string `json:"detail,omitempty"` // the underlying error, for logs
	AgeMs  int64  `json:"ageMs,omitempty"`  // >0: answered from the brief cache
}

func (c capability) up() bool { return c.State == capUp }

type status struct {
	// OK is true only when all three are up. unknown is not ok: a caller that
	// reads only this field now fails closed, which is the opposite of what
	// happened on 2026-09-19.
	OK     bool       `json:"ok"`
	UDID   string     `json:"udid,omitempty"`
	See    capability `json:"see"`
	Act    capability `json:"act"`
	Apps   capability `json:"apps"`
	Reason string     `json:"reason,omitempty"` // the first capability that is not up
	Detail string     `json:"detail,omitempty"`
}

// appsCapability answers what /apps would do, by opening the channel /apps
// opens. Presence on the usbmux bus is not evidence: the incident state was a
// phone present on the bus whose lockdown channel refused with error code:2.
//
// In no-mux mode the channel is the installation_proxy RSD shim, and the table
// the handshake just returned is consulted first: a phone whose RSD does not
// list the shim cannot give an app list over this road, whatever was
// remembered, and that is established without opening anything.
func (b *bridge) appsCapability(d ios.DeviceEntry) capability {
	probeApps, proof, channel := probeLockdown, proofLockdown, "the lockdown channel"
	if noMux.on {
		if err := shimListed(d); err != nil {
			return capability{State: capDown, Proof: proofRSD, Reason: reasonOf(err), Detail: err.Error()}
		}
		probeApps, proof, channel = probeShim, proofShim, "the installation_proxy shim"
	}
	// The remembered answer comes FIRST, before the probe switch. envAppsProbe
	// bounds what this function may OPEN; it is not permission to forget what
	// the phone already said. Reading it first threw away an /apps listing that
	// had just succeeded and pinned apps unknown/unprobed for as long as the
	// switch was set — a fresh "ok=false" over hard proof of ok.
	key := appsKey(d)
	b.probeMu.Lock()
	last := b.appsProof
	b.probeMu.Unlock()
	if last.key == key && !last.at.IsZero() {
		if age := time.Since(last.at); age < appsProbeTTL {
			c := appsCapabilityFor(last)
			if ms := age.Milliseconds(); ms > 0 {
				c.AgeMs = ms
			}
			return c
		}
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv(envAppsProbe)), "off") {
		// Nothing is in hand and nothing may be opened, so nothing is claimed.
		return capability{State: capUnknown, Reason: reasonAppsUnprobed,
			Detail: envAppsProbe + "=off: " + channel + " was not opened"}
	}
	err := probeApps(d)
	b.noteApps(d, err, proof)
	b.probeMu.Lock()
	fresh := b.appsProof
	b.probeMu.Unlock()
	return appsCapabilityFor(fresh)
}

func appsCapabilityFor(p appsProof) capability {
	if p.err == nil {
		return capability{State: capUp, Proof: p.proof}
	}
	return capability{State: capDown, Proof: p.proof, Reason: reasonOf(p.err), Detail: p.err.Error()}
}

func (b *bridge) probe() status {
	if noMux.on {
		return b.probeNoMux()
	}
	st := status{}

	// apps: usbmux presence first (a local unix socket; it never reaches the
	// phone), then the lockdown channel itself.
	live, lerr := listDevices()
	if lerr != nil {
		// installationproxy has no route that does not go through usbmuxd, so
		// this one is a certain no, not an unknown.
		st.Apps = capability{State: capDown, Reason: reasonMuxUnreachable, Detail: lerr.Error()}
	} else if d, err := b.appsEntry(live); err != nil {
		st.Apps = capability{State: capDown, Reason: reasonOf(err)}
	} else {
		st.UDID = d.Properties.SerialNumber
		st.Apps = b.appsCapability(d)
	}

	// see/act: resolve the tunnel fresh — a cached RSD table is exactly the kind
	// of stale claim that caused this. No video stream and no HID session are
	// started here; a probe must not drive the phone.
	d, err := resolve()
	if err != nil {
		down := capability{State: capDown, Reason: reasonOf(err), Detail: err.Error()}
		st.See, st.Act = down, down
		// A probe observes; it must not cost the user a rebuild. Drop the
		// device selection (its RSD table is dead) but leave the gesture
		// session alone: every acting path re-checks for itself.
		b.dropDevice()
	} else {
		if st.UDID == "" {
			st.UDID = d.Properties.SerialNumber
		}
		st.See, st.Act = seeAct(d)
		b.devMu.Lock()
		b.devCopy, b.devReady = d, true
		b.devMu.Unlock()
	}
	return st.summarize()
}

// seeAct reads "see" and "act" out of a freshly handshaken RSD table.
func seeAct(d ios.DeviceEntry) (see, act capability) {
	if d.Rsd == nil {
		down := capability{State: capDown, Reason: "phone_handshake_failed"}
		return down, down
	}
	see = capability{State: capUp, Proof: proofRSD}
	act = capability{State: capUp, Proof: proofRSD}
	if d.Rsd.GetPort(svcScreenshot) == 0 {
		see = capability{State: capDown, Proof: proofRSD, Reason: "phone_capture_failed"}
	}
	if d.Rsd.GetPort(svcHID) == 0 {
		// dtuhidd ships in the developer disk image, not in iOS.
		act = capability{State: capDown, Proof: proofRSD, Reason: "phone_hid_failed"}
	}
	return see, act
}

// summarize fills OK and the single reason from the three capabilities.
func (st status) summarize() status {
	st.OK = st.See.up() && st.Act.up() && st.Apps.up()
	// The single reason is for a caller that reads one string; the capabilities
	// are the truth. apps leads because that is the one that was lied about.
	for _, c := range []capability{st.Apps, st.See, st.Act} {
		if !c.up() {
			st.Reason, st.Detail = c.Reason, c.Detail
			break
		}
	}
	return st
}

// probeNoMux is probe() for the road with no usbmux: every capability rides
// the one tunnel, so it is resolved first (a fresh, bounded handshake) and
// the app channel is then probed over the RSD shim on that same tunnel. If the
// tunnel does not answer, all three are down for that one reason. The
// UDID reported is only ever the one the handshake proved.
//
// Unlike probe(), a failed resolve here DOES condemn the gesture session. In
// usbmux mode a phone that went away is caught by the usbmux re-checks; in
// no-mux mode nothing else ever would be, because the HID session rides the
// very tunnel this handshake just failed on and its writes expect no reply, so
// taps kept answering {"ok":true} into a dead relay until the process was
// replaced. The cost is one rebuild on the next gesture if the failure was a
// passing one; the alternative is a gesture claimed that never happened.
func (b *bridge) probeNoMux() status {
	st := status{}
	d, err := resolve()
	if err != nil {
		down := capability{State: capDown, Reason: reasonOf(err), Detail: err.Error()}
		st.See, st.Act, st.Apps = down, down, down
		b.invalidate()
		return st.summarize()
	}
	b.sawTunnel()
	st.UDID = d.Properties.SerialNumber
	st.See, st.Act = seeAct(d)
	st.Apps = b.appsCapability(d)
	b.devMu.Lock()
	b.devCopy, b.devReady = d, true
	b.devMu.Unlock()
	return st.summarize()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// lockedLaunch is iOS's own wording when it refuses to open an app because the
// phone is locked (FBSOpenApplicationErrorDomain error 7, "Locked": "the device
// was not, or could not be, unlocked").
var lockedLaunch = regexp.MustCompile(`(?i)\blocked\b|could not be,? unlocked`)

// launchReason names a refused launch. A locked phone is the one refusal the
// person holding it can fix, so it gets its own reason instead of the generic
// phone_launch_failed (2026-09-28: the voice must say "unlock your phone").
func launchReason(err error) string {
	if err != nil && lockedLaunch.MatchString(err.Error()) {
		return "phone_locked"
	}
	return "phone_launch_failed"
}

func reasonOf(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ":"); i > 0 {
		return msg[:i]
	}
	return msg
}

func fail(w http.ResponseWriter, err error) {
	writeJSON(w, 502, map[string]any{"ok": false, "reason": reasonOf(err), "detail": err.Error()})
}

// tunnelAgent is WHERE `ios tunnel start` publishes its tunnels: go-ios's own
// agent API (127.0.0.1:60105, or GO_IOS_AGENT_HOST / GO_IOS_AGENT_PORT).
//
// This used to be a hard-coded 127.0.0.1:28100, the port of an older go-ios.
// Nothing listens there, so the live lookup ALWAYS failed and chooseTunnel
// always fell back to the address pinned at launch. Over Wi-Fi the tunnel is
// rebuilt with a new address every time the phone sleeps ("SleepyTime"), so
// within minutes the bridge was dialling a dead address: see and act down
// with phone_tunnel_unreachable while the tunnel itself was up (2026-09-28,
// "open my mail app" refused with the tunnel on).
func tunnelAgent() (string, int) {
	return ios.HttpApiHost(), ios.HttpApiPort()
}

// tunnelInfoForDevice is a seam so the choice below can be tested without a tunnel.
var tunnelInfoForDevice = tunnel.TunnelInfoForDevice

// chooseTunnel decides WHERE the phone's tunnel is: ask the tunnel itself first,
// and fall back to the address pinned at launch only when it will not answer.
//
// It used to be the other way round. phone-bridge.sh exports COAGENT_PHONE_ADDR
// and COAGENT_PHONE_RSD when it starts this process, and with those set the live
// lookup was never made. But unplugging and replugging the phone gives the
// tunnel a NEW address and port, so the bridge kept dialling the dead one until
// somebody reran the script: "plug your phone back in" did not work on its own.
// The pinned value still matters - the tunnel's info service is known to die
// while the tunnel itself lives - so it stays, as the fallback it always was.
func chooseTunnel(udid string, live tunnel.Tunnel, liveErr error, envAddr, envPort string) (tunnel.Tunnel, error) {
	if liveErr == nil && live.Address != "" && live.RsdPort > 0 {
		return live, nil
	}
	if envAddr != "" {
		port, perr := strconv.Atoi(envPort)
		if perr != nil {
			return tunnel.Tunnel{}, fmt.Errorf("phone_tunnel_env_invalid")
		}
		return tunnel.Tunnel{Address: envAddr, RsdPort: port, Udid: udid}, nil
	}
	if liveErr != nil {
		return tunnel.Tunnel{}, fmt.Errorf("phone_tunnel_down: %w", liveErr)
	}
	return tunnel.Tunnel{}, fmt.Errorf("phone_tunnel_down")
}

func main() {
	token := strings.TrimSpace(os.Getenv("COAGENT_PHONE_TOKEN"))
	if len(token) < 24 {
		log.Fatal("COAGENT_PHONE_TOKEN (>=24 chars) is required")
	}
	addr := os.Getenv("COAGENT_PHONE_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8793"
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		log.Fatal("loopback only")
	}
	// The no-mux switch is read here and nowhere else.
	pin, err := parseNoMux(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if pin.on {
		useNoMux(pin)
		os.Setenv("USBMUXD_SOCKET_ADDRESS", muxGuard)
		// Every service dial (DTX, display, HID) goes to the one pinned tunnel,
		// and a route must fit inside the daemon's 20 s: see the budgets.
		ios.SetTunnelDialTimeout(noMuxDialTimeout)
	}
	b := &bridge{}
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("authorization") != "Bearer "+token {
				writeJSON(w, 401, map[string]any{"ok": false, "reason": "phone_bridge_unauthorized"})
				return
			}
			h(w, r)
		}
	}
	body := func(r *http.Request) map[string]any {
		m := map[string]any{}
		json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4096)).Decode(&m)
		return m
	}
	num := func(m map[string]any, k string) float64 {
		v, ok := m[k].(float64)
		if !ok {
			return -1
		}
		return v
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", auth(func(w http.ResponseWriter, r *http.Request) {
		// Always 200: the body IS the answer, and a caller that cannot read it
		// learns nothing about which of the three capabilities died. Concurrent
		// callers share one probe (bridge.status): two handshakes at once make
		// the phone reset one of them.
		writeJSON(w, 200, b.status())
	}))
	mux.HandleFunc("/screenshot", auth(func(w http.ResponseWriter, r *http.Request) {
		var png []byte
		err := b.withDevice(func(d ios.DeviceEntry) error {
			ss, err := instruments.NewScreenshotService(d)
			if err != nil {
				return fmt.Errorf("phone_capture_failed: %w", err)
			}
			defer ss.Close()
			shot, err := ss.TakeScreenshot()
			if err != nil || len(shot) == 0 {
				return fmt.Errorf("phone_capture_failed: %v", err)
			}
			png = shot
			return nil
		})
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("content-type", "image/png")
		w.Write(png)
	}))
	mux.HandleFunc("/tap", auth(func(w http.ResponseWriter, r *http.Request) {
		m := body(r)
		x, y := num(m, "x"), num(m, "y")
		if !unit(x) || !unit(y) {
			writeJSON(w, 400, map[string]any{"ok": false, "reason": "phone_point_invalid"})
			return
		}
		hold := 60 * time.Millisecond
		if h := num(m, "holdMs"); h > 0 && h <= 3000 {
			hold = time.Duration(h) * time.Millisecond
		}
		err := b.withHID(func(s *hid.Session) error {
			if e := s.TouchDown(pt(x, y)); e != nil {
				return e
			}
			time.Sleep(hold)
			return s.TouchUp(pt(x, y))
		})
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
	mux.HandleFunc("/swipe", auth(func(w http.ResponseWriter, r *http.Request) {
		m := body(r)
		x1, y1, x2, y2 := num(m, "x1"), num(m, "y1"), num(m, "x2"), num(m, "y2")
		if !unit(x1) || !unit(y1) || !unit(x2) || !unit(y2) {
			writeJSON(w, 400, map[string]any{"ok": false, "reason": "phone_point_invalid"})
			return
		}
		ms := num(m, "durationMs")
		if ms < 40 || ms > 3000 {
			ms = 250
		}
		steps := int(ms / 8)
		err := b.withHID(func(s *hid.Session) error {
			for i := 0; i <= steps; i++ {
				t := float64(i) / float64(steps)
				if e := s.TouchDown(pt(x1+(x2-x1)*t, y1+(y2-y1)*t)); e != nil {
					return e
				}
				time.Sleep(8 * time.Millisecond)
			}
			return s.TouchUp(pt(x2, y2))
		})
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
	mux.HandleFunc("/launch", auth(func(w http.ResponseWriter, r *http.Request) {
		m := body(r)
		id, _ := m["bundleId"].(string)
		if id == "" || len(id) > 200 {
			writeJSON(w, 400, map[string]any{"ok": false, "reason": "phone_bundle_invalid"})
			return
		}
		var pid uint64
		err := b.withDevice(func(d ios.DeviceEntry) error {
			pc, err := instruments.NewProcessControl(d)
			if err != nil {
				return fmt.Errorf("%s: %w", launchReason(err), err)
			}
			defer pc.Close()
			p, err := pc.LaunchApp(id, map[string]any{})
			if err != nil {
				return fmt.Errorf("%s: %w", launchReason(err), err)
			}
			pid = p
			return nil
		})
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "pid": pid})
	}))
	mux.HandleFunc("/apps", auth(func(w http.ResponseWriter, r *http.Request) {
		out, err := b.apps()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "apps": out})
	}))
	if noMux.on {
		log.Printf("coagent-phoned on %s (no-mux: tunnel [%s]:%d, expected udid %q)", addr, noMux.addr, noMux.rsd, noMux.udid)
	} else {
		log.Printf("coagent-phoned on %s", addr)
	}
	log.Fatal(http.ListenAndServe(addr, mux))
}
