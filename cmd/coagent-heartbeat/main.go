// coagent-heartbeat: keep the phone's lockdown heartbeat answered while Co-Agent controls it over the
// network (the lan road: lanmux.py + USBMUXD_SOCKET_ADDRESS).
//
// WHY THIS EXISTS (2026-09-22). Over Wi-Fi, iOS ties every lockdown service a host starts to that
// host's com.apple.mobile.heartbeat session: heartbeatd watches the service and, when no heartbeat is
// running for the host, invalidates it the moment it opens. For the CoreDeviceProxy tunnel that looks
// like the phone closing the connection right after TLS ("could not exchange tunnel parameters ... EOF";
// phone log: "Lockdown tunnel connection failed ... connection was closed"). Apple's usbmuxd runs this
// heartbeat for the network devices IT manages; lanmux dials the phone directly, so nothing did — and
// the lan road only worked when something else on the Mac (Xcode, Apple's usbmuxd) happened to be
// holding one. Measured: the same request answered serverHandshakeResponse once a heartbeat ran.
//
// The protocol: the phone sends {Command: Marco, Interval: N}; the host answers {Command: Polo}. The
// session is reopened whenever it drops (phone asleep, Wi-Fi change). One JSON line per state change.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"howett.net/plist"
)

func logLine(event string, kv ...any) {
	out := map[string]any{"t": time.Now().Format(time.RFC3339), "event": event}
	for i := 0; i+1 < len(kv); i += 2 {
		out[fmt.Sprint(kv[i])] = kv[i+1]
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}

// session holds one heartbeat session until it fails, answering every Marco.
func session(udid string) error {
	list, err := ios.ListDevices()
	if err != nil {
		return fmt.Errorf("usbmux: %w", err)
	}
	var d ios.DeviceEntry
	found := false
	for _, e := range list.DeviceList {
		if udid == "" || e.Properties.SerialNumber == udid {
			d, found = e, true
			break
		}
	}
	if !found {
		return fmt.Errorf("phone not listed")
	}
	conn, err := ios.ConnectToService(d, "com.apple.mobile.heartbeat")
	if err != nil {
		return fmt.Errorf("start heartbeat: %w", err)
	}
	defer conn.Close()
	codec := ios.NewPlistCodec()
	polo, _ := codec.Encode(map[string]any{"Command": "Polo"})
	first := true
	for {
		b, err := codec.Decode(conn.Reader())
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		var m map[string]any
		if _, err := plist.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("decode: %w", err)
		}
		if m["Command"] != "Marco" {
			// SleepyTime and anything else: the phone is going away; reopen when it comes back.
			return fmt.Errorf("phone sent %v", m["Command"])
		}
		if err := conn.Send(polo); err != nil {
			return fmt.Errorf("send: %w", err)
		}
		if first {
			logLine("heartbeat_up", "interval", m["Interval"])
			first = false
		}
	}
}

func main() {
	udid := ""
	if len(os.Args) > 1 {
		udid = os.Args[1]
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() { <-signals; logLine("stopped"); os.Exit(0) }()
	for {
		err := session(udid)
		logLine("heartbeat_down", "error", err.Error())
		time.Sleep(3 * time.Second)
	}
}
