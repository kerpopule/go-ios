// coagent-wifilockdown: read (and, only when the owner has said yes, change) the one phone setting
// that decides whether this Mac may reach the phone's lockdown service over the network.
//
// WHY THIS EXISTS (2026-09-22). Steve wants phone control with no cable. The LAN transport
// (lanmux.py) proved that go-ios reaches the phone's lockdownd over Wi-Fi at 192.168.1.191:62078 —
// and that lockdownd then resets the connection before answering even an identity-free QueryType.
// The phone's com.apple.mobile.wireless_lockdown domain has NO EnableWifiConnections key, and the
// phone does not advertise _apple-mobdev2._tcp: the classic Wi-Fi-sync gate is closed. That key is
// exactly what Finder's "Show this iPhone when on Wi-Fi" checkbox writes.
//
// It can only be changed over a lockdown session, and a lockdown session over the network is the
// very thing the gate refuses — so it can only be changed while the phone is on the CABLE. This tool
// therefore refuses to run against anything but a USB row from Apple's own usbmuxd.
//
// Changing it is the OWNER'S decision, not a tool's: `read` is the default and changes nothing.
//
//	coagent-wifilockdown [read]      print the domain's current values (JSON)
//	coagent-wifilockdown enable      set EnableWifiConnections=true, then read it back
//	coagent-wifilockdown disable     set EnableWifiConnections=false, then read it back (the revert)
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/danielpaulus/go-ios/ios"
)

const (
	domain = "com.apple.mobile.wireless_lockdown"
	key    = "EnableWifiConnections"
)

func fail(reason string, err error) {
	out := map[string]any{"ok": false, "reason": reason}
	if err != nil {
		out["error"] = err.Error()
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
	os.Exit(1)
}

// usbDevice returns the phone's USB row from Apple's usbmuxd. A LAN or Network row is refused: the
// setting cannot be changed over the network (that is the gate itself), and a tool that silently
// took whatever row came first would be lying about which road it used.
func usbDevice() ios.DeviceEntry {
	if os.Getenv("USBMUXD_SOCKET_ADDRESS") != "" {
		fail("refusing: USBMUXD_SOCKET_ADDRESS is set; this tool only talks to Apple's usbmuxd over the cable", nil)
	}
	list, err := ios.ListDevices()
	if err != nil {
		fail("phone_usbmuxd_unreachable", err)
	}
	for _, d := range list.DeviceList {
		if d.Properties.ConnectionType == "USB" {
			return d
		}
	}
	fail("phone_not_on_usb: this setting can only be read or changed while the phone is on the cable", nil)
	return ios.DeviceEntry{}
}

func readDomain(d ios.DeviceEntry) map[string]any {
	c, err := ios.ConnectLockdownWithSession(d)
	if err != nil {
		fail("phone_lockdown_refused", err)
	}
	defer c.Close()
	v, err := c.GetValueForDomain("", domain)
	if err != nil {
		fail("phone_lockdown_read_failed", err)
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		fail(fmt.Sprintf("unexpected %s shape %T", domain, v), nil)
	}
	// BonjourFullServiceName carries the phone's private Wi-Fi MAC; report only whether it exists.
	if _, has := m["BonjourFullServiceName"]; has {
		m["BonjourFullServiceName"] = "(present)"
	}
	return m
}

func setKey(d ios.DeviceEntry, value bool) {
	c, err := ios.ConnectLockdownWithSession(d)
	if err != nil {
		fail("phone_lockdown_refused", err)
	}
	defer c.Close()
	if err := c.SetValueForDomain(key, domain, value); err != nil {
		fail("phone_lockdown_write_failed", err)
	}
}

func main() {
	cmd := "read"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	d := usbDevice()
	out := map[string]any{"udid": d.Properties.SerialNumber, "connection": d.Properties.ConnectionType, "domain": domain}
	switch cmd {
	case "read":
		out["values"] = readDomain(d)
	case "enable", "disable":
		out["before"] = readDomain(d)
		setKey(d, cmd == "enable")
		out["after"] = readDomain(d)
		out["changed"] = key
	default:
		fail("usage: coagent-wifilockdown [read|enable|disable]", nil)
	}
	out["ok"] = true
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
