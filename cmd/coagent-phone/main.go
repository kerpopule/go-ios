// coagent-phone: minimal see/act probe for Co-Agent over CoreDevice (iOS 27+).
// usage: coagent-phone tap <x 0..1> <y 0..1> | swipe <x1> <y1> <x2> <y2>
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/display"
	"github.com/danielpaulus/go-ios/ios/hid"
	"github.com/danielpaulus/go-ios/ios/tunnel"
)

func die(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", msg, err)
		os.Exit(1)
	}
}

func f(s string) float64 {
	v, err := strconv.ParseFloat(s, 64)
	die("bad coordinate "+s, err)
	if v < 0 || v > 1 {
		die("coordinate", fmt.Errorf("%v outside 0..1", v))
	}
	return v
}

func pt(x, y float64) hid.Point { return hid.Point{X: uint16(x * 65535), Y: uint16(y * 65535)} }

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: coagent-phone tap x y | swipe x1 y1 x2 y2")
		os.Exit(2)
	}
	list, err := ios.ListDevices()
	die("list devices", err)
	if len(list.DeviceList) == 0 {
		die("list devices", fmt.Errorf("no device"))
	}
	dev := list.DeviceList[0]
	udid := dev.Properties.SerialNumber
	var info tunnel.Tunnel
	if a := os.Getenv("COAGENT_PHONE_ADDR"); a != "" {
		port, perr := strconv.Atoi(os.Getenv("COAGENT_PHONE_RSD"))
		die("COAGENT_PHONE_RSD", perr)
		info = tunnel.Tunnel{Address: a, RsdPort: port, Udid: udid}
	} else {
		info, err = tunnel.TunnelInfoForDevice(udid, ios.HttpApiHost(), ios.HttpApiPort())
		die("tunnel info (is `sudo ios tunnel start` running?)", err)
	}
	rsd, err := ios.NewWithAddrPortDevice(info.Address, info.RsdPort, dev)
	die("rsd connect", err)
	provider, err := rsd.Handshake()
	rsd.Close()
	die("rsd handshake", err)
	d, err := ios.GetDeviceWithAddress(udid, info.Address, provider)
	die("device with address", err)

	// Touch is silently discarded unless a media stream is up.
	recv, err := display.OpenReceiver(d)
	die("open receiver", err)
	defer recv.Close()
	go func() { buf := make([]byte, 65536); for { if _, e := recv.Read(buf); e != nil { return } } }()
	svc, err := display.New(d)
	die("display service", err)
	defer svc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sid, err := svc.StartVideoStream(ctx, display.VideoStreamRequest{ReceiverIP: recv.IP(), ReceiverPort: recv.Port(), SenderIP: d.Address})
	die("start video stream", err)
	defer svc.StopMediaStream(context.Background(), sid)
	time.Sleep(700 * time.Millisecond)

	s, err := hid.NewSession(d)
	die("hid session", err)
	defer s.Close()
	switch os.Args[1] {
	case "tap":
		p := pt(f(os.Args[2]), f(os.Args[3]))
		die("down", s.TouchDown(p))
		time.Sleep(60 * time.Millisecond)
		die("up", s.TouchUp(p))
	case "swipe":
		x1, y1, x2, y2 := f(os.Args[2]), f(os.Args[3]), f(os.Args[4]), f(os.Args[5])
		for i := 0; i <= 20; i++ {
			t := float64(i) / 20
			die("move", s.TouchDown(pt(x1+(x2-x1)*t, y1+(y2-y1)*t)))
			time.Sleep(12 * time.Millisecond)
		}
		die("up", s.TouchUp(pt(x2, y2)))
	}
	time.Sleep(300 * time.Millisecond)
	fmt.Println("OK", os.Args[1:])
}
