package tunnel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios"
)

func TestConnectToTunnelOverRemotePairingAtRejectsBadAddress(t *testing.T) {
	for _, address := range []string{"10.71.0.2", "10.71.0.2:port", ""} {
		_, err := ConnectToTunnelOverRemotePairingAt(context.Background(), address, ios.DeviceEntry{}, PairRecordManager{})
		if err == nil || !strings.Contains(err.Error(), "ConnectToTunnelOverRemotePairingAt") {
			t.Fatalf("%q: want a parse error from ConnectToTunnelOverRemotePairingAt, got %v", address, err)
		}
	}
}

func TestVerifyRemotePairingNamesUnreachablePhone(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1: never routable, so the dial fails without touching a real phone.
	err := VerifyRemotePairing("192.0.2.1:49152", 300*time.Millisecond, PairRecordManager{})
	if err == nil || !strings.Contains(err.Error(), "192.0.2.1:49152") {
		t.Fatalf("want a dial error naming the address, got %v", err)
	}
}
