package service

import (
	"encoding/hex"
	"testing"
)

func Test_MACHex2Bytes(t *testing.T) {
	mac := "2a:1b:4c:fe:a9:e9"
	if res, err := MACHex2Bytes(mac); err != nil {
		t.FailNow()
	} else {
		t.Logf("res: %v, hex: %s", res, hex.EncodeToString(res))
	}
}
