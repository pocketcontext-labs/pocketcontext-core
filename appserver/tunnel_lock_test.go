package appserver

import "testing"

func TestTunnelLockPreventsConcurrentRotation(t *testing.T) {
	p := &Project{rt: testRT, Cache: t.TempDir()}
	release, err := AcquireTunnelLock(p.Cache)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := AcquireTunnelLock(p.Cache); err == nil {
		second()
		release()
		t.Fatal("a second tunnel acquired the lock")
	}
	release()
	release, err = AcquireTunnelLock(p.Cache)
	if err != nil {
		t.Fatal(err)
	}
	release()
}
