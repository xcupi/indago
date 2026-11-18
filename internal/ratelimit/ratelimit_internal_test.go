package ratelimit

import (
	"context"
	"testing"
	"time"
)

// Spacing must be measured between ACTUAL grants. A late grant (scheduler
// pressure, -race overhead) leaves the reservation plan already due while the
// real grant has only just happened, so the next permit may not be granted for
// another full interval — otherwise the permits queued behind it burst to catch
// up with a plan that no longer describes reality.
func TestWaitSpacesFromTheLastActualGrant(t *testing.T) {
	const interval = 20 * time.Millisecond
	l := New(50) // 20ms
	if err := l.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Pose the state a late grant leaves behind: the plan says the next permit
	// is due now, but the last actual grant is a full interval away.
	l.mu.Lock()
	now := time.Now()
	l.next = now
	l.floor = now.Add(interval)
	l.mu.Unlock()

	start := time.Now()
	if err := l.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gap := time.Since(start); gap < interval-time.Millisecond {
		t.Fatalf("permit granted %v after the last actual grant, want >= %v", gap, interval)
	}
}

// The same rule applies when the floor moves while a permit is already reserved
// and asleep: the wake must re-check the spacing and go back to sleep instead of
// granting early because its own slot has arrived.
func TestWaitRearmsWhenTheFloorMovesPastItsSlot(t *testing.T) {
	l := New(5) // 200ms interval
	if err := l.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan time.Time, 1)
	go func() {
		if err := l.Wait(context.Background()); err != nil {
			t.Error(err)
		}
		done <- time.Now()
	}()
	// Let the waiter reserve its 200ms slot and fall asleep, then move the floor
	// past it — what a concurrent grant landing a full step late leaves behind.
	time.Sleep(20 * time.Millisecond)
	l.mu.Lock()
	floor := time.Now().Add(400 * time.Millisecond)
	l.floor = floor
	l.mu.Unlock()

	select {
	case at := <-done:
		if at.Before(floor) {
			t.Fatalf("permit granted %v before the spacing floor", floor.Sub(at))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter never returned")
	}
}
