package inventory

import (
	"testing"
	"time"
)

func TestSequenceAndCrossSourceProjectionOrder(t *testing.T) {
	now := time.Now()
	old := rank{Source: "a", Generation: "one", Record: "r", Sequence: "18446744073709551614", Clock: "trusted", Priority: 2, Collected: now}
	next := old
	next.Sequence = "18446744073709551615"
	next.Collected = now.Add(-time.Hour)
	if !Newer(next, old) {
		t.Fatal("uint64 sequence must beat regressed wall clock")
	}
	next.Generation = "two"
	if Newer(next, old) {
		t.Fatal("new generation bypassed continuity")
	}
	next = old
	next.Source = "b"
	next.Priority = 1
	next.Collected = now.Add(time.Hour)
	if Newer(next, old) {
		t.Fatal("low-priority source won")
	}
	next.Priority = 3
	next.Clock = "unknown"
	if Newer(next, old) {
		t.Fatal("untrusted timestamp won")
	}
	next.Clock = "trusted"
	if !Newer(next, old) {
		t.Fatal("trusted high-priority source did not win")
	}
	next.Priority = 2
	next.Collected = now
	if Newer(next, old) {
		t.Fatal("equal cross-source rank depended on arrival")
	}
}
