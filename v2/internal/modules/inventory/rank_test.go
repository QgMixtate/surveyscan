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

// C26, решение 3А: более приоритетный источник главнее, пока его данные не старше более свежих на порог.
func TestPriorityStaleness(t *testing.T) {
	now := time.Now()
	agent := rank{Source: "agent", Generation: "g", Record: "r", Sequence: "5", Clock: "trusted", Priority: 3, Collected: now.Add(-48 * time.Hour)}
	ssh := rank{Source: "ssh", Generation: "g", Record: "s", Sequence: "9", Clock: "trusted", Priority: 2, Collected: now}
	if !Newer(ssh, agent) {
		t.Fatal("fresh lower-priority data must beat stale higher-priority data")
	}
	if Newer(agent, ssh) {
		t.Fatal("late delivery of stale agent data must not take the card back")
	}
	agent.Collected = now.Add(-time.Hour)
	if Newer(ssh, agent) || !Newer(agent, ssh) {
		t.Fatal("within the threshold priority decides")
	}
	ssh.Clock = "estimated"
	agent.Collected = now.Add(-48 * time.Hour)
	if Newer(ssh, agent) {
		t.Fatal("untrusted clock never wins on staleness")
	}
	ssh.Clock = "trusted"
	SetPriorityStaleAfter(0)
	defer SetPriorityStaleAfter(DefaultPriorityStaleAfter)
	if Newer(ssh, agent) {
		t.Fatal("threshold 0 restores pure priority")
	}
}
