package presence

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)

func pass(src string, n int, complete bool, seen ...string) Pass {
	return Pass{Source: src, At: t0.Add(time.Duration(n) * time.Minute), Complete: complete, Seen: seen}
}

func kinds(ev []Event) []EventKind {
	out := []EventKind{}
	for _, e := range ev {
		out = append(out, e.Kind)
	}
	return out
}

func TestAppearMissingReturned(t *testing.T) {
	tr := New(3)
	if k := kinds(tr.Apply(pass("scan", 0, true, "a", "b"))); len(k) != 2 || k[0] != Appeared {
		t.Fatal(k)
	}
	for i := 1; i <= 2; i++ { // два полных пропуска — ещё не «пропал»
		if ev := tr.Apply(pass("scan", i, true, "a")); len(ev) != 0 {
			t.Fatal("too early:", ev)
		}
	}
	ev := tr.Apply(pass("scan", 3, true, "a"))
	if len(ev) != 1 || ev[0].Key != "b" || ev[0].Kind != Gone {
		t.Fatal(ev)
	}
	if e, _ := tr.Get("b"); e.State != Missing || e.Misses != 3 {
		t.Fatal(e)
	}
	if ev = tr.Apply(pass("scan", 4, true, "a")); len(ev) != 0 {
		t.Fatal("missing must not repeat:", ev)
	}
	ev = tr.Apply(pass("scan", 5, true, "a", "b"))
	if len(ev) != 1 || ev[0].Kind != Returned {
		t.Fatal(ev)
	}
	if e, _ := tr.Get("b"); e.State != Present || e.Returns != 1 || e.Misses != 0 || !e.FirstSeen.Equal(t0) {
		t.Fatal("history must survive return:", e)
	}
}

func TestIncompletePassNeverCountsAsAbsence(t *testing.T) {
	tr := New(2)
	tr.Apply(pass("scan", 0, true, "a"))
	for i := 1; i <= 5; i++ {
		tr.Apply(pass("scan", i, false)) // источник упал/таймаут
	}
	if e, _ := tr.Get("a"); e.State != Present || e.Misses != 0 {
		t.Fatal("failed source must not make hosts missing:", e)
	}
}

func TestOnlyCoveringSourceCanDeclareAbsence(t *testing.T) {
	tr := New(1)
	tr.Apply(pass("arp", 0, true, "a"))
	tr.Apply(pass("dhcp", 1, true, "b"))
	// проход dhcp не видел «a», но «a» наблюдал arp — это не повод считать a пропавшим
	if ev := tr.Apply(pass("dhcp", 2, true, "b")); len(ev) != 0 {
		t.Fatal(ev)
	}
	// Covers ограничивает проход подсетью
	p := pass("arp", 3, true)
	p.Covers = func(k string) bool { return k != "a" }
	if ev := tr.Apply(p); len(ev) != 0 {
		t.Fatal("key outside coverage must not be counted:", ev)
	}
	if ev := tr.Apply(pass("arp", 4, true)); len(ev) != 1 || ev[0].Key != "a" {
		t.Fatal(ev)
	}
}
