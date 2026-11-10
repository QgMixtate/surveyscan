// Package presence — присутствие, пропажа и возвращение объектов по проходам обнаружения (C21).
// Отсутствие доказательства ≠ пропажа: пропуск засчитывается только полным успешным проходом источника,
// который мог бы увидеть объект; неполный/упавший проход состояние не меняет. Heartbeat агента, свежесть
// данных и бизнес-состояние — отдельные сущности и сюда не входят.
package presence

import (
	"sort"
	"time"
)

type State string

const (
	Present State = "present"
	Missing State = "missing"
)

type EventKind string

const (
	Appeared EventKind = "appeared"
	Gone     EventKind = "missing"
	Returned EventKind = "returned"
)

type Event struct {
	Key  string
	Kind EventKind
	At   time.Time
}

type Entity struct {
	Key       string
	State     State
	FirstSeen time.Time
	LastSeen  time.Time
	Misses    int      // подряд засчитанные пропуски
	Sources   []string // источники, видевшие объект в последний раз
	Returns   int
}

// Pass — один проход источника. Complete=false (ошибка, таймаут, частичный ответ) не даёт права считать пропуск.
// Covers — ключи, которые этот проход вообще мог увидеть (например, хосты scope этого прохода); пусто = все известные.
type Pass struct {
	Source   string
	At       time.Time
	Complete bool
	Seen     []string
	Covers   func(key string) bool
}

type Tracker struct {
	MissAfter int // подряд полных проходов без наблюдения до «missing» (по умолчанию 3)
	entities  map[string]*Entity
}

func New(missAfter int) *Tracker {
	if missAfter <= 0 {
		missAfter = 3
	}
	return &Tracker{MissAfter: missAfter, entities: map[string]*Entity{}}
}

// Apply применяет проход и возвращает события. Порядок событий детерминирован (по ключу).
func (t *Tracker) Apply(p Pass) []Event {
	events := []Event{}
	seen := map[string]bool{}
	for _, k := range p.Seen {
		seen[k] = true
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := t.entities[k]
		switch {
		case e == nil:
			t.entities[k] = &Entity{Key: k, State: Present, FirstSeen: p.At, LastSeen: p.At, Sources: []string{p.Source}}
			events = append(events, Event{k, Appeared, p.At})
		case e.State == Missing:
			e.State, e.Misses, e.Returns = Present, 0, e.Returns+1
			events = append(events, Event{k, Returned, p.At})
			fallthrough
		default:
			if p.At.After(e.LastSeen) {
				e.LastSeen = p.At
			}
			e.Misses = 0
			e.Sources = []string{p.Source}
		}
	}
	if !p.Complete {
		return events // нет права засчитывать пропуски
	}
	all := make([]string, 0, len(t.entities))
	for k := range t.entities {
		all = append(all, k)
	}
	sort.Strings(all)
	for _, k := range all {
		e := t.entities[k]
		if seen[k] || e.State == Missing || !contains(e.Sources, p.Source) || (p.Covers != nil && !p.Covers(k)) {
			continue
		}
		e.Misses++
		if e.Misses >= t.MissAfter {
			e.State = Missing
			events = append(events, Event{k, Gone, p.At})
		}
	}
	return events
}

func (t *Tracker) Get(key string) (Entity, bool) {
	e, ok := t.entities[key]
	if !ok {
		return Entity{}, false
	}
	return *e, true
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
