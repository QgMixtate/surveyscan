// Package retry ограничивает повторные исходящие запросы при недоступности узла.
package retry

import (
	"math/rand/v2"
	"time"
)

type Backoff struct {
	attempts uint
	next     time.Time
}

func (b *Backoff) Ready(now time.Time) bool { return !now.Before(b.next) }
func (b *Backoff) Failed(now time.Time) {
	if b.attempts < 7 {
		b.attempts++
	}
	seconds := 1 << uint(b.attempts-1)
	if seconds > 60 {
		seconds = 60
	}
	jitter := .75 + rand.Float64()*.5
	b.next = now.Add(time.Duration(float64(time.Duration(seconds)*time.Second) * jitter))
}
func (b *Backoff) Reset() { b.attempts = 0; b.next = time.Time{} }
