package zdas

import (
	"sync"
	"time"
)

// summaryLog gathers events into a summary of type S and writes it at most
// once per interval, so a flood can't fill the log but can't hide in it
// either. The first event after a quiet interval is written at once. Events
// within the interval are added to the summary, which a timer writes when
// the interval ends, so the end of a flood is written too.
//
// write is called without the lock held, so a slow log sink holds up only
// the caller or timer writing a summary, at most one per interval, and never
// the other callers recording events. A sink that serializes its own writes,
// as slog's handlers do, still holds up everything else that logs through it.
type summaryLog[S any] struct {
	interval time.Duration
	write    func(S)

	mu      sync.Mutex
	pending S
	events  bool        // whether pending holds any
	last    time.Time   // when the last summary was written
	timer   *time.Timer // writes pending when the interval ends; nil when none is set
	stopped bool        // set by stop; events after it are written at once
}

// record applies update to the pending summary. It writes the summary when
// the interval since the last one has passed, or after stop, and otherwise
// sets a timer to write it when the interval ends.
func (l *summaryLog[S]) record(update func(*S)) {
	l.mu.Lock()
	update(&l.pending)
	l.events = true
	now := time.Now()
	// After stop no timer is set, so every event is written at once.
	if wait := l.interval - now.Sub(l.last); !l.last.IsZero() && wait > 0 && !l.stopped {
		if l.timer == nil {
			l.timer = time.AfterFunc(wait, l.flush)
		}
		l.mu.Unlock()
		return
	}
	s := l.take(now)
	l.mu.Unlock()
	l.write(s)
}

// flush writes the pending summary when it holds events and the interval
// since the last one has passed. With events pending but the interval not
// yet over, as when record wrote a summary while the timer was due, it sets
// the timer again for the end of the interval.
func (l *summaryLog[S]) flush() {
	l.mu.Lock()
	l.timer = nil
	// A timer that fired as stop ran can get here after it; record writes
	// whatever came since.
	if !l.events || l.stopped {
		l.mu.Unlock()
		return
	}
	now := time.Now()
	if wait := l.interval - now.Sub(l.last); wait > 0 {
		l.timer = time.AfterFunc(wait, l.flush)
		l.mu.Unlock()
		return
	}
	s := l.take(now)
	l.mu.Unlock()
	l.write(s)
}

// stop cancels the timer and writes any pending summary. Events recorded
// after it are written at once, since no timer outlives it. It may be called
// more than once.
func (l *summaryLog[S]) stop() {
	l.mu.Lock()
	l.stopped = true
	if l.timer != nil {
		l.timer.Stop()
		l.timer = nil
	}
	if !l.events {
		l.mu.Unlock()
		return
	}
	s := l.take(time.Now())
	l.mu.Unlock()
	l.write(s)
}

// take returns the pending summary and starts a new one. l.mu must be held.
func (l *summaryLog[S]) take(now time.Time) S {
	s := l.pending
	var zero S
	l.pending, l.events, l.last = zero, false, now
	return s
}
