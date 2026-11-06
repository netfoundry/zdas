package zdas

import (
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// logBuffer is a log sink that a summaryLog's timer can write to while a
// test reads it.
type logBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *logBuffer) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b.Reset()
}

// summaries collects what a summaryLog of event counts writes, and when.
type summaries struct {
	mu sync.Mutex
	ns []int
	at []time.Time
}

func (s *summaries) write(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ns = append(s.ns, n)
	s.at = append(s.at, time.Now())
}

func (s *summaries) times() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.at...)
}

func (s *summaries) get() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int(nil), s.ns...)
}

// testSummaryLog returns a summaryLog of event counts and what it writes.
func testSummaryLog(interval time.Duration) (*summaryLog[int], *summaries) {
	written := &summaries{}
	return &summaryLog[int]{interval: interval, write: written.write}, written
}

func count(n *int) { *n++ }

// TestSummaryLogWritesFirstEventAtOnce verifies that the first event, and the
// first after a quiet interval, is written at once.
func TestSummaryLogWritesFirstEventAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, written := testSummaryLog(time.Minute)
		l.record(count)
		if len(written.get()) != 1 || written.get()[0] != 1 {
			t.Fatalf("written = %v, want [1]", written.get())
		}
		time.Sleep(2 * time.Minute)
		l.record(count)
		if len(written.get()) != 2 || written.get()[1] != 1 {
			t.Errorf("written after a quiet interval = %v, want [1 1]", written.get())
		}
	})
}

// TestSummaryLogWritesTheTail verifies that events within the interval are
// written when it ends, with no later event to trigger it, and that nothing
// is written for an interval without events.
func TestSummaryLogWritesTheTail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, written := testSummaryLog(time.Minute)
		l.record(count)
		l.record(count)
		l.record(count)
		time.Sleep(time.Minute - time.Second)
		synctest.Wait()
		if len(written.get()) != 1 {
			t.Fatalf("written before the interval ended = %v, want [1]", written.get())
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if len(written.get()) != 2 || written.get()[1] != 2 {
			t.Fatalf("written at the end of the interval = %v, want [1 2]", written.get())
		}
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		if len(written.get()) != 2 {
			t.Errorf("written with no events = %v, want [1 2]", written.get())
		}
	})
}

// TestSummaryLogOncePerInterval verifies that a steady stream of events is
// written once per interval for as long as it lasts, not only when it stops,
// and that every event is counted once.
func TestSummaryLogOncePerInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, written := testSummaryLog(time.Minute)
		start := time.Now()
		events := 0
		// Every 7s for 5 minutes, so no event shares an instant with a timer.
		for time.Since(start) < 5*time.Minute {
			l.record(count)
			events++
			time.Sleep(7 * time.Second)
			synctest.Wait()
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		at := written.times()
		if len(at) != 6 {
			t.Fatalf("%d summaries for 5 minutes of events, want 6 (one at once, then one a minute): %v", len(at), written.get())
		}
		for i := 1; i < len(at); i++ {
			if gap := at[i].Sub(at[i-1]); gap != time.Minute {
				t.Errorf("summary %d came %v after the one before, want 1m", i, gap)
			}
		}
		total := 0
		for _, n := range written.get() {
			total += n
		}
		if total != events {
			t.Errorf("summaries count %d events, want %d: %v", total, events, written.get())
		}
	})
}

// TestSummaryLogAfterATimerWrite verifies that an event soon after the
// timer wrote a summary waits for the next interval.
func TestSummaryLogAfterATimerWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, written := testSummaryLog(time.Minute)
		l.record(count)
		time.Sleep(30 * time.Second)
		l.record(count)
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if got := written.get(); len(got) != 2 {
			t.Fatalf("written at the end of the first interval = %v, want [1 1]", got)
		}
		time.Sleep(30 * time.Second)
		l.record(count)
		if got := written.get(); len(got) != 2 {
			t.Errorf("an event 30s after the timer's summary was written at once: %v", got)
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if got := written.get(); len(got) != 3 {
			t.Errorf("written at the end of the second interval = %v, want [1 1 1]", got)
		}
	})
}

// TestSummaryLogAtTheIntervalEdge verifies that an event exactly one
// interval after the last summary is written at once.
func TestSummaryLogAtTheIntervalEdge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, written := testSummaryLog(time.Minute)
		l.record(count)
		time.Sleep(time.Minute)
		l.record(count)
		if got := written.get(); len(got) != 2 {
			t.Fatalf("an event at the interval's end = %v, want [1 1] at once", got)
		}
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		if got := written.get(); len(got) != 2 {
			t.Errorf("written with no events since = %v, want [1 1]", got)
		}
	})
}

// TestSummaryLogConcurrentRecords verifies that events recorded at once from
// many goroutines are each counted once.
func TestSummaryLogConcurrentRecords(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, written := testSummaryLog(time.Minute)
		var wg sync.WaitGroup
		for range 50 {
			wg.Go(func() {
				for range 20 {
					l.record(count)
				}
			})
		}
		wg.Wait()
		time.Sleep(time.Minute)
		synctest.Wait()
		got := written.get()
		total := 0
		for _, n := range got {
			total += n
		}
		if total != 1000 || len(got) != 2 {
			t.Errorf("summaries = %v (total %d), want 2 summing to 1000", got, total)
		}
	})
}

// TestSummaryLogStop verifies that stop writes what is pending at once,
// cancels the timer, and may be called more than once.
func TestSummaryLogStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, written := testSummaryLog(time.Minute)
		l.record(count)
		l.record(count)
		l.record(count)
		l.stop()
		if got := written.get(); len(got) != 2 || got[1] != 2 {
			t.Fatalf("written by stop = %v, want [1 2]", got)
		}
		l.stop()
		// An event after stop, within the interval, is written at once and
		// sets no timer, which would keep the log's owner reachable until
		// it fired.
		l.record(count)
		l.mu.Lock()
		armed := l.timer != nil
		l.mu.Unlock()
		if armed {
			t.Error("record set a timer after stop")
		}
		if got := written.get(); len(got) != 3 || got[2] != 1 {
			t.Errorf("written for an event after stop = %v, want [1 2 1] at once", got)
		}
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		if got := written.get(); len(got) != 3 {
			t.Errorf("written after stop = %v, want [1 2 1]", got)
		}
	})
}

// TestSummaryLogWritesWithoutTheLock verifies that a log sink that blocks
// holds up only the goroutine writing to it, not other callers recording
// events. It runs outside a synctest bubble, which doesn't count a goroutine
// waiting for a mutex as blocked.
func TestSummaryLogWritesWithoutTheLock(t *testing.T) {
	writing, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	l := &summaryLog[int]{interval: time.Minute, write: func(int) {
		once.Do(func() { close(writing) })
		<-release
	}}
	t.Cleanup(l.stop) // runs after release is closed; leaves no timer behind
	defer close(release)
	go l.record(count) // writes the first summary, and blocks in the sink
	<-writing
	recorded := make(chan struct{})
	go func() {
		l.record(count)
		close(recorded)
	}()
	select {
	case <-recorded:
	case <-time.After(5 * time.Second):
		t.Error("record blocked behind a write in progress")
	}
}

// TestSummaryLogLateFlush verifies that a timer firing after record has
// already written the summary, as one can when the two race at the end of
// the interval, writes nothing empty and nothing early.
func TestSummaryLogLateFlush(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, written := testSummaryLog(time.Minute)
		l.record(count)
		l.flush()
		l.mu.Lock()
		armed := l.timer != nil
		l.mu.Unlock()
		if got := written.get(); len(got) != 1 || armed {
			t.Fatalf("after a flush with nothing pending: written %v, timer set %v; want [1] and no timer", got, armed)
		}
		l.record(count)
		// As if the timer record set had fired early: stop it, and flush.
		l.mu.Lock()
		l.timer.Stop()
		l.mu.Unlock()
		l.flush()
		if got := written.get(); len(got) != 1 {
			t.Fatalf("written by a flush within the interval = %v, want [1]", got)
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if got := written.get(); len(got) != 2 || got[1] != 1 {
			t.Errorf("written at the end of the interval = %v, want [1 1]", got)
		}
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		if got := written.get(); len(got) != 2 {
			t.Errorf("written once the events stopped = %v, want [1 1]", got)
		}
	})
}
