package web

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Internal tests for the per-IP token bucket. They drive an injected clock so
// refill, Retry-After, and idle eviction are exact rather than timing-dependent.

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func TestRateLimiterBurstRefillAndRetryAfter(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	l := newRateLimiter(2, 4, clk.now) // 2 tokens/s, bucket of 4

	for i := 0; i < 4; i++ {
		if d := l.allow("10.0.0.1"); !d.Allowed {
			t.Fatalf("burst request %d refused", i+1)
		}
	}
	d := l.allow("10.0.0.1")
	if d.Allowed {
		t.Fatal("5th request inside one instant must be refused")
	}
	if d.RetryAfterSec != 1 {
		t.Fatalf("Retry-After = %d s, want 1 (0.5 s needed, rounded up, never < 1)", d.RetryAfterSec)
	}
	if !d.StartOfBurst {
		t.Fatal("first refusal of a burst must be marked StartOfBurst (the Info-log trigger)")
	}
	if d2 := l.allow("10.0.0.1"); d2.Allowed || d2.StartOfBurst {
		t.Fatalf("second refusal in the same burst: allowed=%v startOfBurst=%v, want false/false", d2.Allowed, d2.StartOfBurst)
	}

	clk.t = clk.t.Add(500 * time.Millisecond) // refills exactly one token
	if d := l.allow("10.0.0.1"); !d.Allowed {
		t.Fatal("one token should have refilled after 500 ms at 2 rps")
	}
	if d := l.allow("10.0.0.1"); d.Allowed {
		t.Fatal("only one token refilled; the next request must be refused")
	}

	// Clients are independent.
	if d := l.allow("10.0.0.2"); !d.Allowed {
		t.Fatal("a different client must have its own full bucket")
	}
}

func TestRateLimiterRetryAfterIsWholeSecondsAtLeastOne(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	l := newRateLimiter(0.1, 1, clk.now) // one token, then 10 s per token
	l.allow("a")
	d := l.allow("a")
	if d.Allowed || d.RetryAfterSec != 10 {
		t.Fatalf("refused=%v RetryAfterSec=%d, want refused with 10", !d.Allowed, d.RetryAfterSec)
	}
}

func TestRateLimiterEvictsIdleBuckets(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	l := newRateLimiter(2, 4, clk.now)
	l.allow("a")
	l.allow("b")
	if n := l.size(); n != 2 {
		t.Fatalf("size = %d, want 2", n)
	}
	clk.t = clk.t.Add(11 * time.Minute) // both idle > 10 min and full again
	l.allow("c")                        // triggers the sweep
	if n := l.size(); n != 1 {
		t.Fatalf("after idle sweep size = %d, want 1 (only the active client c)", n)
	}
}

func TestRateLimiterSweepsAtMostOncePerMinute(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	l := newRateLimiter(2, 4, clk.now)
	l.allow("a") // first call sweeps
	before := l.sweeps
	clk.t = clk.t.Add(30 * time.Second)
	l.allow("b")
	l.allow("c")
	if l.sweeps != before {
		t.Fatalf("sweep ran %d time(s) within a minute of the last one", l.sweeps-before)
	}
	clk.t = clk.t.Add(31 * time.Second) // now > 1 minute since the last sweep
	l.allow("d")
	if l.sweeps != before+1 {
		t.Fatalf("sweeps = %d after a minute, want %d", l.sweeps, before+1)
	}
}

// Eviction must be invisible: a bucket that has not yet refilled to full must
// keep its state, otherwise a client could reset its limit by going quiet.
func TestRateLimiterNeverEvictsBucketThatIsNotFullYet(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	l := newRateLimiter(0.001, 4, clk.now) // full again only after 4000 s
	for i := 0; i < 4; i++ {
		l.allow("slow")
	}
	clk.t = clk.t.Add(11 * time.Minute) // 660 s: idle past the 10-minute floor, still empty
	l.allow("other")
	if d := l.allow("slow"); d.Allowed {
		t.Fatal("eviction reset a bucket that had not refilled: client regained its burst early")
	}
}

func TestRateLimiterCapFailsClosedForNewClients(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	l := newRateLimiter(2, 4, clk.now)
	l.maxKeys = 2
	l.allow("a")
	l.allow("b")
	d := l.allow("c")
	if d.Allowed {
		t.Fatal("a new client must be refused when the bucket table is full and nothing is evictable")
	}
	if d.RetryAfterSec < 1 {
		t.Fatalf("Retry-After = %d at cap, want >= 1", d.RetryAfterSec)
	}
	if n := l.size(); n != 2 {
		t.Fatalf("refused client was tracked anyway: size = %d", n)
	}
	if d := l.allow("a"); !d.Allowed {
		t.Fatal("existing clients must keep working at cap")
	}
	clk.t = clk.t.Add(11 * time.Minute) // a and b are now evictable
	if d := l.allow("c"); !d.Allowed {
		t.Fatal("after idle eviction a new client must be admitted again")
	}
}

func TestClientKeyUsesRemoteAddrHostOnly(t *testing.T) {
	cases := map[string]string{
		"192.0.2.10:5000":   "192.0.2.10",
		"[2001:db8::1]:443": "2001:db8::1",
		"192.0.2.10":        "192.0.2.10",
	}
	for in, want := range cases {
		if got := clientKey(in); got != want {
			t.Errorf("clientKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEscapeLabelValue(t *testing.T) {
	got := escapeLabelValue("GET /api/x\"y\\z\nw")
	want := `GET /api/x\"y\\z\nw`
	if got != want || strings.ContainsAny(got, "\n") {
		t.Fatalf("escapeLabelValue = %q, want %q", got, want)
	}
}

func TestStatusRecorderForwardsFlush(t *testing.T) {
	inner := &flushSpy{}
	rw := &statusRecorder{ResponseWriter: inner}
	rw.Flush()
	if !inner.flushed {
		t.Fatal("statusRecorder must forward Flush so streaming endpoints keep working")
	}
}

type flushSpy struct {
	headers http.Header
	flushed bool
}

func (f *flushSpy) Header() http.Header {
	if f.headers == nil {
		f.headers = http.Header{}
	}
	return f.headers
}
func (f *flushSpy) Write(b []byte) (int, error) { return len(b), nil }
func (f *flushSpy) WriteHeader(int)             {}
func (f *flushSpy) Flush()                      { f.flushed = true }
