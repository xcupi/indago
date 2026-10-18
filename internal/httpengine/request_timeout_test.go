package httpengine_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/indago/indago/internal/httpengine"
)

// Request.Timeout bounds one Do call's own I/O and is classified as a timeout.
func TestRequestTimeoutBoundsOneCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()
	cfg := httpengine.DefaultConfig()
	cfg.FollowRedirects = false
	c, err := httpengine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	start := time.Now()
	_, err = c.Do(t.Context(), &httpengine.Request{Method: "GET", URL: srv.URL, Timeout: 50 * time.Millisecond})
	var ne net.Error
	isTimeout := errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
	if !isTimeout {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Fatalf("request ran %v before failing; Timeout must cut it short", d)
	}
}
