package playwright

import (
	"sync"
	"testing"
)

// First-navigation request callbacks run concurrently with page publication.
// The writer uses the same frame mutex as newPage/onFrameAttached; all three
// request-facing accessors must accept the not-yet-published state safely.
func TestEarlyFramePagePublicationReaders(t *testing.T) {
	frame := &frameImpl{}
	request := &requestImpl{}
	request.initializer = map[string]any{"frame": &channel{object: frame}}
	if request.Frame() != nil || request.safePage() != nil {
		t.Fatal("early request unexpectedly has a page")
	}
	page := &pageImpl{closedOrCrashed: make(chan error, 1)}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 10000; i++ {
			frame.Lock()
			frame.page = page
			frame.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 10000; i++ {
			request.Frame()
			frame.Page()
			if p := request.safePage(); p != nil && p.closedOrCrashed == nil {
				t.Error("partially initialized page published")
				return
			}
		}
	}()
	close(start)
	wg.Wait()
	if request.Frame() != frame || request.safePage() != page || frame.Page() != page {
		t.Fatal("published page not visible")
	}
}
