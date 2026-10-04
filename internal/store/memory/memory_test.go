package memory_test

import (
	"testing"

	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/store/storetest"
)

func TestMemoryStoreConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) (store.Store, func()) {
		return memory.New(), func() {}
	})
}
