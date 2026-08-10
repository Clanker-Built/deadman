package webui

import (
	"sync"
	"testing"

	"github.com/google/uuid"
)

// TestPendingStoreConcurrent hammers the store from parallel goroutines so
// `go test -race` proves the mutex guards the map. A bare map here previously
// crashed the whole server ("fatal error: concurrent map writes") when two
// TOTP-setup requests raced.
func TestPendingStoreConcurrent(t *testing.T) {
	t.Parallel()
	p := newPendingStore()
	ids := make([]uuid.UUID, 8)
	for i := range ids {
		ids[i] = uuid.New()
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				id := ids[(i+j)%len(ids)]
				p.put(&pendingTOTP{UserID: id})
				_ = p.get(id)
				p.drop(id)
			}
		}(i)
	}
	wg.Wait()
}
