package httpserver

import (
	"sync"
	"time"
)

// rateLimiter allows at most limit events per key within a fixed window.
// It is in-memory, which fits a single-process server.
type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]*rlEntry
	now     func() time.Time
	lastGC  time.Time
}

type rlEntry struct {
	count int
	start time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, entries: map[string]*rlEntry{}, now: time.Now}
}

// Allow records an event for key and reports whether it is within the limit.
func (l *rateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.gc(now)
	e, ok := l.entries[key]
	if !ok || now.Sub(e.start) >= l.window {
		l.entries[key] = &rlEntry{count: 1, start: now}
		return true
	}
	e.count++
	return e.count <= l.limit
}

// Blocked reports whether key is over the limit, without recording an event.
func (l *rateLimiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	return ok && l.now().Sub(e.start) < l.window && e.count >= l.limit
}

// Reset forgets key, e.g. after a successful login.
func (l *rateLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func (l *rateLimiter) gc(now time.Time) {
	if now.Sub(l.lastGC) < l.window {
		return
	}
	l.lastGC = now
	for k, e := range l.entries {
		if now.Sub(e.start) >= l.window {
			delete(l.entries, k)
		}
	}
}
