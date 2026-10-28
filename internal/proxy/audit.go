package proxy

import (
	"slices"
	"sync"
	"time"
)

// Entry is one proxied (or denied) request. It never contains keys or bodies.
type Entry struct {
	Time     time.Time
	Client   string
	IP       string
	Method   string
	Path     string
	Status   int
	Allowed  bool
	Reason   string
	Duration time.Duration
}

// Audit keeps the latest requests in memory for the admin ui.
type Audit struct {
	mu      sync.Mutex
	size    int
	entries []Entry
}

// NewAudit creates a ring buffer for size entries.
func NewAudit(size int) *Audit { return &Audit{size: size} }

// Add appends an entry and drops the oldest one when full.
func (a *Audit) Add(e Entry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	if len(a.entries) > a.size {
		a.entries = slices.Delete(a.entries, 0, len(a.entries)-a.size)
	}
}

// Latest returns the entries, newest first.
func (a *Audit) Latest() []Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := slices.Clone(a.entries)
	slices.Reverse(out)
	return out
}
