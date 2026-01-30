package util

import (
	"sync"
	"time"

	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/logger"
)

// SimpleExpiredMap is a thread-safe map with TTL expiration
// Optimized for TURN credential storage use case
type SimpleExpiredMap struct {
	mu   sync.RWMutex
	data map[interface{}]*expiredValue
}

type expiredValue struct {
	value      interface{}
	expiration time.Time
}

// NewExpiredMap creates a new TTL map optimized for TURN credentials
func NewExpiredMap() *SimpleExpiredMap {
	return &SimpleExpiredMap{
		data: make(map[interface{}]*expiredValue),
	}
}

// Set adds a key with TTL (in seconds)
func (m *SimpleExpiredMap) Set(key, value interface{}, ttlSeconds int64) {
	if ttlSeconds <= 0 {
		return
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	expiration := time.Now().Add(time.Duration(ttlSeconds) * time.Second)
	m.data[key] = &expiredValue{
		value:      value,
		expiration: expiration,
	}
	
	logger.Debugf("ExpiredMap: Set %v with TTL %d seconds", key, ttlSeconds)
}

// Get retrieves a value if it exists and hasn't expired
func (m *SimpleExpiredMap) Get(key interface{}) (found bool, value interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Check if key exists and hasn't expired
	if ev, exists := m.data[key]; exists {
		if time.Now().After(ev.expiration) {
			// Clean up expired entry
			delete(m.data, key)
			return false, nil
		}
		return true, ev.value
	}
	
	return false, nil
}

// Delete removes a key immediately
func (m *SimpleExpiredMap) Delete(key interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
}

// Remove is an alias for Delete
func (m *SimpleExpiredMap) Remove(key interface{}) {
	m.Delete(key)
}

// Cleanup removes all expired entries
func (m *SimpleExpiredMap) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	now := time.Now()
	for key, ev := range m.data {
		if now.After(ev.expiration) {
			delete(m.data, key)
		}
	}
}

// Length returns the number of non-expired entries
func (m *SimpleExpiredMap) Length() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Only count non-expired entries
	count := 0
	now := time.Now()
	for _, ev := range m.data {
		if !now.After(ev.expiration) {
			count++
		}
	}
	return count
}

// Size is an alias for Length
func (m *SimpleExpiredMap) Size() int {
	return m.Length()
}

// TTL returns remaining seconds until expiration
func (m *SimpleExpiredMap) TTL(key interface{}) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if ev, exists := m.data[key]; exists {
		remaining := time.Until(ev.expiration)
		if remaining <= 0 {
			delete(m.data, key)
			return -1
		}
		return int64(remaining.Seconds())
	}
	return -1
}

// Clear removes all entries
func (m *SimpleExpiredMap) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = make(map[interface{}]*expiredValue)
}

// DoForEach iterates over non-expired entries
func (m *SimpleExpiredMap) DoForEach(handler func(interface{}, interface{})) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	now := time.Now()
	for key, ev := range m.data {
		if !now.After(ev.expiration) {
			handler(key, ev.value)
		}
	}
}