package main

import (
	"crypto/rand"
	"crypto/subtle"
	"sync"
	"time"
)

const attestationChallengeLifetime = 24 * time.Hour

type attestationChallengeManager struct {
	mu        sync.Mutex
	current   []byte
	expiresAt time.Time
}

func newAttestationChallengeManager() *attestationChallengeManager {
	return &attestationChallengeManager{}
}

func (m *attestationChallengeManager) Current(now time.Time) ([]byte, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.current) == 0 || !now.Before(m.expiresAt) {
		m.current = make([]byte, 32)
		if _, err := rand.Read(m.current); err != nil {
			return nil, time.Time{}, err
		}
		m.expiresAt = now.Add(attestationChallengeLifetime)
	}
	return append([]byte(nil), m.current...), m.expiresAt, nil
}

func (m *attestationChallengeManager) Valid(encoded string, now time.Time) bool {
	candidate, err := b64url.DecodeString(encoded)
	if err != nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(candidate) == len(m.current) && now.Before(m.expiresAt) &&
		subtle.ConstantTimeCompare(candidate, m.current) == 1
}

type replayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func newReplayCache() *replayCache { return &replayCache{entries: make(map[string]time.Time)} }

func (c *replayCache) Use(key string, now time.Time, ttl time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if expires, exists := c.entries[key]; exists && now.Before(expires) {
		return false
	}
	for existing, expires := range c.entries {
		if !now.Before(expires) {
			delete(c.entries, existing)
		}
	}
	c.entries[key] = now.Add(ttl)
	return true
}
