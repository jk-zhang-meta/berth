package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/jk-zhang-meta/berth/internal/service"

	"github.com/redis/go-redis/v9"
)

const (
	oauthTokenKeyPrefix       = "oauth:token:"
	oauthRefreshLockKeyPrefix = "oauth:refresh_lock:"
)

// releaseRefreshLockCASScript deletes the refresh lock ONLY when its stored
// owner token matches ARGV[1], preventing a slow/paused worker whose TTL
// expired from deleting a successor worker's active lock (K-6).
var releaseRefreshLockCASScript = redis.NewScript(`
	if redis.call("GET", KEYS[1]) == ARGV[1] then
		return redis.call("DEL", KEYS[1])
	end
	return 0
`)

type geminiTokenCache struct {
	rdb        *redis.Client
	lockTokens sync.Map // cacheKey -> owner token string
}

func NewGeminiTokenCache(rdb *redis.Client) service.GeminiTokenCache {
	return &geminiTokenCache{rdb: rdb}
}

func newRefreshLockOwnerToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (c *geminiTokenCache) GetAccessToken(ctx context.Context, cacheKey string) (string, error) {
	key := fmt.Sprintf("%s%s", oauthTokenKeyPrefix, cacheKey)
	return c.rdb.Get(ctx, key).Result()
}

func (c *geminiTokenCache) SetAccessToken(ctx context.Context, cacheKey string, token string, ttl time.Duration) error {
	key := fmt.Sprintf("%s%s", oauthTokenKeyPrefix, cacheKey)
	return c.rdb.Set(ctx, key, token, ttl).Err()
}

func (c *geminiTokenCache) DeleteAccessToken(ctx context.Context, cacheKey string) error {
	key := fmt.Sprintf("%s%s", oauthTokenKeyPrefix, cacheKey)
	return c.rdb.Del(ctx, key).Err()
}

// AcquireRefreshLockToken acquires the Redis lock with a unique owner token
// that callers can pass to ReleaseRefreshLockToken for strict CAS release.
func (c *geminiTokenCache) AcquireRefreshLockToken(ctx context.Context, cacheKey string, ttl time.Duration) (string, bool, error) {
	key := fmt.Sprintf("%s%s", oauthRefreshLockKeyPrefix, cacheKey)
	token := newRefreshLockOwnerToken()
	ok, err := c.rdb.SetNX(ctx, key, token, ttl).Result()
	if err != nil || !ok {
		return "", false, err
	}
	c.lockTokens.Store(cacheKey, token)
	return token, true, nil
}

// ReleaseRefreshLockToken releases the lock ONLY if Redis still holds token.
func (c *geminiTokenCache) ReleaseRefreshLockToken(ctx context.Context, cacheKey, token string) error {
	if token == "" {
		return nil
	}
	key := fmt.Sprintf("%s%s", oauthRefreshLockKeyPrefix, cacheKey)
	if cur, ok := c.lockTokens.Load(cacheKey); ok && cur == token {
		c.lockTokens.Delete(cacheKey)
	}
	return releaseRefreshLockCASScript.Run(ctx, c.rdb, []string{key}, token).Err()
}

func (c *geminiTokenCache) AcquireRefreshLock(ctx context.Context, cacheKey string, ttl time.Duration) (bool, error) {
	_, ok, err := c.AcquireRefreshLockToken(ctx, cacheKey, ttl)
	return ok, err
}

func (c *geminiTokenCache) ReleaseRefreshLock(ctx context.Context, cacheKey string) error {
	v, ok := c.lockTokens.LoadAndDelete(cacheKey)
	if !ok {
		return nil
	}
	token, _ := v.(string)
	if token == "" {
		return nil
	}
	key := fmt.Sprintf("%s%s", oauthRefreshLockKeyPrefix, cacheKey)
	return releaseRefreshLockCASScript.Run(ctx, c.rdb, []string{key}, token).Err()
}
