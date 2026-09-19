package repository

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestRPMCacheReserveRPMRejectDoesNotIncrement(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	cache := &RPMCacheImpl{rdb: client}
	ctx := context.Background()

	count, reserved, err := cache.ReserveRPM(ctx, 42, 2)
	require.NoError(t, err)
	require.True(t, reserved)
	require.Equal(t, 1, count)

	count, reserved, err = cache.ReserveRPM(ctx, 42, 2)
	require.NoError(t, err)
	require.True(t, reserved)
	require.Equal(t, 2, count)

	count, reserved, err = cache.ReserveRPM(ctx, 42, 2)
	require.NoError(t, err)
	require.False(t, reserved)
	require.Equal(t, 2, count)

	current, err := cache.GetRPM(ctx, 42)
	require.NoError(t, err)
	require.Equal(t, 2, current)
}

func TestRPMCacheReserveRPMConcurrentHardLimit(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	cache := &RPMCacheImpl{rdb: client}
	ctx := context.Background()

	const limit = 5
	const workers = 32
	var reserved atomic.Int64
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := cache.ReserveRPM(ctx, 77, limit)
			if err != nil {
				errs <- err
				return
			}
			if ok {
				reserved.Add(1)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, int64(limit), reserved.Load())
	current, err := cache.GetRPM(ctx, 77)
	require.NoError(t, err)
	require.Equal(t, limit, current)
}

func TestProxyRPMUsesIndependentNamespaceAndHardLimit(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	cache := &RPMCacheImpl{rdb: client}
	ctx := context.Background()

	_, reserved, err := cache.ReserveRPM(ctx, 42, 1)
	require.NoError(t, err)
	require.True(t, reserved)

	count, reserved, err := cache.ReserveProxyRPM(ctx, 42, 2)
	require.NoError(t, err)
	require.True(t, reserved)
	require.Equal(t, 1, count)
	count, reserved, err = cache.ReserveProxyRPM(ctx, 42, 2)
	require.NoError(t, err)
	require.True(t, reserved)
	require.Equal(t, 2, count)
	count, reserved, err = cache.ReserveProxyRPM(ctx, 42, 2)
	require.NoError(t, err)
	require.False(t, reserved)
	require.Equal(t, 2, count)

	counts, err := cache.GetProxyRPMBatch(ctx, []int64{42, 99})
	require.NoError(t, err)
	require.Equal(t, map[int64]int{42: 2, 99: 0}, counts)
	accountCount, err := cache.GetRPM(ctx, 42)
	require.NoError(t, err)
	require.Equal(t, 1, accountCount)
}
