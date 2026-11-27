package admin

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/timezone"
)

var (
	accountTodayStatsBatchCache = newSnapshotCache(30 * time.Second)
	accountTodayStatsDayMu      sync.Mutex
	accountTodayStatsLastDay    string
)

// InvalidateAccountTodayStatsCache clears cached account today-stats snapshots so fresh
// Gateway or Berth Edge usage is immediately reflected in Account Pool "今日统计".
func InvalidateAccountTodayStatsCache() {
	accountTodayStatsBatchCache.Clear()
}

func ensureAccountTodayStatsCacheDay() {
	today := timezone.Today().Format("2006-01-02")
	accountTodayStatsDayMu.Lock()
	if accountTodayStatsLastDay != "" && accountTodayStatsLastDay != today {
		accountTodayStatsBatchCache.Clear()
	}
	accountTodayStatsLastDay = today
	accountTodayStatsDayMu.Unlock()
}

func buildAccountTodayStatsBatchCacheKey(accountIDs []int64) string {
	if len(accountIDs) == 0 {
		return "accounts_today_stats_empty"
	}
	var b strings.Builder
	b.Grow(len(accountIDs) * 6)
	_, _ = b.WriteString("accounts_today_stats:")
	for i, id := range accountIDs {
		if i > 0 {
			_ = b.WriteByte(',')
		}
		_, _ = b.WriteString(strconv.FormatInt(id, 10))
	}
	return b.String()
}
