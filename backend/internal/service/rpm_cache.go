package service

import "context"

// RPMCache RPM 计数器缓存接口。
// base_rpm 是账号级硬风控上限；调度平台只影响账号资格，不改变该上限。
type RPMCache interface {
	// ReserveRPM atomically reserves one request in the current minute when the
	// resulting count would not exceed maxRPM. A rejected reservation must not
	// increment the counter.
	ReserveRPM(ctx context.Context, accountID int64, maxRPM int) (count int, reserved bool, err error)

	// GetRPM 获取当前分钟的 RPM 计数
	GetRPM(ctx context.Context, accountID int64) (count int, err error)

	// GetRPMBatch 批量获取多个账号的 RPM 计数（使用 Pipeline）
	GetRPMBatch(ctx context.Context, accountIDs []int64) (map[int64]int, error)
}
