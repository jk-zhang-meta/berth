package service

import "context"

type MarketplaceCommissionSettings struct {
	RentCommissionBPS  int `json:"rent_commission_bps"`
	UsageCommissionBPS int `json:"usage_commission_bps"`
}

func (s *MarketplaceService) GetCommissionSettings(ctx context.Context) (*MarketplaceCommissionSettings, error) {
	var settings MarketplaceCommissionSettings
	err := s.db.QueryRowContext(ctx, "SELECT rent_commission_bps,usage_commission_bps FROM berth_marketplace_settings WHERE id=1").Scan(&settings.RentCommissionBPS, &settings.UsageCommissionBPS)
	return &settings, err
}

// The administrative handler authorizes this operation. Values are basis points.
func (s *MarketplaceService) UpdateCommissionSettings(ctx context.Context, settings MarketplaceCommissionSettings) (*MarketplaceCommissionSettings, error) {
	if settings.RentCommissionBPS < 0 || settings.RentCommissionBPS > 10000 || settings.UsageCommissionBPS < 0 || settings.UsageCommissionBPS > 10000 {
		return nil, ErrMarketplaceInvalid
	}
	err := s.db.QueryRowContext(ctx, `UPDATE berth_marketplace_settings SET rent_commission_bps=$1,usage_commission_bps=$2,updated_at=clock_timestamp() WHERE id=1 RETURNING rent_commission_bps,usage_commission_bps`, settings.RentCommissionBPS, settings.UsageCommissionBPS).Scan(&settings.RentCommissionBPS, &settings.UsageCommissionBPS)
	return &settings, err
}
