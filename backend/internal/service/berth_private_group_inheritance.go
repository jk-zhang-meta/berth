package service

import (
	"context"
	"fmt"
)

// SetMarketplace installs the private-group boundary before serving account
// duplication or shadow creation. Legacy deployments retain upstream behavior.
func (s *adminServiceImpl) SetMarketplace(marketplace *MarketplaceService) {
	s.marketplace = marketplace
}

// Private account groups are capabilities for exactly one account. A new
// account must obtain its own private group; it cannot inherit the source's
// rentals or owner grants. Ordinary administrator groups retain their order.
func (s *adminServiceImpl) inheritableAccountGroupIDs(ctx context.Context, groupIDs []int64) ([]int64, error) {
	if s.marketplace == nil || len(groupIDs) == 0 {
		return groupIDs, nil
	}
	retained := make([]int64, 0, len(groupIDs))
	for _, groupID := range groupIDs {
		managed, _, err := s.marketplace.GroupAccess(ctx, 0, groupID)
		if err != nil {
			return nil, fmt.Errorf("check private group inheritance: %w", err)
		}
		if !managed {
			retained = append(retained, groupID)
		}
	}
	return retained, nil
}
