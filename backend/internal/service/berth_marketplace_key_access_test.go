package service

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jk-zhang-meta/berth/internal/config"
	"github.com/stretchr/testify/require"
)

func TestMarketplaceAccountKeyRevalidation(t *testing.T) {
	for _, tc := range []struct {
		name                                           string
		managed, allowed, simple, queryFails, rejected bool
	}{
		{name: "active lease", managed: true, allowed: true},
		{name: "expired or terminated lease", managed: true, rejected: true},
		{name: "simple mode denies managed group", managed: true, allowed: true, simple: true, rejected: true},
		{name: "unmanaged legacy group", managed: false},
		{name: "database unavailable", queryFails: true, rejected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer func() { _ = db.Close() }()
			service := &APIKeyService{marketplace: NewMarketplaceService(db), cfg: &config.Config{}}
			if tc.simple {
				service.cfg.RunMode = config.RunModeSimple
			}
			query := mock.ExpectQuery("SELECT EXISTS").WithArgs(int64(17), int64(42))
			if tc.queryFails {
				query.WillReturnError(errors.New("database unavailable"))
			} else {
				query.WillReturnRows(sqlmock.NewRows([]string{"managed", "allowed"}).AddRow(tc.managed, tc.allowed))
			}
			groupID := int64(42)
			key := &APIKey{UserID: 17, GroupID: &groupID, User: &User{ID: 17, AllowedGroups: []int64{42}}}
			err = service.CheckMarketplaceAccountKey(context.Background(), key)
			if tc.rejected {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, []int64{42}, key.User.AllowedGroups, "cached allowed groups cannot grant or mutate the current entitlement")
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
