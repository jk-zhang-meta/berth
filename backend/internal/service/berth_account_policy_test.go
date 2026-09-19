//go:build unit

package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBerthShadowCannotEnrollUngroupedParentInDefaultPool(t *testing.T) {
	for _, groups := range [][]int64{nil, {11, 22}} {
		t.Run(fmt.Sprintf("parent_groups_%d", len(groups)), func(t *testing.T) {
			ctx := context.Background()
			repo := newSparkShadowRepoStub()
			groupRepo := &sparkShadowGroupRepoStub{groups: []Group{{ID: 99, Name: PlatformOpenAI + "-default"}}}
			svc := &adminServiceImpl{accountRepo: repo, groupRepo: groupRepo}
			parent := &Account{Name: "parent", Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusActive, GroupIDs: groups}
			require.NoError(t, repo.Create(ctx, parent))
			shadow, err := svc.CreateShadow(ctx, parent.ID, ShadowOptions{Name: "shadow", SkipDefaultGroupBind: true})
			require.NoError(t, err)
			require.Equal(t, groups, repo.groupsOf[shadow.ID])
		})
	}
}
