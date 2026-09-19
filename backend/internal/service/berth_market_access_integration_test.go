//go:build integration

package service

import (
 "context"
 "testing"
 "time"

 "github.com/jk-zhang-meta/berth/internal/config"
 "github.com/stretchr/testify/require"
)

type berthMarketAccessCache struct { APIKeyCache; entry *APIKeyAuthCacheEntry }
func (c *berthMarketAccessCache) GetAuthCache(context.Context,string)(*APIKeyAuthCacheEntry,error){return c.entry,nil}
type berthMarketAccessUserRepo struct {UserRepository;user *User}
func(r *berthMarketAccessUserRepo)GetByID(context.Context,int64)(*User,error){return r.user,nil}
type berthMarketAccessGroupRepo struct {GroupRepository;groups []Group}
func(r *berthMarketAccessGroupRepo)ListActive(context.Context)([]Group,error){return r.groups,nil}
type berthMarketAccessSubscriptionRepo struct {UserSubscriptionRepository}
func(berthMarketAccessSubscriptionRepo)ListActiveByUserID(context.Context,int64)([]UserSubscription,error){return nil,nil}

func TestBerthMarketAccessCachedKeyRechecksLiveRental(t *testing.T){
 db:=marketplaceTestDB(t);ctx:=context.Background();market:=NewMarketplaceService(db)
 listing,err:=market.Publish(ctx,1,false,marketplaceOffer("account",11));require.NoError(t,err)
 rental,err:=market.Checkout(ctx,2,listing.ID,"cached-key");require.NoError(t,err)
 _,err=db.Exec("INSERT INTO groups(id,name,platform,is_exclusive) VALUES(100,'existing public pool','openai',false)");require.NoError(t,err)
 private:=Group{ID:*rental.GroupID,Platform:PlatformOpenAI,Status:StatusActive,IsExclusive:true,SubscriptionType:SubscriptionTypeStandard}
 public:=Group{ID:100,Platform:PlatformOpenAI,Status:StatusActive,IsExclusive:false,SubscriptionType:SubscriptionTypeStandard}
 buyer:=&User{ID:2,Role:RoleUser,Status:StatusActive}
 keyExpiry:=time.Now().Add(72*time.Hour)
 cache:=&berthMarketAccessCache{entry:&APIKeyAuthCacheEntry{Snapshot:&APIKeyAuthSnapshot{
  Version:apiKeyAuthSnapshotVersion,APIKeyID:21,UserID:2,GroupID:rental.GroupID,Status:StatusActive,ExpiresAt:&keyExpiry,
  User:APIKeyAuthUserSnapshot{ID:2,Role:RoleUser,Status:StatusActive},
  Group:&APIKeyAuthGroupSnapshot{ID:private.ID,Platform:PlatformOpenAI,Status:StatusActive,IsExclusive:true,SubscriptionType:SubscriptionTypeStandard},
 }}}
 svc:=NewAPIKeyService(nil,&berthMarketAccessUserRepo{user:buyer},&berthMarketAccessGroupRepo{groups:[]Group{private,public}},berthMarketAccessSubscriptionRepo{},nil,cache,&config.Config{APIKeyAuth:config.APIKeyAuthCacheConfig{L2TTLSeconds:60}})
 svc.SetMarketplace(market)
 key,err:=svc.GetByKey(ctx,"cached-rental-key");require.NoError(t,err);require.Contains(t,key.User.AllowedGroups,private.ID);require.False(t,key.IsExpired())
 require.Empty(t,cache.entry.Snapshot.User.AllowedGroups,"request entitlement must not contaminate reusable cache")
 require.True(t,svc.canUserBindGroup(ctx,buyer,&private))
 groups,err:=svc.GetAvailableGroups(ctx,2);require.NoError(t,err);require.Len(t,groups,2)
 // Expire the order without touching the cached API key or waiting for any worker.
 _,err=db.Exec("UPDATE berth_marketplace_orders SET starts_at=clock_timestamp()-interval '3 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1",rental.ID);require.NoError(t,err)
 _,err=svc.GetByKey(ctx,"cached-rental-key");require.ErrorIs(t,err,ErrGroupNotAllowed)
 require.False(t,svc.canUserBindGroup(ctx,buyer,&private))
 groups,err=svc.GetAvailableGroups(ctx,2);require.NoError(t,err);require.Len(t,groups,1);require.Equal(t,public.ID,groups[0].ID)
 cache.entry.Snapshot.GroupID=&public.ID;cache.entry.Snapshot.Group.ID=public.ID;cache.entry.Snapshot.Group.IsExclusive=false
 key,err=svc.GetByKey(ctx,"cached-public-key");require.NoError(t,err);require.Equal(t,public.ID,*key.GroupID)
 require.True(t,svc.canUserBindGroup(ctx,buyer,&public),"upstream public group rights survive unrelated rental expiry")
}

func TestBerthMarketAccessRejectsForeignOwnerAndSimpleMode(t *testing.T){
 db:=marketplaceTestDB(t);ctx:=context.Background();market:=NewMarketplaceService(db)
 groupID,err:=market.EnsureAccountGroup(ctx,11,1);require.NoError(t,err)
 cache:=&berthMarketAccessCache{entry:&APIKeyAuthCacheEntry{Snapshot:&APIKeyAuthSnapshot{
  Version:apiKeyAuthSnapshotVersion,APIKeyID:21,UserID:2,GroupID:&groupID,Status:StatusActive,
  User:APIKeyAuthUserSnapshot{ID:2,Role:RoleUser,Status:StatusActive,AllowedGroups:[]int64{groupID}},
  Group:&APIKeyAuthGroupSnapshot{ID:groupID,Platform:PlatformOpenAI,Status:StatusActive,IsExclusive:true,SubscriptionType:SubscriptionTypeStandard},
 }}}
 cfg:=&config.Config{APIKeyAuth:config.APIKeyAuthCacheConfig{L2TTLSeconds:60}}
 svc:=NewAPIKeyService(nil,nil,nil,nil,nil,cache,cfg);svc.SetMarketplace(market)
 _,err=svc.GetByKey(ctx,"foreign-key");require.ErrorIs(t,err,ErrGroupNotAllowed,"stale allowed_groups cannot grant ownership")
 cache.entry.Snapshot.UserID=1;cache.entry.Snapshot.User.ID=1
 _,err=svc.GetByKey(ctx,"owner-key");require.NoError(t,err)
 cfg.RunMode=config.RunModeSimple
 _,err=svc.GetByKey(ctx,"owner-key");require.ErrorIs(t,err,ErrGroupNotAllowed,"simple mode cannot bypass private group scheduling")
}
