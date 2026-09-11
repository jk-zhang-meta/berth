package service

import "testing"

func TestPeerAdminIsOnlyTheAdminRole(t *testing.T) {
	if IsPeerAdmin(RoleUser) {
		t.Fatal("regular users manage their own berth, not the admin surface")
	}
	if !IsPeerAdmin(RoleAdmin) {
		t.Fatal("admin role must keep the operator surface")
	}
	user := &User{Role: RoleUser}
	if user.IsAdmin() {
		t.Fatal("role=user must not pass IsAdmin")
	}
}
