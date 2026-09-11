package service

import (
	"context"
	"testing"
)

func TestFilterAccountsForBerth_EmptyAllowedKeepsHousePool(t *testing.T) {
	accounts := []Account{{ID: 1}, {ID: 2}}
	got := FilterAccountsForBerth(contextWithPref(&WorkSessionPref{}), accounts)
	if len(got) != 2 {
		t.Fatalf("house pool should stay intact, got %d", len(got))
	}
}

func TestFilterAccountsForBerth_RestrictsToOwnedOrBorrowed(t *testing.T) {
	pref := &WorkSessionPref{AllowedAccountIDs: map[int64]struct{}{2: {}, 9: {}}}
	got := FilterAccountsForBerth(contextWithPref(pref), []Account{{ID: 1}, {ID: 2}, {ID: 3}})
	if len(got) != 1 || got[0].ID != 2 {
		t.Fatalf("got %#v", got)
	}
}

func TestBerthAllowsAccount(t *testing.T) {
	if !berthAllowsAccount(nil, 1) {
		t.Fatal("nil pref is the house pool")
	}
	pref := &WorkSessionPref{AllowedAccountIDs: map[int64]struct{}{4: {}}}
	if berthAllowsAccount(pref, 1) {
		t.Fatal("1 is not in the personal pool")
	}
	if !berthAllowsAccount(pref, 4) {
		t.Fatal("4 is in the personal pool")
	}
}

func contextWithPref(pref *WorkSessionPref) context.Context {
	return withWorkSessionPref(context.Background(), pref)
}
