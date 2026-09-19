package service

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestStewardTodayLatencies(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	mock.ExpectQuery(`SELECT account_id, ROUND\(AVG\(first_token_ms\)\)::bigint, ROUND\(AVG\(duration_ms\)\)::bigint`).
		WithArgs(int64(1), int64(2), int64(3)).
		WillReturnRows(sqlmock.NewRows([]string{"account_id", "first_token_ms", "duration_ms"}).
			AddRow(1, 420, 2320).AddRow(2, nil, 800).AddRow(3, 100, nil))
	got := NewStewardStore(db).TodayLatencies(context.Background(), []int64{1, 2, 3})
	if len(got) != 3 || got[1].FirstTokenMs.Int64 != 420 || got[1].DurationMs.Int64 != 2320 || got[2].FirstTokenMs.Valid || got[2].DurationMs.Int64 != 800 || got[3].DurationMs.Valid {
		t.Fatalf("independent nullable timing values lost: %+v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStewardNilStoreIsSafe(t *testing.T) {
	var store *StewardStore
	if store.OwnsAccount(context.Background(), 1, 2) || store.OwnsProxy(context.Background(), 1, 2) {
		t.Fatal("nil store must not grant ownership")
	}
	if err := store.ClaimAccount(context.Background(), 1, 2); err != nil {
		t.Fatal(err)
	}
	if len(store.ListAccountIDs(context.Background(), 1)) != 0 {
		t.Fatal("nil store must list nothing")
	}
}
