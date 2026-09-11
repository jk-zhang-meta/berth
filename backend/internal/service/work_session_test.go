package service

import "testing"

func TestNormalizeSessionPlatform(t *testing.T) {
	if got := normalizeSessionPlatform(" OpenAI "); got != "openai" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeSessionPlatform(""); got != "unknown" {
		t.Fatalf("empty -> %q", got)
	}
	if got := normalizeSessionPlatform("composite"); got != "unknown" {
		t.Fatalf("composite -> %q", got)
	}
}

func TestPickQueueAccount_PrefersFirstIdle(t *testing.T) {
	got := pickQueueAccount([]int64{3, 5, 8}, map[int64]int{3: 2, 5: 0, 8: 1}, nil)
	if got != 5 {
		t.Fatalf("pickQueueAccount = %d, want first idle 5", got)
	}
}

func TestPickQueueAccount_SkipsExcludedThenLeastBusy(t *testing.T) {
	got := pickQueueAccount([]int64{3, 5, 8}, map[int64]int{3: 4, 5: 1, 8: 9}, map[int64]struct{}{5: {}})
	if got != 3 {
		t.Fatalf("pickQueueAccount = %d, want least-busy non-excluded 3", got)
	}
}

func TestOccupancyPenalty_HighImportanceAvoidsBusyAccounts(t *testing.T) {
	idle := occupancyPenalty(0, 10)
	busyLow := occupancyPenalty(2, 80)
	busyHigh := occupancyPenalty(2, 10)
	if idle != 0 {
		t.Fatalf("idle penalty = %v, want 0", idle)
	}
	if busyHigh <= busyLow {
		t.Fatalf("high-importance busy penalty %v should exceed low-importance %v", busyHigh, busyLow)
	}
}
