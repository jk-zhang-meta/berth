package edgeproto

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrGrantSliceExhausted = errors.New("edgeproto: grant byte slice exhausted")
	ErrGrantWALExpired     = errors.New("edgeproto: landing grant expired")
	ErrGrantWALRevoked     = errors.New("edgeproto: landing grant revoked")
	ErrGrantInvalidAmount  = errors.New("edgeproto: invalid byte amount")
)

type grantWALOp string

const (
	walOpSliceGranted  grantWALOp = "slice_granted"
	walOpPreDebit      grantWALOp = "pre_debit"
	walOpRefundUnused  grantWALOp = "refund_unused"
	walOpRevokeGrant   grantWALOp = "revoke_grant"
	walOpSnapshotState grantWALOp = "snapshot_state"
)

type grantWALRecord struct {
	Op            grantWALOp `json:"op"`
	SliceID       string     `json:"slice_id,omitempty"`
	DebitID       string     `json:"debit_id,omitempty"`
	GrantID       int64      `json:"grant_id"`
	Bytes         int64      `json:"bytes,omitempty"`
	ExpiresAtUnix int64      `json:"expires_at_unix,omitempty"`
	Revoked       bool       `json:"revoked,omitempty"`
	TimestampUnix int64      `json:"ts"`
}

type grantState struct {
	remaining     int64
	consumed      int64
	expiresAtUnix int64 // 0 means no expiry
	revoked       bool
}

// GrantWAL implements the Codex Blocker #1.5 pre-debited disjoint byte-slice WAL
// for Landing nodes:
//   - Slices granted by Central are deduplicated by slice_id and persisted durably.
//   - Every forwarded chunk is durably pre-debited (fsynced) BEFORE bytes cross the wire.
//   - On restart/crash recovery, uncertain in-flight pre-debits remain charged (never refunded),
//     guaranteeing a crash or parallel stream can NEVER double-spend a slice.
//   - Fails closed with ErrGrantSliceExhausted at the exact last admitted byte.
type GrantWAL struct {
	mu           sync.Mutex
	path         string
	file         *os.File
	grants       map[int64]*grantState
	seenSlices   map[string]struct{}
	activeDebits map[string]int64 // debitID -> remaining refundable bytes (only in-process before crash)
	recordCount  int
}

// OpenGrantWAL opens (or creates) and replays a durable GrantWAL at path.
func OpenGrantWAL(path string) (*GrantWAL, error) {
	if path == "" {
		return nil, errors.New("edgeproto: empty grant WAL path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	w := &GrantWAL{
		path:         path,
		grants:       make(map[int64]*grantState),
		seenSlices:   make(map[string]struct{}),
		activeDebits: make(map[string]int64),
	}

	if err := w.replay(); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	w.file = f
	return w, nil
}

func (w *GrantWAL) replay() error {
	f, err := os.Open(w.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec grantWALRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			// Ignore truncated trailing line from mid-write crash.
			continue
		}
		w.applyRecordLocked(rec, true)
		w.recordCount++
	}
	return scanner.Err()
}

func (w *GrantWAL) getOrCreateLocked(grantID int64) *grantState {
	st, ok := w.grants[grantID]
	if !ok {
		st = &grantState{}
		w.grants[grantID] = st
	}
	return st
}

func (w *GrantWAL) applyRecordLocked(rec grantWALRecord, replaying bool) {
	st := w.getOrCreateLocked(rec.GrantID)
	switch rec.Op {
	case walOpSliceGranted:
		if rec.SliceID != "" {
			if _, dup := w.seenSlices[rec.SliceID]; dup {
				return
			}
			w.seenSlices[rec.SliceID] = struct{}{}
		}
		if rec.Bytes > 0 {
			st.remaining += rec.Bytes
		}
		if rec.ExpiresAtUnix > 0 {
			st.expiresAtUnix = rec.ExpiresAtUnix
		}
	case walOpPreDebit:
		if rec.Bytes > 0 {
			if st.remaining >= rec.Bytes {
				st.remaining -= rec.Bytes
			} else {
				st.remaining = 0
			}
			st.consumed += rec.Bytes
			if !replaying && rec.DebitID != "" {
				w.activeDebits[rec.DebitID] = rec.Bytes
			}
		}
	case walOpRefundUnused:
		if rec.Bytes > 0 {
			st.remaining += rec.Bytes
			if st.consumed >= rec.Bytes {
				st.consumed -= rec.Bytes
			} else {
				st.consumed = 0
			}
		}
	case walOpRevokeGrant:
		st.revoked = true
		st.remaining = 0
	case walOpSnapshotState:
		if rec.SliceID != "" {
			w.seenSlices[rec.SliceID] = struct{}{}
		} else {
			st.remaining = rec.Bytes
			st.expiresAtUnix = rec.ExpiresAtUnix
			st.revoked = rec.Revoked
		}
	}
}

func (w *GrantWAL) appendDurableLocked(rec grantWALRecord) error {
	if w.file == nil {
		return errors.New("edgeproto: grant WAL closed")
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if _, err := w.file.Write(raw); err != nil {
		return err
	}
	if err := w.file.Sync(); err != nil {
		return err
	}
	w.recordCount++
	return nil
}

func newRandomHexID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// AddSlice durably records a disjoint byte slice reserved from Berth Central.
// Replaying the same sliceID is idempotent and never adds bytes twice.
func (w *GrantWAL) AddSlice(sliceID string, grantID int64, bytes int64, expiresAt time.Time) error {
	if sliceID == "" || grantID <= 0 || bytes < 0 {
		return ErrGrantInvalidAmount
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, dup := w.seenSlices[sliceID]; dup {
		return nil
	}
	st := w.getOrCreateLocked(grantID)
	if st.revoked {
		return ErrGrantWALRevoked
	}
	var expUnix int64
	if !expiresAt.IsZero() {
		expUnix = expiresAt.Unix()
	}
	rec := grantWALRecord{
		Op:            walOpSliceGranted,
		SliceID:       sliceID,
		GrantID:       grantID,
		Bytes:         bytes,
		ExpiresAtUnix: expUnix,
		TimestampUnix: time.Now().Unix(),
	}
	if err := w.appendDurableLocked(rec); err != nil {
		return err
	}
	w.applyRecordLocked(rec, false)
	return nil
}

// PreDebit durably commits chunkBytes BEFORE forwarding bytes in either direction.
// Fails closed with ErrGrantSliceExhausted if fewer than chunkBytes remain.
func (w *GrantWAL) PreDebit(grantID int64, chunkBytes int64, now time.Time) (string, error) {
	if grantID <= 0 || chunkBytes <= 0 {
		return "", ErrGrantInvalidAmount
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	st := w.getOrCreateLocked(grantID)
	if st.revoked {
		return "", ErrGrantWALRevoked
	}
	if st.expiresAtUnix > 0 && now.Unix() >= st.expiresAtUnix {
		return "", ErrGrantWALExpired
	}
	if st.remaining < chunkBytes {
		return "", fmt.Errorf("%w: grant=%d need=%d rem=%d", ErrGrantSliceExhausted, grantID, chunkBytes, st.remaining)
	}
	debitID := newRandomHexID()
	rec := grantWALRecord{
		Op:            walOpPreDebit,
		DebitID:       debitID,
		GrantID:       grantID,
		Bytes:         chunkBytes,
		TimestampUnix: now.Unix(),
	}
	if err := w.appendDurableLocked(rec); err != nil {
		return "", err
	}
	w.applyRecordLocked(rec, false)
	return debitID, nil
}

// PreDebitUpTo durably pre-debits min(wantBytes, remaining) so streaming cutoffs
// stop at the exact last admitted byte without over-spending.
func (w *GrantWAL) PreDebitUpTo(grantID int64, wantBytes int64, now time.Time) (int64, string, error) {
	if grantID <= 0 || wantBytes <= 0 {
		return 0, "", ErrGrantInvalidAmount
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	st := w.getOrCreateLocked(grantID)
	if st.revoked {
		return 0, "", ErrGrantWALRevoked
	}
	if st.expiresAtUnix > 0 && now.Unix() >= st.expiresAtUnix {
		return 0, "", ErrGrantWALExpired
	}
	if st.remaining <= 0 {
		return 0, "", fmt.Errorf("%w: grant=%d rem=0", ErrGrantSliceExhausted, grantID)
	}
	admit := wantBytes
	if admit > st.remaining {
		admit = st.remaining
	}
	debitID := newRandomHexID()
	rec := grantWALRecord{
		Op:            walOpPreDebit,
		DebitID:       debitID,
		GrantID:       grantID,
		Bytes:         admit,
		TimestampUnix: now.Unix(),
	}
	if err := w.appendDurableLocked(rec); err != nil {
		return 0, "", err
	}
	w.applyRecordLocked(rec, false)
	return admit, debitID, nil
}

// RefundConfirmedUnsent refunds strictly unused tail bytes from an active in-process
// pre-debit when the caller proves those bytes were never forwarded. Because activeDebits
// is in-memory only, a crash after PreDebit can NEVER trigger a refund upon restart.
func (w *GrantWAL) RefundConfirmedUnsent(debitID string, grantID int64, unusedBytes int64) error {
	if debitID == "" || grantID <= 0 || unusedBytes <= 0 {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	orig, ok := w.activeDebits[debitID]
	if !ok || unusedBytes > orig {
		return fmt.Errorf("%w: refund exceeds debit", ErrGrantInvalidAmount)
	}
	st := w.getOrCreateLocked(grantID)
	if st.revoked {
		delete(w.activeDebits, debitID)
		return nil
	}
	rec := grantWALRecord{
		Op:            walOpRefundUnused,
		DebitID:       debitID,
		GrantID:       grantID,
		Bytes:         unusedBytes,
		TimestampUnix: time.Now().Unix(),
	}
	if err := w.appendDurableLocked(rec); err != nil {
		return err
	}
	w.applyRecordLocked(rec, false)
	delete(w.activeDebits, debitID)
	return nil
}

// MarkDebitSettled clears an in-process debit entry once its bytes have crossed the wire.
func (w *GrantWAL) MarkDebitSettled(debitID string) {
	w.mu.Lock()
	delete(w.activeDebits, debitID)
	w.mu.Unlock()
}

// RevokeGrant durably marks a grant revoked and zeroes its local remaining slice.
func (w *GrantWAL) RevokeGrant(grantID int64) error {
	if grantID <= 0 {
		return ErrGrantInvalidAmount
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	rec := grantWALRecord{
		Op:            walOpRevokeGrant,
		GrantID:       grantID,
		Revoked:       true,
		TimestampUnix: time.Now().Unix(),
	}
	if err := w.appendDurableLocked(rec); err != nil {
		return err
	}
	w.applyRecordLocked(rec, false)
	return nil
}

// Remaining returns the currently available pre-debitable bytes for grantID.
func (w *GrantWAL) Remaining(grantID int64) int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	st, ok := w.grants[grantID]
	if !ok || st.revoked {
		return 0
	}
	return st.remaining
}

// TotalConsumed returns the cumulative durably charged bytes for grantID.
func (w *GrantWAL) TotalConsumed(grantID int64) int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	st, ok := w.grants[grantID]
	if !ok {
		return 0
	}
	return st.consumed
}

// NeedsRefill reports whether grantID's remaining slice is at or below lowWatermark.
func (w *GrantWAL) NeedsRefill(grantID int64, lowWatermark int64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	st, ok := w.grants[grantID]
	if !ok {
		return true
	}
	if st.revoked {
		return false
	}
	return st.remaining <= lowWatermark
}

// Compact atomically rewrites the WAL to a compact snapshot preserving seenSliceIDs
// and per-grant remaining/revoked state.
func (w *GrantWAL) Compact() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	tmpPath := w.path + ".compact.tmp"
	tmp, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	nowUnix := time.Now().Unix()
	writeRec := func(rec grantWALRecord) error {
		b, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		b = append(b, '\n')
		_, err = tmp.Write(b)
		return err
	}

	for sid := range w.seenSlices {
		if err := writeRec(grantWALRecord{
			Op:            walOpSnapshotState,
			SliceID:       sid,
			TimestampUnix: nowUnix,
		}); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
			return err
		}
	}
	for gid, st := range w.grants {
		if err := writeRec(grantWALRecord{
			Op:            walOpSnapshotState,
			GrantID:       gid,
			Bytes:         st.remaining,
			ExpiresAtUnix: st.expiresAtUnix,
			Revoked:       st.revoked,
			TimestampUnix: nowUnix,
		}); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	if err := os.Rename(tmpPath, w.path); err != nil {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	w.file = f
	w.recordCount = len(w.seenSlices) + len(w.grants)
	return nil
}

// Close closes the underlying WAL file cleanly.
func (w *GrantWAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}
