package edgeproto

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// UsageReceipt is the immutable idempotent usage/TTFT/status receipt emitted by
// Landing nodes to Berth Central (Codex Blocker #1.1).
type UsageReceipt struct {
	ReceiptID           string  `json:"receipt_id"`
	NodeID              int64   `json:"node_id"`
	LeaseID             string  `json:"lease_id"`
	GrantID             int64   `json:"grant_id"`
	UserID              int64   `json:"user_id"`
	APIKeyID            int64   `json:"api_key_id"`
	AccountID           int64   `json:"account_id"`
	WorkSessionID       int64   `json:"work_session_id"`
	Platform            string  `json:"platform"`
	Model               string  `json:"model,omitempty"`
	InputTokens         int     `json:"input_tokens,omitempty"`
	OutputTokens        int     `json:"output_tokens,omitempty"`
	CacheCreationTokens int     `json:"cache_creation_tokens,omitempty"`
	CacheReadTokens     int     `json:"cache_read_tokens,omitempty"`
	Stream              bool    `json:"stream,omitempty"`
	IngressBytes        int64   `json:"ingress_bytes"`
	EgressBytes         int64   `json:"egress_bytes"`
	TotalBytes          int64   `json:"total_bytes"`
	RequestCount        int     `json:"request_count"`
	StatusCode          int     `json:"status_code"`
	TTFTMs              int64   `json:"ttft_ms"`
	DurationMs          int64   `json:"duration_ms"`
	CreatedAtUnix       int64   `json:"created_at"`
	// Server-side settlement telemetry populated by Berth Central during outbox ingestion.
	TotalCost        float64 `json:"-"`
	ActualCost       float64 `json:"-"`
	AccountStatsCost float64 `json:"-"`
	UsageLogID       int64   `json:"-"`
}

type outboxEntry struct {
	Op      string        `json:"op"` // "put" | "ack"
	Receipt *UsageReceipt `json:"receipt,omitempty"`
	AckIDs  []string      `json:"ack_ids,omitempty"`
}

// OutboxWAL persists terminal usage receipts to an append-only JSONL WAL BEFORE
// completing requests and flushes them idempotently to Berth Central with
// exponential backoff + compaction after ACK (Codex Blocker #1.1).
type OutboxWAL struct {
	mu          sync.Mutex
	path        string
	file        *os.File
	pending     map[string]UsageReceipt
	order       []string
	ackedCount  int
	compactHint int
	notifyCh    chan struct{}
}

// OpenOutboxWAL opens (or creates) and replays an OutboxWAL at path.
func OpenOutboxWAL(path string) (*OutboxWAL, error) {
	if path == "" {
		return nil, errors.New("edgeproto: empty outbox WAL path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	o := &OutboxWAL{
		path:        path,
		pending:     make(map[string]UsageReceipt),
		compactHint: 64,
		notifyCh:    make(chan struct{}, 1),
	}

	if err := o.replay(); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	o.file = f
	return o, nil
}

func (o *OutboxWAL) replay() error {
	f, err := os.Open(o.path)
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
		var ent outboxEntry
		if err := json.Unmarshal(line, &ent); err != nil {
			continue
		}
		switch ent.Op {
		case "put":
			if ent.Receipt != nil && ent.Receipt.ReceiptID != "" {
				if _, exists := o.pending[ent.Receipt.ReceiptID]; !exists {
					o.order = append(o.order, ent.Receipt.ReceiptID)
				}
				o.pending[ent.Receipt.ReceiptID] = *ent.Receipt
			}
		case "ack":
			for _, id := range ent.AckIDs {
				if _, exists := o.pending[id]; exists {
					delete(o.pending, id)
					o.ackedCount++
				}
			}
		}
	}
	o.rebuildOrderLocked()
	return scanner.Err()
}

func (o *OutboxWAL) rebuildOrderLocked() {
	kept := o.order[:0]
	for _, id := range o.order {
		if _, ok := o.pending[id]; ok {
			kept = append(kept, id)
		}
	}
	o.order = kept
}

func (o *OutboxWAL) writeDurableLocked(ent outboxEntry) error {
	if o.file == nil {
		return errors.New("edgeproto: outbox WAL closed")
	}
	raw, err := json.Marshal(ent)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if _, err := o.file.Write(raw); err != nil {
		return err
	}
	return o.file.Sync()
}

// Append durably commits a terminal UsageReceipt to disk (fsync) before request finalization.
func (o *OutboxWAL) Append(r UsageReceipt) error {
	if r.ReceiptID == "" {
		return errors.New("edgeproto: receipt_id is required")
	}
	if r.CreatedAtUnix == 0 {
		r.CreatedAtUnix = time.Now().Unix()
	}
	if r.TotalBytes == 0 && (r.IngressBytes > 0 || r.EgressBytes > 0) {
		r.TotalBytes = r.IngressBytes + r.EgressBytes
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	if _, dup := o.pending[r.ReceiptID]; dup {
		return nil
	}
	if err := o.writeDurableLocked(outboxEntry{Op: "put", Receipt: &r}); err != nil {
		return err
	}
	o.pending[r.ReceiptID] = r
	o.order = append(o.order, r.ReceiptID)

	select {
	case o.notifyCh <- struct{}{}:
	default:
	}
	return nil
}

// Pending returns a snapshot slice of all un-ACKed receipts in append order.
func (o *OutboxWAL) Pending() []UsageReceipt {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]UsageReceipt, 0, len(o.pending))
	for _, id := range o.order {
		if r, ok := o.pending[id]; ok {
			out = append(out, r)
		}
	}
	return out
}

// PendingCount returns the number of un-ACKed receipts waiting for Central delivery.
func (o *OutboxWAL) PendingCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.pending)
}

// Ack durably records Central acknowledgements and compacts the WAL when warranted.
func (o *OutboxWAL) Ack(receiptIDs []string) error {
	if len(receiptIDs) == 0 {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()

	matched := make([]string, 0, len(receiptIDs))
	for _, id := range receiptIDs {
		if _, ok := o.pending[id]; ok {
			matched = append(matched, id)
		}
	}
	if len(matched) == 0 {
		return nil
	}
	if err := o.writeDurableLocked(outboxEntry{Op: "ack", AckIDs: matched}); err != nil {
		return err
	}
	for _, id := range matched {
		delete(o.pending, id)
		o.ackedCount++
	}
	o.rebuildOrderLocked()

	if o.ackedCount >= o.compactHint || len(o.pending) == 0 {
		return o.compactLocked()
	}
	return nil
}

// Compact atomically rewrites the outbox WAL keeping only un-ACKed receipts.
func (o *OutboxWAL) Compact() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.compactLocked()
}

func (o *OutboxWAL) compactLocked() error {
	tmpPath := o.path + ".compact.tmp"
	tmp, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	for _, id := range o.order {
		r, ok := o.pending[id]
		if !ok {
			continue
		}
		b, err := json.Marshal(outboxEntry{Op: "put", Receipt: &r})
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
			return err
		}
		b = append(b, '\n')
		if _, err := tmp.Write(b); err != nil {
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
	if o.file != nil {
		_ = o.file.Close()
		o.file = nil
	}
	if err := os.Rename(tmpPath, o.path); err != nil {
		return err
	}
	f, err := os.OpenFile(o.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	o.file = f
	o.ackedCount = 0
	return nil
}

// FlushOnce sends all pending receipts (in batches up to maxBatch) via sender and ACKs returned IDs.
func (o *OutboxWAL) FlushOnce(ctx context.Context, maxBatch int, sender func(ctx context.Context, batch []UsageReceipt) ([]string, error)) (int, error) {
	if sender == nil {
		return 0, errors.New("edgeproto: nil outbox sender")
	}
	if maxBatch <= 0 {
		maxBatch = 100
	}
	pending := o.Pending()
	if len(pending) == 0 {
		return 0, nil
	}

	flushed := 0
	for start := 0; start < len(pending); start += maxBatch {
		end := start + maxBatch
		if end > len(pending) {
			end = len(pending)
		}
		batch := pending[start:end]
		acked, err := sender(ctx, batch)
		if len(acked) > 0 {
			if ackErr := o.Ack(acked); ackErr != nil {
				return flushed, ackErr
			}
			flushed += len(acked)
		}
		if err != nil {
			return flushed, err
		}
	}
	return flushed, nil
}

// RunFlusher runs a background idempotent flush loop with exponential backoff until ctx is cancelled.
func (o *OutboxWAL) RunFlusher(
	ctx context.Context,
	baseBackoff, maxBackoff time.Duration,
	sender func(ctx context.Context, batch []UsageReceipt) ([]string, error),
) {
	if baseBackoff <= 0 {
		baseBackoff = 200 * time.Millisecond
	}
	if maxBackoff < baseBackoff {
		maxBackoff = 30 * time.Second
	}
	backoff := baseBackoff
	timer := time.NewTimer(baseBackoff)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-o.notifyCh:
		case <-timer.C:
		}

		if o.PendingCount() > 0 {
			_, err := o.FlushOnce(ctx, 100, sender)
			if err != nil {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			} else {
				backoff = baseBackoff
			}
		} else {
			backoff = baseBackoff
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(backoff)
	}
}

// Close closes the underlying outbox WAL file.
func (o *OutboxWAL) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.file != nil {
		err := o.file.Close()
		o.file = nil
		return err
	}
	return nil
}
