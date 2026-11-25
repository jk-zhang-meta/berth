// Package edgeproto defines lightweight, zero-heavy-dependency wire protocols,
// cryptographic lease/revocation verification, BHE1 attestation framing,
// single-mux reverse-tunnel registration, and durable Edge WAL primitives
// shared between Berth Central and the standalone berth-edge daemon.
package edgeproto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	ErrLeaseInvalid               = errors.New("edgeproto: invalid session lease")
	ErrLeaseSignatureInvalid      = errors.New("edgeproto: invalid lease signature")
	ErrLeaseExpired               = errors.New("edgeproto: session lease expired")
	ErrLeaseNotYetValid           = errors.New("edgeproto: session lease not yet valid")
	ErrLeaseRevoked               = errors.New("edgeproto: session lease revoked")
	ErrGrantRevoked               = errors.New("edgeproto: landing grant revoked")
	ErrAPIKeyRevoked              = errors.New("edgeproto: api key revoked")
	ErrCageEpochStale             = errors.New("edgeproto: cage epoch is stale")
	ErrRevocationSnapshotMissing  = errors.New("edgeproto: revocation snapshot missing")
	ErrRevocationSnapshotInvalid  = errors.New("edgeproto: invalid revocation snapshot signature")
	ErrRevocationSnapshotStale    = errors.New("edgeproto: revocation snapshot stale or expired")
	ErrRevocationSnapshotBehind   = errors.New("edgeproto: revocation snapshot sequence behind lease")
	ErrNodeAuthInvalid            = errors.New("edgeproto: invalid edge node request signature")
)

const (
	leaseClockSkewSeconds = 30
	leaseTypeHeader       = "berth-lease+jwt"
	leaseAlgHeader        = "EdDSA"
)

// RouteHop describes a single hop along a signed Edge forwarding route chain.
type RouteHop struct {
	NodeID    int64  `json:"node_id"`
	NodeName  string `json:"node_name"`
	Role      string `json:"role"`
	Addr      string `json:"addr"`
	LinkClass string `json:"link_class"` // direct | iplc | reverse_tunnel
}

// SessionLeaseClaims binds all authorization, cage, routing, and revocation
// fields required by Codex Blocker #1.2 into a single signed Ed25519 lease.
type SessionLeaseClaims struct {
	LeaseID           string     `json:"lease_id"`
	JTI               string     `json:"jti"`
	UserID            int64      `json:"user_id"`
	APIKeyID          int64      `json:"api_key_id"`
	WorkSessionID     int64      `json:"work_session_id"`
	Platform          string     `json:"platform"`
	AccountID         int64      `json:"account_id"`
	CageID            int64      `json:"cage_id"`
	CageEpoch         int64      `json:"cage_epoch"`
	GrantID           int64      `json:"grant_id"`
	IngressNodeID     int64      `json:"ingress_node_id"`
	LandingNodeID     int64      `json:"landing_node_id"`
	RouteChain        []RouteHop `json:"route_chain"`
	CohortTimezone    string     `json:"cohort_timezone"`
	CohortCountryCode string     `json:"cohort_country_code"`
	CohortLocale      string     `json:"cohort_locale"`
	RevSeq            int64      `json:"rev_seq"`
	LeaseEpoch        int64      `json:"lease_epoch"`
	IssuedAt          int64      `json:"iat"`
	ExpiresAt         int64      `json:"exp"`
}

type leaseJWSHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// KeyIDFromPublicKey computes a deterministic 16-hex-char identifier for an Ed25519 public key.
func KeyIDFromPublicKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// ValidateBoundClaims ensures every required bound authorization field is populated.
func (c *SessionLeaseClaims) ValidateBoundClaims() error {
	if c == nil {
		return ErrLeaseInvalid
	}
	if strings.TrimSpace(c.LeaseID) == "" || strings.TrimSpace(c.JTI) == "" {
		return fmt.Errorf("%w: missing lease_id or jti", ErrLeaseInvalid)
	}
	if c.UserID <= 0 || c.AccountID <= 0 || c.LandingNodeID <= 0 {
		return fmt.Errorf("%w: missing bound principal/account/landing_node_id", ErrLeaseInvalid)
	}
	if c.CageEpoch < 0 || c.RevSeq < 0 {
		return fmt.Errorf("%w: negative cage_epoch or rev_seq", ErrLeaseInvalid)
	}
	if c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt {
		return fmt.Errorf("%w: invalid iat/exp timestamps", ErrLeaseInvalid)
	}
	return nil
}

// SignLease signs a SessionLeaseClaims into a compact EdDSA JWS token.
func SignLease(priv ed25519.PrivateKey, kid string, claims SessionLeaseClaims) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("%w: invalid ed25519 private key length", ErrLeaseInvalid)
	}
	if err := claims.ValidateBoundClaims(); err != nil {
		return "", err
	}
	if kid == "" {
		pub := priv.Public().(ed25519.PublicKey)
		kid = KeyIDFromPublicKey(pub)
	}

	hdrBytes, err := json.Marshal(leaseJWSHeader{
		Alg: leaseAlgHeader,
		Typ: leaseTypeHeader,
		Kid: kid,
	})
	if err != nil {
		return "", err
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hdrBytes) + "." + enc.EncodeToString(payloadBytes)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + enc.EncodeToString(sig), nil
}

// VerifyLease verifies the compact EdDSA JWS signature, required bound fields, and validity window.
func VerifyLease(pub ed25519.PublicKey, token string, now time.Time) (*SessionLeaseClaims, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid ed25519 public key length", ErrLeaseSignatureInvalid)
	}
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, ErrLeaseInvalid
	}

	enc := base64.RawURLEncoding
	hdrBytes, err := enc.DecodeString(parts[0])
	if err != nil {
		return nil, ErrLeaseInvalid
	}
	var hdr leaseJWSHeader
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, ErrLeaseInvalid
	}
	if hdr.Alg != leaseAlgHeader || hdr.Typ != leaseTypeHeader {
		return nil, fmt.Errorf("%w: unexpected alg/typ", ErrLeaseInvalid)
	}

	sigBytes, err := enc.DecodeString(parts[2])
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, ErrLeaseSignatureInvalid
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sigBytes) {
		return nil, ErrLeaseSignatureInvalid
	}

	payloadBytes, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, ErrLeaseInvalid
	}
	var claims SessionLeaseClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrLeaseInvalid
	}
	if err := claims.ValidateBoundClaims(); err != nil {
		return nil, err
	}

	nowUnix := now.Unix()
	if nowUnix >= claims.ExpiresAt {
		return nil, ErrLeaseExpired
	}
	if nowUnix+leaseClockSkewSeconds < claims.IssuedAt {
		return nil, ErrLeaseNotYetValid
	}
	return &claims, nil
}

// RevocationSnapshot is a Central-signed, monotonically sequenced, time-bounded
// revocation snapshot required for fail-closed Edge authorization.
type RevocationSnapshot struct {
	Seq              int64           `json:"seq"`
	IssuedAt         int64           `json:"issued_at"`
	ValidUntil       int64           `json:"valid_until"`
	RevokedLeaseIDs  []string        `json:"revoked_lease_ids"`
	RevokedGrantIDs  []int64         `json:"revoked_grant_ids"`
	RevokedAPIKeyIDs []int64         `json:"revoked_api_key_ids"`
	CageMinEpochs    map[int64]int64 `json:"cage_min_epochs"`
	KeyID            string          `json:"kid,omitempty"`
	Signature        string          `json:"sig"`
}

type revocationSnapshotSignable struct {
	Seq              int64           `json:"seq"`
	IssuedAt         int64           `json:"issued_at"`
	ValidUntil       int64           `json:"valid_until"`
	RevokedLeaseIDs  []string        `json:"revoked_lease_ids"`
	RevokedGrantIDs  []int64         `json:"revoked_grant_ids"`
	RevokedAPIKeyIDs []int64         `json:"revoked_api_key_ids"`
	CageMinEpochs    map[int64]int64 `json:"cage_min_epochs"`
	KeyID            string          `json:"kid,omitempty"`
}

func (s *RevocationSnapshot) canonicalBytes() ([]byte, error) {
	if s == nil {
		return nil, ErrRevocationSnapshotMissing
	}
	leases := s.RevokedLeaseIDs
	if leases == nil {
		leases = []string{}
	}
	grants := s.RevokedGrantIDs
	if grants == nil {
		grants = []int64{}
	}
	keys := s.RevokedAPIKeyIDs
	if keys == nil {
		keys = []int64{}
	}
	cages := s.CageMinEpochs
	if cages == nil {
		cages = map[int64]int64{}
	}
	// encoding/json deterministically sorts map keys in Go.
	return json.Marshal(revocationSnapshotSignable{
		Seq:              s.Seq,
		IssuedAt:         s.IssuedAt,
		ValidUntil:       s.ValidUntil,
		RevokedLeaseIDs:  leases,
		RevokedGrantIDs:  grants,
		RevokedAPIKeyIDs: keys,
		CageMinEpochs:    cages,
		KeyID:            s.KeyID,
	})
}

// SignRevocationSnapshot signs snap in-place using Central's Ed25519 private key.
func SignRevocationSnapshot(priv ed25519.PrivateKey, kid string, snap *RevocationSnapshot) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: invalid private key", ErrRevocationSnapshotInvalid)
	}
	if snap == nil || snap.Seq < 0 || snap.IssuedAt <= 0 || snap.ValidUntil <= snap.IssuedAt {
		return ErrRevocationSnapshotInvalid
	}
	if kid == "" {
		pub := priv.Public().(ed25519.PublicKey)
		kid = KeyIDFromPublicKey(pub)
	}
	snap.KeyID = kid
	if snap.RevokedLeaseIDs == nil {
		snap.RevokedLeaseIDs = []string{}
	}
	if snap.RevokedGrantIDs == nil {
		snap.RevokedGrantIDs = []int64{}
	}
	if snap.RevokedAPIKeyIDs == nil {
		snap.RevokedAPIKeyIDs = []int64{}
	}
	if snap.CageMinEpochs == nil {
		snap.CageMinEpochs = map[int64]int64{}
	}
	payload, err := snap.canonicalBytes()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, payload)
	snap.Signature = base64.RawURLEncoding.EncodeToString(sig)
	return nil
}

// VerifyRevocationSnapshot verifies the Ed25519 signature and freshness window of snap.
func VerifyRevocationSnapshot(pub ed25519.PublicKey, snap *RevocationSnapshot, now time.Time) error {
	if snap == nil {
		return ErrRevocationSnapshotMissing
	}
	if len(pub) != ed25519.PublicKeySize {
		return ErrRevocationSnapshotInvalid
	}
	if snap.Seq < 0 || snap.IssuedAt <= 0 || snap.ValidUntil <= snap.IssuedAt {
		return ErrRevocationSnapshotInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(snap.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrRevocationSnapshotInvalid
	}
	payload, err := snap.canonicalBytes()
	if err != nil {
		return ErrRevocationSnapshotInvalid
	}
	if !ed25519.Verify(pub, payload, sig) {
		return ErrRevocationSnapshotInvalid
	}
	nowUnix := now.Unix()
	if nowUnix >= snap.ValidUntil {
		return ErrRevocationSnapshotStale
	}
	if nowUnix+leaseClockSkewSeconds < snap.IssuedAt {
		return ErrRevocationSnapshotInvalid
	}
	return nil
}

// IsAuthorized performs fail-closed authorization of a lease against this revocation snapshot.
// Callers must verify the snapshot's Ed25519 signature with VerifyRevocationSnapshot when installing it.
func (s *RevocationSnapshot) IsAuthorized(lease *SessionLeaseClaims, now time.Time) error {
	if s == nil {
		return ErrRevocationSnapshotMissing
	}
	if lease == nil {
		return ErrLeaseInvalid
	}
	nowUnix := now.Unix()
	if s.IssuedAt <= 0 || s.ValidUntil <= s.IssuedAt || nowUnix >= s.ValidUntil {
		return ErrRevocationSnapshotStale
	}
	if nowUnix >= lease.ExpiresAt {
		return ErrLeaseExpired
	}
	if nowUnix+leaseClockSkewSeconds < lease.IssuedAt {
		return ErrLeaseNotYetValid
	}
	if lease.RevSeq > s.Seq {
		return ErrRevocationSnapshotBehind
	}
	for _, id := range s.RevokedLeaseIDs {
		if id == lease.LeaseID {
			return ErrLeaseRevoked
		}
	}
	if lease.GrantID > 0 {
		for _, gid := range s.RevokedGrantIDs {
			if gid == lease.GrantID {
				return ErrGrantRevoked
			}
		}
	}
	if lease.APIKeyID > 0 {
		for _, kid := range s.RevokedAPIKeyIDs {
			if kid == lease.APIKeyID {
				return ErrAPIKeyRevoked
			}
		}
	}
	if lease.CageID > 0 && s.CageMinEpochs != nil {
		if minEpoch, ok := s.CageMinEpochs[lease.CageID]; ok && lease.CageEpoch < minEpoch {
			return ErrCageEpochStale
		}
	}
	return nil
}

// VerifyAndAuthorize verifies BOTH the revocation snapshot signature and lease authorization.
func VerifyAndAuthorize(pub ed25519.PublicKey, snap *RevocationSnapshot, lease *SessionLeaseClaims, now time.Time) error {
	if err := VerifyRevocationSnapshot(pub, snap, now); err != nil {
		return err
	}
	return snap.IsAuthorized(lease, now)
}

// NodeRequestSignInput constructs the canonical signing payload for Edge -> Central HTTP calls.
func NodeRequestSignInput(nodeID int64, method, path string, ts int64, body []byte) []byte {
	bodySum := sha256.Sum256(body)
	var b strings.Builder
	b.Grow(128)
	b.WriteString("berth-edge-req-v1\n")
	b.WriteString(strconv.FormatInt(nodeID, 10))
	b.WriteByte('\n')
	b.WriteString(strings.ToUpper(method))
	b.WriteByte('\n')
	b.WriteString(path)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(ts, 10))
	b.WriteByte('\n')
	b.WriteString(hex.EncodeToString(bodySum[:]))
	return []byte(b.String())
}

// SignNodeRequest signs an Edge -> Central internal HTTP request with the node's Ed25519 key.
func SignNodeRequest(priv ed25519.PrivateKey, nodeID int64, method, path string, ts int64, body []byte) (string, error) {
	if len(priv) != ed25519.PrivateKeySize || nodeID <= 0 {
		return "", ErrNodeAuthInvalid
	}
	msg := NodeRequestSignInput(nodeID, method, path, ts, body)
	sig := ed25519.Sign(priv, msg)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyNodeRequest verifies an Edge -> Central internal HTTP request signature and timestamp skew.
func VerifyNodeRequest(pub ed25519.PublicKey, nodeID int64, method, path string, ts int64, body []byte, sigB64 string, now time.Time) error {
	if len(pub) != ed25519.PublicKeySize || nodeID <= 0 {
		return ErrNodeAuthInvalid
	}
	diff := now.Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > leaseClockSkewSeconds {
		return fmt.Errorf("%w: timestamp skew %ds", ErrNodeAuthInvalid, diff)
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrNodeAuthInvalid
	}
	msg := NodeRequestSignInput(nodeID, method, path, ts, body)
	if !ed25519.Verify(pub, msg, sig) {
		return ErrNodeAuthInvalid
	}
	return nil
}
