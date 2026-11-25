package service

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	HeaderBerthCageTZ            = "X-Berth-Cage-TZ"
	HeaderBerthCageCountry       = "X-Berth-Cage-Country"
	HeaderBerthCageStrict        = "X-Berth-Cage-Strict"
	HeaderBerthAllowCageHandover = "X-Berth-Allow-Cage-Handover"
	HeaderBerthAGSVersion        = "X-Berth-AGS-Version"

	HeaderBerthFailoverReason      = "X-Berth-Failover-Reason"
	HeaderBerthSessionCohortTZ     = "X-Berth-Session-Cohort-TZ"
	HeaderBerthRecommendedCohortTZ = "X-Berth-Recommended-Cohort-TZ"
	HeaderBerthAvailableCohorts    = "X-Berth-Available-Cohorts"
	HeaderBerthCageHandoverTZ      = "X-Berth-Cage-Handover-TZ"
	HeaderBerthCageHandoverEpoch   = "X-Berth-Cage-Handover-Epoch"
)

const (
	ASNClassResidentialISP = "residential_isp"
	ASNClassDatacenter     = "datacenter"
	ASNClassUnknown        = "unknown"
)

// CohortFailoverLevel identifies which rung of the 4-level cohort ladder satisfied selection.
type CohortFailoverLevel string

const (
	CohortLevelUnconstrained CohortFailoverLevel = "unconstrained"
	CohortLevel2AExact       CohortFailoverLevel = "2A_exact_tz_country_asn"
	CohortLevel2BSameTZ      CohortFailoverLevel = "2B_exact_tz_country"
	CohortLevel2CSameOffset  CohortFailoverLevel = "2C_offset_country"
	CohortLevel2DHandover    CohortFailoverLevel = "2D_cross_cohort_handover"
)

// CageCohort captures the egress geography and network posture inherited from a landing proxy.
type CageCohort struct {
	Timezone         string
	UTCOffsetSeconds *int
	CountryCode      string
	ASNClass         string
}

func (c CageCohort) IsSet() bool {
	return strings.TrimSpace(c.Timezone) != ""
}

func (c CageCohort) Normalized() CageCohort {
	out := CageCohort{
		Timezone:    strings.TrimSpace(c.Timezone),
		CountryCode: strings.ToUpper(strings.TrimSpace(c.CountryCode)),
		ASNClass:    normalizeASNClass(c.ASNClass),
	}
	if c.UTCOffsetSeconds != nil {
		v := *c.UTCOffsetSeconds
		out.UTCOffsetSeconds = &v
	} else if out.Timezone != "" {
		if loc, err := time.LoadLocation(out.Timezone); err == nil {
			_, off := time.Now().In(loc).Zone()
			out.UTCOffsetSeconds = &off
		}
	}
	return out
}

// CohortAvailability describes an available fallback cohort and candidate count.
type CohortAvailability struct {
	Timezone         string `json:"timezone"`
	CountryCode      string `json:"country_code,omitempty"`
	UTCOffsetSeconds *int   `json:"utc_offset_seconds,omitempty"`
	AvailableCount   int    `json:"available_count"`
}

// ErrCageRebindRequired is returned pre-commit when a strict/caged session has
// zero healthy candidates in its exact (exit_timezone, exit_country_code) cohort
// and explicit handover was not authorized.
type ErrCageRebindRequired struct {
	Reason                   string               `json:"error"`
	Message                  string               `json:"message"`
	CurrentCohortTZ          string               `json:"current_cohort_tz"`
	CurrentCohortCountry     string               `json:"current_cohort_country,omitempty"`
	RecommendedCohortTZ      string               `json:"recommended_cohort_tz,omitempty"`
	RecommendedCohortCountry string               `json:"recommended_cohort_country,omitempty"`
	AvailableCohorts         []CohortAvailability `json:"available_cohorts"`
	RetryAfterSeconds        int                  `json:"retry_after_seconds"`
}

func (e *ErrCageRebindRequired) Error() string {
	if e == nil {
		return "cage_rebind_required"
	}
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("cage_rebind_required: cohort %s exhausted (recommended=%s)", e.CurrentCohortTZ, e.RecommendedCohortTZ)
}

// FormatAvailableCohortsHeader renders "America/New_York:4,Asia/Tokyo:2".
func (e *ErrCageRebindRequired) FormatAvailableCohortsHeader() string {
	if e == nil || len(e.AvailableCohorts) == 0 {
		return ""
	}
	parts := make([]string, 0, len(e.AvailableCohorts))
	for _, item := range e.AvailableCohorts {
		parts = append(parts, fmt.Sprintf("%s:%d", item.Timezone, item.AvailableCount))
	}
	return strings.Join(parts, ",")
}

// CageCohortRequest carries the resolved session cohort boundary on request context.
type CageCohortRequest struct {
	Target        CageCohort
	StrictMode    bool
	AllowHandover bool
	FailoverEpoch int
}

type cageCohortRequestCtxKey struct{}

func WithCageCohortRequest(ctx context.Context, req *CageCohortRequest) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if req == nil {
		return ctx
	}
	copied := *req
	copied.Target = copied.Target.Normalized()
	return context.WithValue(ctx, cageCohortRequestCtxKey{}, &copied)
}

func CageCohortRequestFromContext(ctx context.Context) *CageCohortRequest {
	if ctx == nil {
		return nil
	}
	req, _ := ctx.Value(cageCohortRequestCtxKey{}).(*CageCohortRequest)
	return req
}

// ExtractCageCohortRequest resolves cohort target & strictness from explicit
// client/AGS headers first, then persisted WorkSession metadata.
func ExtractCageCohortRequest(headers http.Header, pref *WorkSessionPref) *CageCohortRequest {
	req := &CageCohortRequest{FailoverEpoch: 1}
	if pref != nil {
		if pref.CohortTimezone != "" {
			req.Target.Timezone = pref.CohortTimezone
			req.Target.CountryCode = pref.CohortCountryCode
			req.Target.ASNClass = pref.CohortASNClass
		}
		if pref.CageStrictMode {
			req.StrictMode = true
		}
		if pref.FailoverEpoch > 0 {
			req.FailoverEpoch = pref.FailoverEpoch
		}
	}
	if headers != nil {
		if tz := strings.TrimSpace(headers.Get(HeaderBerthCageTZ)); tz != "" {
			req.Target.Timezone = tz
			// Explicit X-Berth-Cage-TZ activates strict exact-TZ cohort matching by default
			// (Codex Review #3.3: never conflate equal UTC offsets that diverge at DST).
			req.StrictMode = true
		}
		if cc := strings.TrimSpace(headers.Get(HeaderBerthCageCountry)); cc != "" {
			req.Target.CountryCode = strings.ToUpper(cc)
		}
		if rawStrict := strings.TrimSpace(strings.ToLower(headers.Get(HeaderBerthCageStrict))); rawStrict != "" {
			switch rawStrict {
			case "1", "true", "yes":
				req.StrictMode = true
			case "0", "false", "no":
				if strings.TrimSpace(headers.Get(HeaderBerthCageTZ)) == "" {
					req.StrictMode = false
				}
			}
		}
		if rawHandover := strings.TrimSpace(strings.ToLower(headers.Get(HeaderBerthAllowCageHandover))); rawHandover == "1" || rawHandover == "true" || rawHandover == "yes" {
			req.AllowHandover = true
		}
		if agsVer := strings.TrimSpace(headers.Get(HeaderBerthAGSVersion)); agsVer != "" && req.Target.IsSet() {
			req.StrictMode = true
		}
	}
	req.Target = req.Target.Normalized()
	if !req.Target.IsSet() && !req.StrictMode && !req.AllowHandover {
		return nil
	}
	return req
}

func normalizeASNClass(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case ASNClassResidentialISP:
		return ASNClassResidentialISP
	case ASNClassDatacenter:
		return ASNClassDatacenter
	default:
		return ASNClassUnknown
	}
}

var datacenterISPKeywords = []string{
	"amazon", "aws", "google cloud", "google llc", "microsoft", "azure",
	"digitalocean", "hetzner", "ovh", "vultr", "linode", "akamai", "cloudflare",
	"alibaba", "aliyun", "tencent", "oracle", "contabo", "choopa", "m247",
	"datacamp", "leaseweb", "psychz", "quadranet", "rackspace", "server", "hosting", "cloud",
}

// DeriveProxyASNClass resolves residential_isp vs datacenter vs unknown for a proxy.
func DeriveProxyASNClass(proxy *Proxy) string {
	if proxy == nil {
		return ASNClassUnknown
	}
	if cls := normalizeASNClass(proxy.ASNClass); cls != ASNClassUnknown {
		return cls
	}
	isp := strings.ToLower(strings.TrimSpace(proxy.ExitISP))
	if isp == "" {
		return ASNClassUnknown
	}
	for _, kw := range datacenterISPKeywords {
		if strings.Contains(isp, kw) {
			return ASNClassDatacenter
		}
	}
	return ASNClassResidentialISP
}

// AccountCohort extracts an account's CageCohort from its attached Proxy exit profile.
func AccountCohort(acc *Account) CageCohort {
	if acc == nil || acc.Proxy == nil {
		return CageCohort{ASNClass: ASNClassUnknown}
	}
	return CageCohort{
		Timezone:         acc.Proxy.ExitTimezone,
		UTCOffsetSeconds: acc.Proxy.ExitUTCOffsetSeconds,
		CountryCode:      acc.Proxy.ExitCountryCode,
		ASNClass:         DeriveProxyASNClass(acc.Proxy),
	}.Normalized()
}

// FilterCandidatesByCohort applies the 4-level Cage Cohort failover ladder:
//   - Level 2A: exact exit_timezone + exact exit_country_code + exact asn_class
//   - Level 2B: exact exit_timezone + exact exit_country_code (any asn_class)
//   - Level 2C: same exit_utc_offset_seconds + exact exit_country_code (NON-STRICT ONLY!)
//   - Level 2D: cross-cohort — BLOCKED with ErrCageRebindRequired when strict && !allowHandover;
//     otherwise selects the closest UTC offset delta (same country first).
func FilterCandidatesByCohort(
	candidates []*Account,
	target CageCohort,
	strict bool,
	allowHandover bool,
) ([]*Account, CohortFailoverLevel, string, error) {
	if len(candidates) == 0 {
		return nil, CohortLevelUnconstrained, "", nil
	}
	normTarget := target.Normalized()
	if !normTarget.IsSet() {
		return candidates, CohortLevelUnconstrained, "", nil
	}

	var lvl2A, lvl2B, lvl2C []*Account
	for _, acc := range candidates {
		c := AccountCohort(acc)
		if !c.IsSet() {
			continue
		}
		sameTZ := strings.EqualFold(c.Timezone, normTarget.Timezone)
		sameCountry := normTarget.CountryCode == "" || strings.EqualFold(c.CountryCode, normTarget.CountryCode)

		if sameTZ && sameCountry {
			if normTarget.ASNClass == ASNClassUnknown || c.ASNClass == normTarget.ASNClass {
				lvl2A = append(lvl2A, acc)
			}
			lvl2B = append(lvl2B, acc)
			continue
		}

		// Level 2C (UTC offset match) is strictly forbidden under cage_strict_mode
		// because equal UTC offsets can diverge across DST transitions.
		if !strict && sameCountry && normTarget.UTCOffsetSeconds != nil && c.UTCOffsetSeconds != nil && *normTarget.UTCOffsetSeconds == *c.UTCOffsetSeconds {
			lvl2C = append(lvl2C, acc)
		}
	}

	if len(lvl2A) > 0 {
		return lvl2A, CohortLevel2AExact, "", nil
	}
	if len(lvl2B) > 0 {
		return lvl2B, CohortLevel2BSameTZ, "", nil
	}
	if !strict && len(lvl2C) > 0 {
		return lvl2C, CohortLevel2CSameOffset, "", nil
	}

	// Level 2D: rank all remaining candidates' cohorts by (same country, smallest |ΔUTC offset|, count desc).
	avail, byCohortKey := rankAvailableCohorts(candidates, normTarget)
	recommendedTZ := ""
	recommendedCC := ""
	if len(avail) > 0 {
		recommendedTZ = avail[0].Timezone
		recommendedCC = avail[0].CountryCode
	}

	if strict && !allowHandover {
		return nil, CohortLevel2DHandover, "", &ErrCageRebindRequired{
			Reason:                   "cage_rebind_required",
			Message:                  fmt.Sprintf("no schedulable accounts in cohort %s; rebind required before dispatching cross-cohort", normTarget.Timezone),
			CurrentCohortTZ:          normTarget.Timezone,
			CurrentCohortCountry:     normTarget.CountryCode,
			RecommendedCohortTZ:      recommendedTZ,
			RecommendedCohortCountry: recommendedCC,
			AvailableCohorts:         avail,
			RetryAfterSeconds:        5,
		}
	}

	// Explicit handover or non-strict mode: pick candidates from the closest cohort first.
	if len(avail) > 0 {
		bestKey := cohortRankKey(avail[0].Timezone, avail[0].CountryCode)
		if chosen := byCohortKey[bestKey]; len(chosen) > 0 {
			return chosen, CohortLevel2DHandover, avail[0].Timezone, nil
		}
	}

	// Candidates without verified exit profile (e.g. legacy admin direct accounts):
	// never allow under strict mode, allow under non-strict fallback.
	if strict {
		return nil, CohortLevel2DHandover, "", &ErrCageRebindRequired{
			Reason:               "cage_rebind_required",
			Message:              fmt.Sprintf("no verified cohort accounts available for %s", normTarget.Timezone),
			CurrentCohortTZ:      normTarget.Timezone,
			CurrentCohortCountry: normTarget.CountryCode,
			AvailableCohorts:     avail,
			RetryAfterSeconds:    5,
		}
	}
	return candidates, CohortLevel2DHandover, "", nil
}

func cohortRankKey(tz, cc string) string {
	return strings.ToLower(strings.TrimSpace(tz)) + "|" + strings.ToUpper(strings.TrimSpace(cc))
}

func rankAvailableCohorts(candidates []*Account, target CageCohort) ([]CohortAvailability, map[string][]*Account) {
	byKey := make(map[string][]*Account)
	meta := make(map[string]CohortAvailability)
	for _, acc := range candidates {
		c := AccountCohort(acc)
		if !c.IsSet() {
			continue
		}
		k := cohortRankKey(c.Timezone, c.CountryCode)
		byKey[k] = append(byKey[k], acc)
		entry, exists := meta[k]
		if !exists {
			entry = CohortAvailability{
				Timezone:         c.Timezone,
				CountryCode:      c.CountryCode,
				UTCOffsetSeconds: c.UTCOffsetSeconds,
			}
		}
		entry.AvailableCount++
		meta[k] = entry
	}
	avail := make([]CohortAvailability, 0, len(meta))
	for _, v := range meta {
		avail = append(avail, v)
	}
	sort.SliceStable(avail, func(i, j int) bool {
		a, b := avail[i], avail[j]
		aSameCountry := target.CountryCode != "" && strings.EqualFold(a.CountryCode, target.CountryCode)
		bSameCountry := target.CountryCode != "" && strings.EqualFold(b.CountryCode, target.CountryCode)
		if aSameCountry != bSameCountry {
			return aSameCountry
		}
		aDelta := utcOffsetDeltaSeconds(target.UTCOffsetSeconds, a.UTCOffsetSeconds)
		bDelta := utcOffsetDeltaSeconds(target.UTCOffsetSeconds, b.UTCOffsetSeconds)
		if aDelta != bDelta {
			return aDelta < bDelta
		}
		if a.AvailableCount != b.AvailableCount {
			return a.AvailableCount > b.AvailableCount
		}
		return a.Timezone < b.Timezone
	})
	return avail, byKey
}

func utcOffsetDeltaSeconds(a, b *int) int {
	if a == nil || b == nil {
		return math.MaxInt32
	}
	diff := *a - *b
	if diff < 0 {
		return -diff
	}
	return diff
}
