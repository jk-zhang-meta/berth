package service

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"time"
)

const (
	FallbackModeNone   = "none"
	FallbackModeProxy  = "proxy"
	FallbackModeDirect = "direct"

	verifiedProxyExitProfileMaxAge = 15 * time.Minute
)

type Proxy struct {
	ID             int64
	Name           string
	Protocol       string
	Host           string
	Port           int
	Username       string
	Password       string
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	ExpiresAt      *time.Time
	FallbackMode   string
	BackupProxyID  *int64
	ExpiryWarnDays int

	// Verified proxy egress profile. These fields describe the network exit,
	// never the end user's physical/device location.
	ExitIP               string
	ExitCountry          string
	ExitCountryCode      string
	ExitRegion           string
	ExitCity             string
	ExitTimezone         string
	ExitUTCOffsetSeconds *int
	ExitASN              string
	ExitISP              string
	ExitCheckedAt        *time.Time
}

func (p *Proxy) HasVerifiedExitProfile() bool {
	return p != nil && p.ExitIP != "" && p.ExitTimezone != "" && p.ExitCheckedAt != nil
}

func (p *Proxy) HasFreshVerifiedExitProfile(now time.Time) bool {
	if !p.HasVerifiedExitProfile() || now.IsZero() {
		return false
	}
	checkedAt := p.ExitCheckedAt.UTC()
	now = now.UTC()
	if checkedAt.After(now.Add(time.Minute)) {
		return false
	}
	return !checkedAt.Before(now.Add(-verifiedProxyExitProfileMaxAge))
}

func (p *Proxy) IsActive() bool {
	return p.Status == StatusActive
}

// IsExpired 报告代理是否已过期（基于 expires_at，与 status 无关）。
func (p *Proxy) IsExpired(now time.Time) bool {
	return p.ExpiresAt != nil && !p.ExpiresAt.After(now)
}

func (p *Proxy) connectionURL() string {
	u := &url.URL{
		Scheme: p.Protocol,
		Host:   net.JoinHostPort(p.Host, strconv.Itoa(p.Port)),
	}
	if p.Username != "" && p.Password != "" {
		u.User = url.UserPassword(p.Username, p.Password)
	}
	return u.String()
}

func (p *Proxy) URL() string {
	rental, allowed, err := proxyRentalState(context.Background(), p.ID, false)
	if err != nil || (rental && !allowed) {
		return deniedRentalProxyURL
	}
	u, err := url.Parse(p.connectionURL())
	if err != nil {
		return deniedRentalProxyURL
	}
	if rental {
		u.Fragment = rentalProxyFragmentPrefix + strconv.FormatInt(p.ID, 10)
	}
	return u.String()
}

type ProxyWithAccountCount struct {
	Proxy
	AccountCount     int64
	LatencyMs        *int64
	LatencyStatus    string
	LatencyMessage   string
	IPAddress        string
	Country          string
	CountryCode      string
	Region           string
	City             string
	Timezone         string
	UTCOffsetSeconds *int
	ASN              string
	ISP              string
	ExitCheckedAt    *int64
	QualityStatus    string
	QualityScore     *int
	QualityGrade     string
	QualitySummary   string
	QualityChecked   *int64
}

type ProxyAccountSummary struct {
	ID       int64
	Name     string
	Platform string
	Type     string
	Notes    *string
}
