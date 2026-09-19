package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/proxyurl"
)

// ProxyRentalChecker reads current lease state, including when the proxy or
// account passed to a caller came from a JSON cache.
type ProxyRentalChecker interface {
	CheckRentalProxy(context.Context, int64) (rental, allowed bool, err error)
	CheckAccountProxy(context.Context, int64) (rental, allowed bool, err error)
}

type proxyRentalCheckerHolder struct{ checker ProxyRentalChecker }

var proxyRentalChecker atomic.Pointer[proxyRentalCheckerHolder]

var ErrProxyRentalUnavailable = errors.New("proxy rental is no longer available")

// Deliberately fails both net/url.Parse and the shared proxyurl parser. An empty
// URL would mean direct connection, which must never be an expired lease fallback.
const deniedRentalProxyURL = "%zz-berth-rental-denied"

const rentalProxyFragmentPrefix = "berth-rental-"

// SetProxyRentalChecker installs the process-owned checker once during startup,
// before accepting requests. It cannot be replaced by a request or cache reload.
func SetProxyRentalChecker(checker ProxyRentalChecker) error {
	if checker == nil {
		return errors.New("proxy rental checker is nil")
	}
	if !proxyRentalChecker.CompareAndSwap(nil, &proxyRentalCheckerHolder{checker: checker}) {
		return errors.New("proxy rental checker is already installed")
	}
	return nil
}

func proxyRentalState(ctx context.Context, id int64, account bool) (rental, allowed bool, err error) {
	holder := proxyRentalChecker.Load()
	if holder == nil || id <= 0 {
		return false, true, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if account {
		return holder.checker.CheckAccountProxy(ctx, id)
	}
	return holder.checker.CheckRentalProxy(ctx, id)
}

func checkProxyRentalState(ctx context.Context, id int64, account bool) error {
	rental, allowed, err := proxyRentalState(ctx, id, account)
	if err != nil {
		return fmt.Errorf("verify proxy rental: %w", err)
	}
	if rental && !allowed {
		return ErrProxyRentalUnavailable
	}
	return nil
}

// CheckProxyRental protects proxy-based auxiliary clients and individual WS
// turns. Call before sending a new request, not only when creating a connection.
func CheckProxyRental(ctx context.Context, proxyID int64) error {
	return checkProxyRentalState(ctx, proxyID, false)
}

// CheckAccountProxyRental protects reused HTTP clients and WS connections from
// stale account/proxy snapshots. The checker resolves the current assignment.
func CheckAccountProxyRental(ctx context.Context, accountID int64) error {
	return checkProxyRentalState(ctx, accountID, true)
}

// CheckProxyRentalURL checks the actual leased proxy retained by a retry, even
// after the account is rebound elsewhere. The marker is an internal fragment:
// transports do not send it to the proxy, and client normalization removes it
// only after this guard has run.
func CheckProxyRentalURL(ctx context.Context, rawURL string) error {
	if !strings.Contains(rawURL, "#"+rentalProxyFragmentPrefix) {
		return nil
	}
	_, parsed, err := proxyurl.Parse(rawURL)
	if err != nil || parsed == nil {
		return errors.New("invalid rental proxy URL")
	}
	idText, ok := strings.CutPrefix(parsed.Fragment, rentalProxyFragmentPrefix)
	if !ok {
		return errors.New("invalid rental proxy marker")
	}
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id <= 0 {
		return errors.New("invalid rental proxy marker")
	}
	return CheckProxyRental(ctx, id)
}

// A reused WS lease retains its original proxy even if the account's assignment
// changes meanwhile. Check both the current assignment and that cached proxy.
func checkAccountSnapshotProxyRental(ctx context.Context, account *Account) error {
	if err := CheckAccountProxyRental(ctx, account.ID); err != nil {
		return err
	}
	if account.Proxy != nil {
		return CheckProxyRental(ctx, account.Proxy.ID)
	}
	if account.ProxyID != nil {
		return CheckProxyRental(ctx, *account.ProxyID)
	}
	return nil
}

// ProxyNeedsRentalRedaction fails closed when lease classification is unavailable.
// The admin DTO uses its separate unredacted mapper.
func ProxyNeedsRentalRedaction(proxyID int64) bool {
	rental, _, err := proxyRentalState(context.Background(), proxyID, false)
	return rental || err != nil
}
