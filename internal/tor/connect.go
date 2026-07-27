package tor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

// dialRetryInterval is how often a starting instance is re-probed while its
// control port and auth cookie appear.
const dialRetryInterval = 200 * time.Millisecond

// Connect waits for an instance's control port to accept connections and its
// auth cookie to be written, then returns an authenticated Control.
//
// Both conditions matter and they do not happen at the same moment: tor opens
// the control port before it has finished writing the cookie file, so dialling
// alone is not enough — authentication would fail against a truncated cookie.
func Connect(ctx context.Context, cfg InstanceConfig) (*Control, error) {
	var lastErr error
	for {
		ctrl, err := tryConnect(ctx, cfg)
		if err == nil {
			return ctrl, nil
		}
		lastErr = err

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("connect to instance %d control port: %w (last attempt: %w)",
				cfg.Index, ctx.Err(), lastErr)
		case <-time.After(dialRetryInterval):
		}
	}
}

func tryConnect(ctx context.Context, cfg InstanceConfig) (*Control, error) {
	// Check the cookie first: it is the later of the two to appear, and
	// reading it is cheaper than a dial.
	info, err := os.Stat(cfg.CookiePath())
	if err != nil {
		return nil, fmt.Errorf("auth cookie not ready: %w", err)
	}
	if info.Size() == 0 {
		return nil, errors.New("auth cookie is still empty")
	}

	ctrl, err := Dial(ctx, cfg.ControlAddr())
	if err != nil {
		return nil, err
	}
	if err := ctrl.AuthenticateCookie(cfg.CookiePath()); err != nil {
		_ = ctrl.Close()
		return nil, err
	}
	return ctrl, nil
}

// WaitBootstrapped polls until the instance reports 100% bootstrap, reporting
// intermediate progress through onProgress (which may be nil).
//
// Progress is not monotonic: tor can report a lower percentage after losing a
// connection, so callers must not treat a decrease as an error.
func WaitBootstrapped(ctx context.Context, ctrl *Control, poll time.Duration, onProgress func(int)) error {
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		pct, err := ctrl.BootstrapPercent()
		if err != nil {
			return err
		}
		if onProgress != nil {
			onProgress(pct)
		}
		if pct >= 100 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("bootstrap stalled at %d%%: %w", pct, ctx.Err())
		case <-ticker.C:
		}
	}
}
