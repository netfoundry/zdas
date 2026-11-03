package zdas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// fallbackReconciler renames identities enrolled via the fallback path (unmodified
// tunnelers that didn't send device_name). After the tunneler connects and
// reports envInfo (including hostname), the reconciler renames the identity
// from its temporary name to the final name based on the hostname.
type fallbackReconciler struct {
	cfg       FallbackConfig
	claimsCfg ClaimsConfig
	client    *http.Client
	mgmtURL   string // the management API, e.g. https://ctrl:1280/edge/management/v1
	logger    *slog.Logger

	mu      sync.Mutex
	pending map[string]*pendingReconciliation

	// Session token for the management API (zt-session). Protected by sessMu.
	sessMu         sync.RWMutex
	sessionToken   string
	sessionExpires time.Time

	cancel  context.CancelFunc
	stopped chan struct{}
}

// pendingReconciliation tracks a fallback-enrolled identity awaiting
// reconciliation.
type pendingReconciliation struct {
	ExternalID string
	Username   string
	Nonce      string
	TrackedAt  time.Time
}

// newFallbackReconciler creates a fallbackReconciler that reaches the
// management API of the controller at ctrlURL, its root or an Edge API URL.
// Call start to begin background polling.
func newFallbackReconciler(cfg FallbackConfig, claimsCfg ClaimsConfig, client *http.Client, ctrlURL string, logger *slog.Logger) *fallbackReconciler {
	return &fallbackReconciler{
		cfg:       cfg,
		claimsCfg: claimsCfg,
		client:    client,
		mgmtURL:   controllerRoot(ctrlURL) + managementAPIPath,
		logger:    logger,
		pending:   make(map[string]*pendingReconciliation),
	}
}

// track adds a fallback-enrolled identity to the reconciliation queue. An
// external ID validExternalID rejects is logged and not tracked.
func (r *fallbackReconciler) track(externalID, username, nonce string) {
	if !validExternalID(externalID) {
		r.logger.Warn("not tracking fallback identity with an unsupported external ID", "external_id", externalID)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending[externalID] = &pendingReconciliation{
		ExternalID: externalID,
		Username:   username,
		Nonce:      nonce,
		TrackedAt:  time.Now(),
	}
	r.logger.Info("tracking fallback identity for reconciliation", "external_id", externalID, "username", username)
}

// start authenticates with the controller and begins the background polling
// loop. The initial authentication failure is non-fatal (logged as warning)
// since the reconciler can retry on each poll cycle.
func (r *fallbackReconciler) start(ctx context.Context) {
	if err := r.refreshSession(ctx); err != nil {
		r.logger.Warn("initial reconciler authentication failed, will retry", "error", err)
	}

	pollCtx, cancel := context.WithCancel(ctx)
	stopped := make(chan struct{})
	r.mu.Lock()
	r.cancel, r.stopped = cancel, stopped
	r.mu.Unlock()
	go r.loop(pollCtx, stopped)
}

// stop cancels the background poll loop and waits for it to exit.
func (r *fallbackReconciler) stop() {
	r.mu.Lock()
	cancel := r.cancel
	stopped := r.stopped
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if stopped != nil {
		<-stopped
	}
}

// loop polls every PollInterval until ctx is done, then closes stopped.
func (r *fallbackReconciler) loop(ctx context.Context, stopped chan<- struct{}) {
	defer close(stopped)
	interval := r.cfg.PollInterval
	if interval <= 0 {
		interval = defaultFallbackPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.poll(ctx)
		}
	}
}

func (r *fallbackReconciler) poll(ctx context.Context) {
	// Drop timed-out entries first, so that the queue cannot grow while the
	// controller is unreachable, then snapshot the rest so the lock is
	// released during API calls.
	r.mu.Lock()
	snapshot := make([]*pendingReconciliation, 0, len(r.pending))
	for _, p := range r.pending {
		if time.Since(p.TrackedAt) > r.cfg.Timeout {
			r.logger.Warn("fallback identity reconciliation timed out",
				"external_id", p.ExternalID, "username", p.Username,
				"tracked_for", time.Since(p.TrackedAt).Round(time.Second))
			delete(r.pending, p.ExternalID)
			continue
		}
		snapshot = append(snapshot, p)
	}
	r.mu.Unlock()

	if len(snapshot) == 0 {
		return
	}

	// Ensure we have a valid session.
	r.sessMu.RLock()
	expired := time.Now().Add(sessionRefreshMargin).After(r.sessionExpires)
	r.sessMu.RUnlock()
	if expired {
		if err := r.refreshSession(ctx); err != nil {
			r.logger.Warn("reconciler session refresh failed", "error", err)
			return
		}
	}

	for _, p := range snapshot {
		done, err := r.reconcileOne(ctx, p)
		if errors.Is(err, errSessionRejected) {
			// The controller dropped the session, e.g. on restart. Refresh
			// on the next poll rather than waiting for it to expire.
			r.sessMu.Lock()
			r.sessionExpires = time.Time{}
			r.sessMu.Unlock()
			r.logger.Warn("reconciler session rejected, refreshing on next poll")
			return
		}
		if err != nil {
			r.logger.Warn("reconcile failed", "external_id", p.ExternalID, "error", err)
			continue
		}
		if done {
			r.mu.Lock()
			delete(r.pending, p.ExternalID)
			r.mu.Unlock()
		}
	}
}

func (r *fallbackReconciler) reconcileOne(ctx context.Context, p *pendingReconciliation) (bool, error) {
	// Find the identity by externalId.
	identityID, hostname, err := r.findIdentity(ctx, p.ExternalID)
	if err != nil {
		return false, err
	}
	if identityID == "" {
		return false, nil // not enrolled yet, keep tracking
	}
	if hostname == "" {
		return false, nil // enrolled but no envInfo yet, keep tracking
	}

	// Build the final name using the hostname as the device name.
	finalName := expandTemplate(r.claimsCfg.NameTemplate, p.Username, &DeviceInfo{
		DeviceName: hostname,
		Hostname:   hostname,
	})

	if err := r.renameIdentity(ctx, identityID, finalName); err != nil {
		return false, err
	}
	r.logger.Info("reconciled fallback identity",
		"identity_id", identityID,
		"old_nonce", p.Nonce,
		"new_name", finalName)
	return true, nil
}

// sessionRefreshMargin is how long before its management API session
// expires the reconciler authenticates again.
const sessionRefreshMargin = 5 * time.Minute

// errSessionRejected reports a management API call the controller refused
// with 401, meaning the session is no longer valid.
var errSessionRejected = errors.New("management API session rejected")

// zitiqlString returns s as a quoted ZitiQL string literal. ZitiQL strings
// take any character but the double quote, the backslash and control
// characters, which must be escaped; it reports false for a control
// character ZitiQL has no escape for.
func zitiqlString(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, c := range s {
		switch c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(c)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if c < 0x20 {
				return "", false
			}
			b.WriteRune(c)
		}
	}
	b.WriteByte('"')
	return b.String(), true
}

// validExternalID reports whether id can be tracked: not empty, not over
// 256 bytes, and expressible as a ZitiQL string.
func validExternalID(id string) bool {
	if id == "" || len(id) > 256 {
		return false
	}
	_, ok := zitiqlString(id)
	return ok
}

// findIdentity queries the management API for an identity by externalId.
// Returns the identity ID and envInfo hostname, or empty strings if not found.
// It fails unless exactly one identity has that external ID.
func (r *fallbackReconciler) findIdentity(ctx context.Context, externalID string) (id, hostname string, err error) {
	if !validExternalID(externalID) {
		return "", "", fmt.Errorf("unsupported external ID %q", externalID)
	}
	quoted, _ := zitiqlString(externalID)
	filter := "externalId=" + quoted
	reqURL := r.mgmtURL + "/identities?filter=" + url.QueryEscape(filter)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("build identity request: %w", err)
	}
	r.sessMu.RLock()
	token := r.sessionToken
	r.sessMu.RUnlock()
	req.Header.Set("zt-session", token)
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("fetch identity: %w", err)
	}
	defer resp.Body.Close()
	body, err := readResponseBody(resp)
	if err != nil {
		return "", "", fmt.Errorf("read identity response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return "", "", errSessionRejected
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("identity query returned %d: %s", resp.StatusCode, truncateBody(body))
	}

	var result struct {
		Data []struct {
			ID         string `json:"id"`
			ExternalID string `json:"externalId"`
			EnvInfo    *struct {
				Hostname string `json:"hostname"`
			} `json:"envInfo"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", fmt.Errorf("parse identity response: %w", err)
	}
	switch {
	case len(result.Data) == 0:
		return "", "", nil
	case len(result.Data) > 1:
		return "", "", fmt.Errorf("%d identities have external ID %s", len(result.Data), externalID)
	}
	entry := result.Data[0]
	if entry.ExternalID != externalID {
		return "", "", fmt.Errorf("identity query for external ID %s returned identity %s with external ID %q", externalID, entry.ID, entry.ExternalID)
	}
	hn := ""
	if entry.EnvInfo != nil {
		hn = entry.EnvInfo.Hostname
	}
	return entry.ID, hn, nil
}

// renameIdentity patches the identity name via the management API.
func (r *fallbackReconciler) renameIdentity(ctx context.Context, identityID, newName string) error {
	patchURL := r.mgmtURL + "/identities/" + url.PathEscape(identityID)
	payload, _ := json.Marshal(map[string]string{"name": newName})

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, patchURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build patch request: %w", err)
	}
	r.sessMu.RLock()
	tok := r.sessionToken
	r.sessMu.RUnlock()
	req.Header.Set("zt-session", tok)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("patch identity: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return errSessionRejected
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := readResponseBody(resp)
		return fmt.Errorf("patch identity returned %d: %s", resp.StatusCode, truncateBody(body))
	}
	return nil
}

func (r *fallbackReconciler) refreshSession(ctx context.Context) error {
	session, err := authenticateSession(ctx, r.client, r.mgmtURL)
	if err != nil {
		return err
	}
	r.sessMu.Lock()
	r.sessionToken = session.Token
	r.sessionExpires = session.ExpiresAt
	r.sessMu.Unlock()
	r.logger.Debug("reconciler session refreshed", "expires_at", session.ExpiresAt)
	return nil
}
