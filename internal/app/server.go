package app

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*.html
var webFS embed.FS

const mailboxCodeFreshWindow = 5 * time.Minute
const mailboxCreateMinInterval = 3 * time.Second
const mailboxCreateLimitCooldown = 2 * time.Minute
const mailboxListDefaultPageSize = 10
const mailboxListMaxPageSize = 500
const bulkDeleteTimeBudget = 12 * time.Minute

var mailboxMailSyncMinInterval = 3 * time.Second
var mailboxCodeFastWait = 600 * time.Millisecond
var mailboxCodePollDebounce = 100 * time.Millisecond
var mailboxCodeLocalPollInterval = 100 * time.Millisecond
var mailboxCodeBatchSyncTimeout = 120 * time.Second
var mailboxCodeMaxClientWait = 30 * time.Second
var iCloudMailboxListAccountTimeout = 3 * time.Minute
var mailWatcherPollInterval = 3 * time.Second
var mailWatcherActiveTTL = 20 * time.Minute

const (
	defaultMailWatcherFetchLimit        = 8
	defaultMailWatcherInitialFetchLimit = 20
	defaultMailWatcherLookback          = 24 * time.Hour
	mailWatcherSyncTimeout              = 90 * time.Second
	mailboxRemoteCleanupTimeout         = 30 * time.Second
	userDeleteRemoteCleanupTimeout      = 5 * time.Minute
)

const (
	csrfCookieName = "ipm_csrf"
	csrfHeaderName = "X-CSRF-Token"
)

type Server struct {
	cfg                            Config
	store                          *FileStore
	logger                         *slog.Logger
	mux                            *http.ServeMux
	icloudProtocolLogins           *appleAuthPendingStore
	appleAccountLogins             *appleAuthPendingStore
	icloudCreateMu                 sync.Mutex
	icloudCreateGates              map[string]chan struct{}
	icloudCreateLast               map[string]time.Time
	icloudCreateCooldown           map[string]time.Time
	icloudMailSyncMu               sync.Mutex
	icloudMailSyncGates            map[string]chan struct{}
	icloudMailSyncLast             map[string]time.Time
	mailboxAccountOperationMu      sync.Mutex
	mailboxAccountOperationGates   map[string]*mailboxAccountOperationGate
	mailboxRemoteDeleteMu          sync.Mutex
	mailboxRemoteDeleteGates       map[string]*mailboxRemoteDeleteGate
	mailboxSyncMinInterval         time.Duration
	mailboxCodeFastWait            time.Duration
	mailboxCodePollDebounce        time.Duration
	mailboxCodeLocalPollInterval   time.Duration
	mailboxCodeBatchSyncTimeout    time.Duration
	mailboxCodeMu                  sync.Mutex
	mailboxCodePollers             map[string]*mailboxCodePoller
	mailWatcherMu                  sync.Mutex
	mailWatcherCancel              context.CancelFunc
	mailWatcherWake                chan struct{}
	mailWatcherEnabled             bool
	mailWatcherInterval            time.Duration
	mailWatcherFetchLimit          int
	mailWatcherInitialFetchLimit   int
	mailWatcherLookback            time.Duration
	mailWatcherActiveUntil         map[string]time.Time
	appleAccountKeepAliveMu        sync.Mutex
	appleAccountKeepAliveCancel    context.CancelFunc
	appleAccountKeepAliveEnabled   bool
	appleAccountKeepAliveInterval  time.Duration
	schedulerMu                    sync.Mutex
	mailboxSchedulers              map[string]*mailboxSchedulerJob
	userDeletionMu                 sync.Mutex
	deletingUsers                  map[string]struct{}
	mailboxAPIExportRollbackMu     sync.Mutex
	mailboxAPIExportRollbacks      map[string]mailboxAPIExportRollback
	createMailboxForOwner          func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error)
	deleteRemoteMailbox            func(ctx context.Context, mailbox Mailbox) error
	keepAliveAppleAccountState     func(ctx context.Context, state LoginState) (LoginState, error)
	startICloudProtocolLogin       func(ctx context.Context, appleID, password, defaultHost, clientID string, pendingStore *appleAuthPendingStore, twoFactorMethod, proxyURL, ownerID string) (appleAuthStartResult, error)
	submitICloudProtocol2FA        func(ctx context.Context, pending appleAuthPending, code string) (ICloudSession, error)
	startAppleAccountLogin         func(ctx context.Context, appleID, password string, pendingStore *appleAuthPendingStore, twoFactorMethod, proxyURL, ownerID string) (appleAuthStartResult, error)
	submitAppleAccount2FA          func(ctx context.Context, pending appleAuthPending, code string, phoneNumber json.RawMessage) (ICloudSession, error)
	syncMailboxMessages            func(ctx context.Context, session ICloudSession, mailbox Mailbox, after time.Time, keyword string, maxThreads int) ([]ICloudSyncedMessage, error)
	syncMailboxBatch               func(ctx context.Context, session ICloudSession, mailboxes []Mailbox, after time.Time, keyword string, maxThreads int) (map[string][]ICloudSyncedMessage, error)
	syncCodeMailboxBatch           func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error)
	syncCodeMailboxBatchWithCursor func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (iCloudIMAPSyncResult, error)
	latestIMAPUID                  func(ctx context.Context, state LoginState) (string, error)
	checkIMAPLogin                 func(ctx context.Context, email, appPassword string) error
	checkIMAPLoginWithProxy        func(ctx context.Context, email, appPassword, proxyURL string) error
	updateMu                       sync.Mutex
	updateApplyMu                  sync.Mutex
	updateCache                    updateCandidate
	updateCacheAt                  time.Time
}

type mailboxRemoteDeleteGate struct {
	ch   chan struct{}
	refs int
}

type mailboxAccountOperationGate struct {
	ch   chan struct{}
	refs int
}

const mailboxAPIExportRollbackTTL = 15 * time.Minute

type mailboxAPIExportRollback struct {
	RequesterID string
	IDs         []string
	ExportedAt  time.Time
	ExpiresAt   time.Time
}

type remoteDeleteCompletedWarning struct {
	err error
}

func (e remoteDeleteCompletedWarning) Error() string {
	if e.err == nil {
		return "远端删除已完成，但后续状态写入存在告警"
	}
	return e.err.Error()
}

func (e remoteDeleteCompletedWarning) Unwrap() error {
	return e.err
}

func isRemoteDeleteCompletedWarning(err error) bool {
	var completedWarning remoteDeleteCompletedWarning
	return errors.As(err, &completedWarning)
}

type createMailboxFailure struct {
	AccountID string `json:"account_id,omitempty"`
	AppleID   string `json:"apple_id,omitempty"`
	Channel   string `json:"channel,omitempty"`
	Code      string `json:"code,omitempty"`
	Error     string `json:"error"`
}

type mailboxCreateChannel string

const (
	mailboxCreateChannelAuto         mailboxCreateChannel = ""
	mailboxCreateChannelAppleAccount mailboxCreateChannel = "apple_account"
	mailboxCreateChannelICloudWeb    mailboxCreateChannel = "icloud_web"
)

type mailboxCreateChannelContextKey struct{}

type mailboxCreateRequest struct {
	AccountID string
	Channel   mailboxCreateChannel
}

func contextWithMailboxCreateChannel(ctx context.Context, channel mailboxCreateChannel) context.Context {
	channel = normalizeMailboxCreateChannel(channel)
	if channel == mailboxCreateChannelAuto {
		return ctx
	}
	return context.WithValue(ctx, mailboxCreateChannelContextKey{}, channel)
}

func mailboxCreateChannelFromContext(ctx context.Context) mailboxCreateChannel {
	channel, _ := ctx.Value(mailboxCreateChannelContextKey{}).(mailboxCreateChannel)
	return normalizeMailboxCreateChannel(channel)
}

func normalizeMailboxCreateChannel(channel mailboxCreateChannel) mailboxCreateChannel {
	switch channel {
	case mailboxCreateChannelAppleAccount, mailboxCreateChannelICloudWeb:
		return channel
	default:
		return mailboxCreateChannelAuto
	}
}

func mailboxCreateChannelLabel(channel mailboxCreateChannel) string {
	switch normalizeMailboxCreateChannel(channel) {
	case mailboxCreateChannelAppleAccount:
		return "新接口"
	case mailboxCreateChannelICloudWeb:
		return "旧接口"
	default:
		return "自动接口"
	}
}

type syncICloudMailboxResult struct {
	AccountID      string `json:"account_id,omitempty"`
	AppleID        string `json:"apple_id,omitempty"`
	Source         string `json:"source,omitempty"`
	Total          int    `json:"total"`
	RemoteTotal    int    `json:"remote_total"`
	LocalProcessed int    `json:"local_processed"`
	Created        int    `json:"created"`
	Updated        int    `json:"updated"`
	Skipped        int    `json:"skipped"`
	RemoteMissing  int    `json:"remote_missing"`
	RemoteEmpty    bool   `json:"remote_empty"`
	Warning        string `json:"warning,omitempty"`
	Error          string `json:"error,omitempty"`
}

type mailboxCodeWaiter struct {
	ctx           context.Context
	mailboxID     string
	after         time.Time
	keyword       string
	forceSync     bool
	skipMessageID string
	result        chan mailboxCodeResult
}

type mailboxCodeResult struct {
	message Message
	code    string
	ok      bool
	syncErr error
}

type mailboxCodePoller struct {
	ownerID string
	waiters []*mailboxCodeWaiter
}

type mailboxWatcherOwnerGroup struct {
	ownerID   string
	mailboxes []Mailbox
}

type mailboxWatcherIMAPGroup struct {
	key       string
	ownerID   string
	accountID string
	state     LoginState
	mailboxes []Mailbox
	signature string
}

type mailboxWatcherIdleWorker struct {
	cancel    context.CancelFunc
	signature string
}

func NewServer(cfg Config, store *FileStore, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{
		cfg:                           cfg,
		store:                         store,
		logger:                        logger,
		mux:                           http.NewServeMux(),
		icloudProtocolLogins:          newAppleAuthPendingStore(),
		appleAccountLogins:            newAppleAuthPendingStore(),
		icloudCreateGates:             make(map[string]chan struct{}),
		icloudCreateLast:              make(map[string]time.Time),
		icloudCreateCooldown:          make(map[string]time.Time),
		icloudMailSyncGates:           make(map[string]chan struct{}),
		icloudMailSyncLast:            make(map[string]time.Time),
		mailboxAccountOperationGates:  make(map[string]*mailboxAccountOperationGate),
		mailboxRemoteDeleteGates:      make(map[string]*mailboxRemoteDeleteGate),
		mailboxSyncMinInterval:        mailboxMailSyncMinInterval,
		mailboxCodeFastWait:           mailboxCodeFastWait,
		mailboxCodePollDebounce:       mailboxCodePollDebounce,
		mailboxCodeLocalPollInterval:  mailboxCodeLocalPollInterval,
		mailboxCodeBatchSyncTimeout:   mailboxCodeBatchSyncTimeout,
		mailboxCodePollers:            make(map[string]*mailboxCodePoller),
		mailWatcherWake:               make(chan struct{}, 1),
		mailWatcherEnabled:            cfg.MailWatcherEnabled,
		mailWatcherInterval:           mailWatcherPollInterval,
		mailWatcherFetchLimit:         defaultMailWatcherFetchLimit,
		mailWatcherInitialFetchLimit:  defaultMailWatcherInitialFetchLimit,
		mailWatcherLookback:           defaultMailWatcherLookback,
		mailWatcherActiveUntil:        make(map[string]time.Time),
		appleAccountKeepAliveEnabled:  cfg.AppleAccountKeepAliveEnabled,
		appleAccountKeepAliveInterval: appleAccountKeepAliveDefaultInterval,
		mailboxSchedulers:             make(map[string]*mailboxSchedulerJob),
		deletingUsers:                 make(map[string]struct{}),
		mailboxAPIExportRollbacks:     make(map[string]mailboxAPIExportRollback),
	}
	if cfg.PublicSyncMinIntervalMS > 0 {
		s.mailboxSyncMinInterval = time.Duration(cfg.PublicSyncMinIntervalMS) * time.Millisecond
	}
	if cfg.PublicFastSyncWaitMS > 0 {
		s.mailboxCodeFastWait = time.Duration(cfg.PublicFastSyncWaitMS) * time.Millisecond
	}
	if cfg.MailWatcherPollMS > 0 {
		s.mailWatcherInterval = time.Duration(cfg.MailWatcherPollMS) * time.Millisecond
	}
	if cfg.MailWatcherFetchLimit > 0 {
		s.mailWatcherFetchLimit = cfg.MailWatcherFetchLimit
	}
	if cfg.MailWatcherInitialFetchLimit > 0 {
		s.mailWatcherInitialFetchLimit = cfg.MailWatcherInitialFetchLimit
	}
	if cfg.MailWatcherLookbackHours > 0 {
		s.mailWatcherLookback = time.Duration(cfg.MailWatcherLookbackHours) * time.Hour
	}
	if cfg.AppleAccountKeepAliveMS > 0 {
		s.appleAccountKeepAliveInterval = time.Duration(cfg.AppleAccountKeepAliveMS) * time.Millisecond
	}
	s.createMailboxForOwner = s.createICloudMailboxForOwner
	s.deleteRemoteMailbox = s.deleteICloudMailboxRemote
	s.startICloudProtocolLogin = func(ctx context.Context, appleID, password, defaultHost, clientID string, pendingStore *appleAuthPendingStore, twoFactorMethod, proxyURL, ownerID string) (appleAuthStartResult, error) {
		return NewAppleAuthClient().StartLoginWithProxyForOwner(ctx, appleID, password, defaultHost, clientID, pendingStore, twoFactorMethod, proxyURL, ownerID)
	}
	s.submitICloudProtocol2FA = func(ctx context.Context, pending appleAuthPending, code string) (ICloudSession, error) {
		return NewAppleAuthClient().Submit2FA(ctx, pending, code)
	}
	s.startAppleAccountLogin = func(ctx context.Context, appleID, password string, pendingStore *appleAuthPendingStore, twoFactorMethod, proxyURL, ownerID string) (appleAuthStartResult, error) {
		return NewAppleAuthClient().StartAppleAccountManageLoginWithProxyForOwner(ctx, appleID, password, pendingStore, twoFactorMethod, proxyURL, ownerID)
	}
	s.submitAppleAccount2FA = func(ctx context.Context, pending appleAuthPending, code string, phoneNumber json.RawMessage) (ICloudSession, error) {
		return NewAppleAuthClient().SubmitAppleAccountManage2FA(ctx, pending, code, phoneNumber)
	}
	s.keepAliveAppleAccountState = func(ctx context.Context, state LoginState) (LoginState, error) {
		return newICloudKeepAliveClient().keepAliveAppleAccountManageStateUnlocked(ctx, state)
	}
	s.syncMailboxMessages = func(ctx context.Context, session ICloudSession, mailbox Mailbox, after time.Time, keyword string, maxThreads int) ([]ICloudSyncedMessage, error) {
		return NewICloudClient().SyncMailboxMessages(ctx, session, mailbox, after, keyword, maxThreads)
	}
	s.syncMailboxBatch = func(ctx context.Context, session ICloudSession, mailboxes []Mailbox, after time.Time, keyword string, maxThreads int) (map[string][]ICloudSyncedMessage, error) {
		return NewICloudClient().SyncMailboxMessagesBatch(ctx, session, mailboxes, after, keyword, maxThreads)
	}
	s.checkIMAPLogin = CheckICloudIMAPLogin
	s.checkIMAPLoginWithProxy = CheckICloudIMAPLoginWithProxy
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.validBrowserRequest(r) {
		writeError(w, http.StatusForbidden, errCode("csrf_invalid", "请求校验失败，请刷新页面后重试", false))
		return
	}
	if s.requiresAdmin(r) &&
		!s.authorizedAdminSession(r) &&
		!(s.allowsUserSession(r) && s.authorizedUserSession(r)) {
		writeError(w, http.StatusUnauthorized, errCode("auth_required", "请先登录账号", false))
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) validBrowserRequest(r *http.Request) bool {
	if r == nil || !strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}
	if isSafeHTTPMethod(r.Method) && !browserMailboxCodeNeedsCSRF(r) {
		return true
	}
	if !requestOriginMatches(r) {
		return false
	}
	if r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/register" || strings.HasPrefix(r.URL.Path, "/api/v1/") {
		return true
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return true
	}
	return validCSRFToken(r, cookie.Value)
}

func browserMailboxCodeNeedsCSRF(r *http.Request) bool {
	if r == nil || r.Method != http.MethodGet ||
		(!strings.HasPrefix(r.URL.Path, "/api/v1/mailboxes/") &&
			!strings.HasPrefix(r.URL.Path, "/api/mailboxes/")) ||
		!strings.HasSuffix(r.URL.Path, "/code") {
		return false
	}
	for _, name := range []string{"peek", "preview", "cache"} {
		if truthy(r.URL.Query().Get(name)) {
			return false
		}
	}
	cookie, err := r.Cookie(sessionCookieName)
	return err == nil && strings.TrimSpace(cookie.Value) != ""
}

func isSafeHTTPMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func requestOriginMatches(r *http.Request) bool {
	if r == nil {
		return false
	}
	if fetchSite := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); fetchSite == "cross-site" {
		return false
	}
	requestScheme := requestExternalScheme(r)
	expectedHost := strings.ToLower(requestExternalHost(r))
	if expectedHost == "" {
		return false
	}
	for _, headerName := range []string{"Origin", "Referer"} {
		value := strings.TrimSpace(r.Header.Get(headerName))
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || parsed == nil || parsed.Scheme == "" || parsed.Host == "" {
			return false
		}
		if !strings.EqualFold(parsed.Scheme, requestScheme) || !strings.EqualFold(parsed.Host, expectedHost) {
			return false
		}
		if headerName == "Origin" {
			break
		}
	}
	return true
}

func requestExternalScheme(r *http.Request) string {
	if r == nil {
		return ""
	}
	if proto := forwardedHeaderParameter(r.Header.Get("Forwarded"), "proto"); isHTTPOriginScheme(proto) {
		return strings.ToLower(proto)
	}
	if proto := firstForwardedHeaderValue(r.Header.Get("X-Forwarded-Proto")); isHTTPOriginScheme(proto) {
		return strings.ToLower(proto)
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func requestExternalHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host := forwardedHeaderParameter(r.Header.Get("Forwarded"), "host"); validForwardedHost(host) {
		return host
	}
	if host := firstForwardedHeaderValue(r.Header.Get("X-Forwarded-Host")); validForwardedHost(host) {
		return host
	}
	return strings.TrimSpace(r.Host)
}

func firstForwardedHeaderValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if comma := strings.IndexByte(value, ','); comma >= 0 {
		value = value[:comma]
	}
	return strings.Trim(strings.TrimSpace(value), `"`)
}

func forwardedHeaderParameter(value, name string) string {
	value = firstForwardedHeaderValue(value)
	if value == "" {
		return ""
	}
	name = strings.ToLower(strings.TrimSpace(name))
	for _, parameter := range strings.Split(value, ";") {
		parts := strings.SplitN(parameter, "=", 2)
		if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), name) {
			continue
		}
		return strings.Trim(strings.TrimSpace(parts[1]), `"`)
	}
	return ""
}

func isHTTPOriginScheme(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func validForwardedHost(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && !strings.ContainsAny(value, "\r\n")
}

func validCSRFToken(r *http.Request, sessionToken string) bool {
	expected := csrfTokenForSession(sessionToken)
	cookie, cookieErr := r.Cookie(csrfCookieName)
	header := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if cookieErr != nil {
		return false
	}
	if cookieErr != nil || !constantTimeEqual(cookie.Value, expected) {
		return false
	}
	return constantTimeEqual(header, expected)
}

func csrfTokenForSession(sessionToken string) string {
	return sessionTokenHash("csrf:" + strings.TrimSpace(sessionToken))
}

func (s *Server) StartMailWatcher(ctx context.Context) {
	if !s.mailWatcherEnabled {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mailWatcherMu.Lock()
	if s.mailWatcherCancel != nil {
		s.mailWatcherMu.Unlock()
		return
	}
	watchCtx, cancel := context.WithCancel(ctx)
	s.mailWatcherCancel = cancel
	s.mailWatcherMu.Unlock()

	go s.runMailWatcher(watchCtx)
}

func (s *Server) StopMailWatcher() {
	s.mailWatcherMu.Lock()
	cancel := s.mailWatcherCancel
	s.mailWatcherCancel = nil
	s.mailWatcherMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Server) StartAppleAccountKeepAlive(ctx context.Context) {
	if !s.appleAccountKeepAliveEnabled {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.appleAccountKeepAliveMu.Lock()
	if s.appleAccountKeepAliveCancel != nil {
		s.appleAccountKeepAliveMu.Unlock()
		return
	}
	keepAliveCtx, cancel := context.WithCancel(ctx)
	s.appleAccountKeepAliveCancel = cancel
	s.appleAccountKeepAliveMu.Unlock()

	go s.runAppleAccountKeepAlive(keepAliveCtx)
}

func (s *Server) StopAppleAccountKeepAlive() {
	s.appleAccountKeepAliveMu.Lock()
	cancel := s.appleAccountKeepAliveCancel
	s.appleAccountKeepAliveCancel = nil
	s.appleAccountKeepAliveMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /", s.handleHome)
	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("GET /manage", s.handleManagePage)
	s.mux.HandleFunc("GET /api/auth/me", s.handleAuthMe)
	s.mux.HandleFunc("POST /api/auth/register", s.handleAuthRegister)
	s.mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleAuthLogout)
	s.mux.HandleFunc("DELETE /api/admin/users/{id}", s.handleAdminDeleteUser)
	s.mux.HandleFunc("GET /api/status", s.handleStatus)
	s.mux.HandleFunc("GET /api/update/status", s.handleUpdateStatus)
	s.mux.HandleFunc("POST /api/update/apply", s.handleApplyUpdate)
	s.mux.HandleFunc("GET /api/create-settings", s.handleCreateSettings)
	s.mux.HandleFunc("POST /api/create-settings", s.handleSaveCreateSettings)
	s.mux.HandleFunc("GET /api/manage/data", s.handleManageData)
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("POST /api/v1/mailboxes/claim", s.handleClaimMailbox)
	s.mux.HandleFunc("POST /api/v1/mailboxes/lookup", s.handleLookupMailboxes)
	s.mux.HandleFunc("GET /api/runtime/export", s.handleExportRuntimeData)
	s.mux.HandleFunc("POST /api/runtime/export", s.handleExportRuntimeData)
	s.mux.HandleFunc("GET /api/runtime/export-mailbox-apis", s.handleExportMailboxAPIs)
	s.mux.HandleFunc("GET /api/runtime/export-mailbox-emails", s.handleExportMailboxEmails)
	s.mux.HandleFunc("POST /api/runtime/export-mailbox-apis", s.handleExportMailboxAPIs)
	s.mux.HandleFunc("POST /api/runtime/export-mailbox-emails", s.handleExportMailboxEmails)
	s.mux.HandleFunc("POST /api/runtime/unmark-mailbox-apis", s.handleUnmarkMailboxAPIs)
	s.mux.HandleFunc("GET /api/icloud/session", s.handleICloudSession)
	s.mux.HandleFunc("POST /api/icloud/protocol-login/start", s.handleStartICloudProtocolLogin)
	s.mux.HandleFunc("POST /api/icloud/protocol-login/2fa", s.handleSubmitICloudProtocol2FA)
	s.mux.HandleFunc("POST /api/apple-account/login/start", s.handleStartAppleAccountLogin)
	s.mux.HandleFunc("POST /api/apple-account/login/2fa", s.handleSubmitAppleAccount2FA)
	s.mux.HandleFunc("POST /api/icloud/session/check", s.handleCheckICloudSession)
	s.mux.HandleFunc("POST /api/icloud/imap-login/save", s.handleSaveICloudIMAPLogin)
	s.mux.HandleFunc("POST /api/icloud/imap-login/check", s.handleCheckICloudIMAPLogin)
	s.mux.HandleFunc("POST /api/icloud/mailboxes/create", s.handleCreateICloudMailbox)
	s.mux.HandleFunc("POST /api/icloud/mailboxes/sync", s.handleSyncICloudMailboxes)
	s.mux.HandleFunc("GET /api/icloud/scheduler/status", s.handleMailboxSchedulerStatus)
	s.mux.HandleFunc("POST /api/icloud/scheduler/start", s.handleStartMailboxScheduler)
	s.mux.HandleFunc("POST /api/icloud/scheduler/stop", s.handleStopMailboxScheduler)
	s.mux.HandleFunc("POST /api/icloud/scheduler/logs/clear", s.handleClearMailboxSchedulerLogs)
	s.mux.HandleFunc("GET /api/accounts", s.handleListAccounts)
	s.mux.HandleFunc("POST /api/accounts", s.handleCreateAccount)
	s.mux.HandleFunc("PATCH /api/accounts/{id}", s.handleUpdateAccount)
	s.mux.HandleFunc("GET /api/mailboxes", s.handleListMailboxes)
	s.mux.HandleFunc("POST /api/mailboxes", s.handleCreateMailbox)
	s.mux.HandleFunc("POST /api/mailboxes/bulk-delete", s.handleBulkDeleteMailboxes)
	s.mux.HandleFunc("POST /api/mailboxes/remote-clean", s.handleCleanRemoteMailboxes)
	s.mux.HandleFunc("POST /api/mailboxes/{id}/verify", s.handleVerifyMailbox)
	s.mux.HandleFunc("POST /api/mailboxes/{id}/disable", s.handleDisableMailbox)
	s.mux.HandleFunc("POST /api/mailboxes/{id}/status", s.handleSetMailboxStatus)
	s.mux.HandleFunc("POST /api/mailboxes/{id}/bind", s.handleBindMailbox)
	s.mux.HandleFunc("POST /api/mailboxes/{id}/sync", s.handleSyncMailbox)
	s.mux.HandleFunc("POST /api/mailboxes/{id}/remote-clean", s.handleCleanRemoteMailbox)
	s.mux.HandleFunc("DELETE /api/mailboxes/{id}", s.handleDeleteMailbox)
	s.mux.HandleFunc("GET /api/mailboxes/{id}/messages", s.handleListMessages)
	s.mux.HandleFunc("POST /api/mailboxes/{id}/messages", s.handleCreateMessage)
	s.mux.HandleFunc("GET /api/mailboxes/{id}/code", s.handleMailboxCodeByID)
	s.mux.HandleFunc("GET /api/v1/mailboxes/{email}/code", s.handleMailboxCodeByEmail)
}

func (s *Server) handleHome(w http.ResponseWriter, _ *http.Request) {
	s.writeTemplate(w, "templates/index.html")
}

func (s *Server) handleLoginPage(w http.ResponseWriter, _ *http.Request) {
	s.writeTemplate(w, "templates/login.html")
}

func (s *Server) handleManagePage(w http.ResponseWriter, _ *http.Request) {
	s.writeTemplate(w, "templates/manage.html")
}

func (s *Server) handleCreateSettings(w http.ResponseWriter, r *http.Request) {
	ownerID := requestOwnerID(r, s.store)
	if ownerID == "" {
		writeError(w, http.StatusUnauthorized, errCode("auth_required", "请先登录账号", false))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"settings": publicCreateSettings(s.store.CreateSettingsForOwner(ownerID)),
	})
}

func (s *Server) handleSaveCreateSettings(w http.ResponseWriter, r *http.Request) {
	ownerID := requestOwnerID(r, s.store)
	if ownerID == "" {
		writeError(w, http.StatusUnauthorized, errCode("auth_required", "请先登录账号", false))
		return
	}
	if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	var payload struct {
		Label                         string   `json:"label"`
		Note                          string   `json:"note"`
		AccountIDs                    []string `json:"account_ids"`
		CreateChannel                 string   `json:"create_channel"`
		SchedulerCreateChannel        string   `json:"scheduler_create_channel"`
		AppleAccountTwoFactorMethod   string   `json:"apple_account_two_factor_method"`
		ICloudWebTwoFactorMethod      string   `json:"icloud_web_two_factor_method"`
		SchedulerIntervalMinutes      int      `json:"scheduler_interval_minutes"`
		SchedulerRoundIntervalSeconds int      `json:"scheduler_round_interval_seconds"`
		MailboxPageSize               int      `json:"mailbox_page_size"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	accountIDs := normalizeAccountIDSelection("", payload.AccountIDs)
	for _, accountID := range accountIDs {
		if !s.canAccessAccountID(r, accountID) || !s.accountInRequestScope(r, accountID) {
			writeError(w, http.StatusNotFound, errCode("account_not_found", "账号不存在，配置未保存", false))
			return
		}
	}
	var releaseOwnerOperation func()
	if ownerID != "" {
		var gateErr error
		releaseOwnerOperation, gateErr = s.acquireMailboxAccountOperationSlot(
			r.Context(),
			mailboxAccountOperationKey(ownerID, ""),
		)
		if gateErr != nil {
			writeError(w, http.StatusConflict, gateErr)
			return
		}
		defer releaseOwnerOperation()
		if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
	}
	settings, err := s.store.SaveCreateSettingsForOwner(ownerID, CreateSettings{
		Label:                         payload.Label,
		Note:                          payload.Note,
		AccountIDs:                    accountIDs,
		CreateChannel:                 payload.CreateChannel,
		SchedulerCreateChannel:        payload.SchedulerCreateChannel,
		AppleAccountTwoFactorMethod:   payload.AppleAccountTwoFactorMethod,
		ICloudWebTwoFactorMethod:      payload.ICloudWebTwoFactorMethod,
		SchedulerIntervalMinutes:      payload.SchedulerIntervalMinutes,
		SchedulerRoundIntervalSeconds: payload.SchedulerRoundIntervalSeconds,
		MailboxPageSize:               payload.MailboxPageSize,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"message":  "创建配置已保存到服务器",
		"settings": publicCreateSettings(settings),
	})
}

func (s *Server) writeTemplate(w http.ResponseWriter, name string) {
	data, err := webFS.ReadFile(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errCode("template_missing", "面板模板缺失", false))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) handleAuthRegister(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	user, err := s.store.CreateUser(payload.Username, payload.Password)
	if err != nil {
		status := http.StatusBadRequest
		if isCodedError(err, "user_create_persist_failed") {
			status = http.StatusInternalServerError
		}
		writeError(w, status, err)
		return
	}
	token, session, err := s.store.CreateWebSession(user.ID, user.IsAdmin, 30*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.setSessionCookie(w, r, token, session.ExpiresAt)
	writeJSON(w, http.StatusCreated, map[string]any{
		"success": true,
		"user":    publicUserFromUser(user),
		"message": firstNonEmpty(map[bool]string{true: "注册成功，当前账号是管理员", false: "注册成功"}[user.IsAdmin]),
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	user, err := s.store.AuthenticateUser(payload.Username, payload.Password)
	if err != nil {
		status := http.StatusUnauthorized
		if isCodedError(err, "user_login_persist_failed") {
			status = http.StatusInternalServerError
		}
		writeError(w, status, err)
		return
	}
	token, session, err := s.store.CreateWebSession(user.ID, user.IsAdmin, 30*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.setSessionCookie(w, r, token, session.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"user":    publicUserFromUser(user),
	})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if session, user, ok := s.currentWebSession(r); ok {
		out := publicUserFromUser(user)
		out.IsAdmin = session.IsAdmin || user.IsAdmin
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "authenticated": true, "user": out})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "authenticated": false})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if err := s.store.DeleteWebSession(cookie.Value); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	s.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	session, currentUser, ok := s.currentWebSession(r)
	if !ok || (!session.IsAdmin && !currentUser.IsAdmin) {
		writeError(w, http.StatusForbidden, errCode("admin_required", "需要管理员权限", false))
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, errCode("user_id_missing", "缺少账号 ID", false))
		return
	}
	if constantTimeEqual(currentUser.ID, id) {
		writeError(w, http.StatusBadRequest, errCode("cannot_delete_self", "不能删除当前登录的管理员账号", false))
		return
	}
	user, ok := s.store.UserByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, errCode("user_not_found", "账号不存在", false))
		return
	}
	if user.IsAdmin {
		writeError(w, http.StatusBadRequest, errCode("cannot_delete_admin_user", "不能删除管理员账号", false))
		return
	}
	releaseUserDeletion, err := s.beginUserDeletion(id)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	defer releaseUserDeletion()

	if job := s.mailboxScheduler(id); job != nil {
		job.stop("所属平台账号正在删除")
	}
	cleanupBase := context.Background()
	if r.Context() != nil {
		cleanupBase = context.WithoutCancel(r.Context())
	}
	cleanupCtx, cancel := context.WithTimeout(cleanupBase, userDeleteRemoteCleanupTimeout)
	defer cancel()
	if err := s.waitForOwnerMailboxOperations(cleanupCtx, id); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	ownerState := s.store.SnapshotForOwner(id)
	remoteFailures := make([]mailboxDeleteFailure, 0)
	remoteDeleted := 0
	for _, mailbox := range ownerState.Mailboxes {
		if strings.TrimSpace(mailbox.RemoteAnonymousID) == "" {
			continue
		}
		if err := s.deleteRemoteMailboxForRequest(cleanupCtx, mailbox); err != nil {
			remoteFailures = append(remoteFailures, mailboxDeleteFailure{
				ID:      mailbox.ID,
				Email:   mailbox.Email,
				Message: publicErrorMessage(err),
			})
			continue
		}
		remoteDeleted++
	}
	if len(remoteFailures) > 0 {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"success":        false,
			"partial":        true,
			"message":        "远端隐私邮箱删除失败，本地账号及归属数据未删除",
			"deleted":        0,
			"remote_deleted": remoteDeleted,
			"failed":         len(remoteFailures),
			"failures":       remoteFailures,
		})
		return
	}
	result, err := s.store.DeleteUser(id)
	if err != nil {
		status := http.StatusBadRequest
		if isCodedError(err, "user_delete_persist_failed") {
			status = http.StatusInternalServerError
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":        true,
		"deleted":        result,
		"remote_deleted": remoteDeleted,
	})
}

func (s *Server) beginUserDeletion(ownerID string) (func(), error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return nil, errCode("user_id_missing", "缺少账号 ID", false)
	}
	s.userDeletionMu.Lock()
	defer s.userDeletionMu.Unlock()
	if s.deletingUsers == nil {
		s.deletingUsers = make(map[string]struct{})
	}
	if _, exists := s.deletingUsers[ownerID]; exists {
		return nil, errCode("user_delete_in_progress", "该平台账号正在删除，请稍后重试", true)
	}
	s.deletingUsers[ownerID] = struct{}{}
	var once sync.Once
	return func() {
		once.Do(func() {
			s.userDeletionMu.Lock()
			delete(s.deletingUsers, ownerID)
			s.userDeletionMu.Unlock()
		})
	}, nil
}

func (s *Server) ownerDeletionInProgress(ownerID string) bool {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return false
	}
	s.userDeletionMu.Lock()
	defer s.userDeletionMu.Unlock()
	_, exists := s.deletingUsers[ownerID]
	return exists
}

func (s *Server) ensureOwnerNotDeleting(ownerID string) error {
	if s.ownerDeletionInProgress(ownerID) {
		return errCode("user_delete_in_progress", "该平台账号正在删除，请稍后重试", true)
	}
	return nil
}

func (s *Server) waitForOwnerMailboxOperations(ctx context.Context, ownerID string) error {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return nil
	}
	state := s.store.SnapshotForOwner(ownerID)
	keys := make(map[string]struct{})
	addKey := func(accountID string) {
		keys[mailboxAccountOperationKey(ownerID, accountID)] = struct{}{}
	}
	addKey("")
	for _, account := range state.Accounts {
		if strings.TrimSpace(account.OwnerID) == ownerID {
			addKey(account.ID)
		}
	}
	for _, session := range state.ICloudSessions {
		if strings.TrimSpace(session.OwnerID) == ownerID {
			addKey(session.AccountID)
		}
	}
	if state.ICloudSession != nil && strings.TrimSpace(state.ICloudSession.OwnerID) == ownerID {
		addKey(state.ICloudSession.AccountID)
	}
	for _, mailbox := range state.Mailboxes {
		if strings.TrimSpace(mailbox.OwnerID) == ownerID {
			addKey(mailbox.AccountID)
		}
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	for _, key := range ordered {
		release, err := s.acquireMailboxAccountOperationSlot(ctx, key)
		if err != nil {
			return errCode("user_delete_operation_wait_failed", "等待该平台账号的进行中操作结束失败，请稍后重试", true)
		}
		release()
	}
	return nil
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	state := s.homeScopedState(r)
	sessions := s.publicSessionsForHomeRequest(r)
	currentUser := publicUser{}
	authenticated := false
	if session, user, ok := s.currentWebSession(r); ok {
		authenticated = true
		currentUser = publicUserFromUser(user)
		currentUser.IsAdmin = session.IsAdmin || user.IsAdmin
	}
	session := publicSession(nil)
	if len(sessions) > 0 {
		session = sessions[0]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":            true,
		"service":            "icloud-privacy-mail",
		"api_key_configured": strings.TrimSpace(s.cfg.APIKey) != "",
		"base_url":           requestBaseURL(r),
		"account_scoped":     scopedOwnerID(r, s.store) != "",
		"authenticated":      authenticated,
		"current_user":       currentUser,
		"accounts":           len(state.Accounts),
		"mailboxes":          len(state.Mailboxes),
		"messages":           len(state.Messages),
		"icloud_session":     session,
		"icloud_sessions":    sessions,
		"version":            currentVersionInfo(),
	})
}

func (s *Server) handleManageData(w http.ResponseWriter, r *http.Request) {
	state := s.scopedState(r)
	users := state.Users
	if s.isAdminRequest(r) {
		users = s.store.Users()
	}
	publicUsers := make([]publicUser, 0, len(users))
	for _, user := range users {
		publicUsers = append(publicUsers, publicUserFromUser(user))
	}
	accounts := make([]publicAccount, 0, len(state.Accounts))
	for _, account := range state.Accounts {
		accounts = append(accounts, s.publicAccount(account))
	}
	mailboxes := make([]publicMailbox, 0, len(state.Mailboxes))
	for _, mailbox := range state.Mailboxes {
		mailboxes = append(mailboxes, s.publicMailbox(r, mailbox))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":         true,
		"is_admin":        s.isAdminRequest(r),
		"users":           publicUsers,
		"user_summaries":  s.publicUserSummaries(users, state),
		"accounts":        accounts,
		"mailboxes":       mailboxes,
		"messages":        len(state.Messages),
		"icloud_session":  s.publicSessionForRequest(r),
		"icloud_sessions": s.publicSessionsForManagementRequest(r),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.cfg.APIKey) != "" && !s.authorizedGlobalAPI(r) {
		writeError(w, http.StatusUnauthorized, errCode("invalid_api_key", "API Key 错误", false))
		return
	}
	session, ok := s.store.ICloudSession()
	icloudActive := ok && sessionCanCreatePrivacyMailbox(session)
	if !icloudActive {
		for _, scopedSession := range s.store.Snapshot().ICloudSessions {
			if sessionCanCreatePrivacyMailbox(scopedSession) {
				icloudActive = true
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":       true,
		"service":       "icloud-privacy-mail",
		"api_active":    strings.TrimSpace(s.cfg.APIKey) != "",
		"icloud_active": icloudActive,
		"time":          formatTime(time.Now()),
	})
}

func (s *Server) handleClaimMailbox(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedGlobalAPI(r) {
		writeError(w, http.StatusUnauthorized, errCode("global_api_key_required", "自动取号需要配置并提交全局 API Key", false))
		return
	}
	var payload struct {
		Project string `json:"project"`
		Purpose string `json:"purpose"`
		Count   int    `json:"count"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		_ = r.Body.Close()
	}
	note := strings.TrimSpace(payload.Project)
	if strings.TrimSpace(payload.Purpose) != "" {
		note = strings.TrimSpace(note + " " + payload.Purpose)
	}
	if note == "" {
		note = "外部 API 已领取"
	} else {
		note = "外部 API 已领取：" + note
	}
	var mailbox Mailbox
	var err error
	for _, candidate := range s.store.AvailableMailboxCandidates() {
		if ctxErr := r.Context().Err(); ctxErr != nil {
			writeError(w, http.StatusConflict, ctxErr)
			return
		}
		if deletionErr := s.ensureOwnerNotDeleting(candidate.OwnerID); deletionErr != nil {
			if isCodedError(deletionErr, "user_delete_in_progress") {
				continue
			}
			writeError(w, http.StatusConflict, deletionErr)
			return
		}
		releaseAccountOperation, acquired, gateErr := s.tryAcquireMailboxAccountOperationSlot(
			mailboxAccountOperationKey(candidate.OwnerID, candidate.AccountID),
		)
		if gateErr != nil {
			writeError(w, http.StatusConflict, gateErr)
			return
		}
		if !acquired {
			continue
		}
		if deletionErr := s.ensureOwnerNotDeleting(candidate.OwnerID); deletionErr != nil {
			releaseAccountOperation()
			if isCodedError(deletionErr, "user_delete_in_progress") {
				continue
			}
			writeError(w, http.StatusConflict, deletionErr)
			return
		}
		mailbox, err = s.store.ClaimAvailableMailboxForID(candidate.ID, note)
		releaseAccountOperation()
		if err == nil {
			break
		}
		if isCodedError(err, "mailbox_not_found") || isCodedError(err, "mailbox_not_available") {
			continue
		}
		break
	}
	if err != nil {
		status := http.StatusInternalServerError
		if isCodedError(err, "no_available_mailbox") || isCodedError(err, "mailbox_not_found") || isCodedError(err, "mailbox_not_available") {
			status = http.StatusOK
			err = errCode("no_available_mailbox", "没有可用隐私邮箱", false)
		}
		writeError(w, status, err)
		return
	}
	if mailbox.ID == "" {
		writeError(w, http.StatusOK, errCode("no_available_mailbox", "没有可用隐私邮箱", false))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"mailbox": s.publicExternalMailbox(r, mailbox),
	})
}

func (s *Server) handleLookupMailboxes(w http.ResponseWriter, r *http.Request) {
	if !s.authorizedGlobalAPI(r) {
		writeError(w, http.StatusUnauthorized, errCode("global_api_key_required", "查询邮箱 API 需要配置并提交全局 API Key", false))
		return
	}
	var payload struct {
		Emails []string `json:"emails"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(payload.Emails) == 0 || len(payload.Emails) > 500 {
		writeError(w, http.StatusBadRequest, errCode("invalid_email_count", "邮箱数量必须是 1-500", false))
		return
	}

	seen := make(map[string]struct{}, len(payload.Emails))
	missing := make([]string, 0)
	mailboxes := make([]publicMailbox, 0, len(payload.Emails))
	for _, rawEmail := range payload.Emails {
		email := strings.ToLower(strings.TrimSpace(rawEmail))
		if email == "" {
			continue
		}
		if _, ok := seen[email]; ok {
			continue
		}
		seen[email] = struct{}{}
		mailbox, ok := s.store.FindMailboxByEmail(email)
		if !ok {
			missing = append(missing, email)
			continue
		}
		mailboxes = append(mailboxes, s.publicExternalMailbox(r, mailbox))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"mailboxes": mailboxes,
		"missing":   missing,
	})
}

func (s *Server) handleExportRuntimeData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, errCode("runtime_export_requires_post", "运行时数据导出必须使用 POST", false))
		return
	}
	state := s.homeScopedState(r)
	exportSession := state.ICloudSession
	if exportSession == nil && len(state.ICloudSessions) > 0 {
		first := cloneICloudSession(state.ICloudSessions[0])
		exportSession = &first
	}
	payload := struct {
		ExportedAt      string          `json:"exported_at"`
		Scope           string          `json:"scope"`
		Owner           string          `json:"owner,omitempty"`
		DataPath        string          `json:"data_path,omitempty"`
		NextID          int             `json:"next_id"`
		Accounts        []Account       `json:"accounts"`
		Mailboxes       []Mailbox       `json:"mailboxes"`
		ICloudSession   *ICloudSession  `json:"icloud_session,omitempty"`
		ICloudSessions  []ICloudSession `json:"icloud_sessions,omitempty"`
		MessageCount    int             `json:"message_count"`
		Messages        []Message       `json:"messages,omitempty"`
		IncludeMessages bool            `json:"include_messages"`
	}{
		ExportedAt:      formatTime(time.Now()),
		Scope:           "user",
		NextID:          state.NextID,
		Accounts:        state.Accounts,
		Mailboxes:       state.Mailboxes,
		ICloudSession:   exportSession,
		ICloudSessions:  state.ICloudSessions,
		MessageCount:    len(state.Messages),
		IncludeMessages: truthy(r.URL.Query().Get("include_messages")),
	}
	switch s.adminOwnerScope(r) {
	case "all":
		payload.Scope = "all"
		payload.DataPath = s.store.Path()
	case "__global":
		payload.Scope = "global"
	default:
		if ownerID := s.adminOwnerScope(r); ownerID != "" {
			payload.Owner = s.ownerName(ownerID)
		} else if ownerID := scopedOwnerID(r, s.store); ownerID != "" {
			payload.Owner = s.ownerName(ownerID)
		} else {
			payload.Scope = "all"
			payload.DataPath = s.store.Path()
		}
	}
	if payload.IncludeMessages {
		payload.Messages = state.Messages
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	filename := "icloud-privacy-mail-state-" + time.Now().Format("20060102-150405") + ".json"
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	setSensitiveDownloadHeaders(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(data, '\n'))
}

func (s *Server) handleExportMailboxAPIs(w http.ResponseWriter, r *http.Request) {
	s.writeMailboxTextExport(w, r, mailboxExportAPI)
}

func (s *Server) handleUnmarkMailboxAPIs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, errCode("mailbox_api_export_requires_post", "邮箱 API 导出必须使用 POST", false))
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, errCode("mailbox_api_export_requires_json", "邮箱 API 导出必须使用 application/json", false))
		return
	}
	request, err := parseMailboxExportRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	rollback, hasRollback := s.takeMailboxAPIExportRollback(request.RollbackToken, requestOwnerID(r, s.store))
	if request.ExportedAt.IsZero() && !hasRollback {
		writeError(w, http.StatusBadRequest, errCode("invalid_export_request", "缺少导出时间，无法回滚 API 导出状态", false))
		return
	}
	state := s.mailboxExportState(r, request.OwnerID)
	exportOwnerID := ""
	if !s.isAdminRequest(r) {
		exportOwnerID = scopedOwnerID(r, s.store)
	}
	mailboxes := filterMailboxesForExport(state.Mailboxes, request.AccountID, request.IDs)
	mailboxes = filterMailboxesBySearchKeyword(mailboxes, mailboxAccountMap(state.Accounts), request.Search)
	ids := make([]string, 0, len(mailboxes))
	for _, mailbox := range mailboxes {
		if id := strings.TrimSpace(mailbox.ID); id != "" {
			ids = append(ids, id)
		}
	}
	if hasRollback {
		if request.ExportedAt.IsZero() {
			request.ExportedAt = rollback.ExportedAt
		}
		if len(ids) == 0 {
			ids = append([]string(nil), rollback.IDs...)
		}
	}
	var unmarked int
	if exportOwnerID != "" {
		unmarked, err = s.store.UnmarkMailboxesAPIExportedAtForOwner(exportOwnerID, ids, request.ExportedAt)
	} else {
		unmarked, err = s.store.UnmarkMailboxesAPIExportedAt(ids, request.ExportedAt)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "unmarked": unmarked})
}

func (s *Server) handleExportMailboxEmails(w http.ResponseWriter, r *http.Request) {
	s.writeMailboxTextExport(w, r, mailboxExportEmail)
}

type mailboxExportMode string

const (
	mailboxExportAPI   mailboxExportMode = "api"
	mailboxExportEmail mailboxExportMode = "email"
)

type mailboxExportFormat struct {
	ext         string
	contentType string
	separator   string
	csv         bool
	jsonl       bool
}

func (s *Server) writeMailboxTextExport(w http.ResponseWriter, r *http.Request, mode mailboxExportMode) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		code := "mailbox_export_requires_post"
		message := "邮箱导出必须使用 POST"
		if mode == mailboxExportAPI {
			code = "mailbox_api_export_requires_post"
			message = "邮箱 API 导出必须使用 POST"
		}
		writeError(w, http.StatusMethodNotAllowed, errCode(code, message, false))
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		code := "mailbox_export_requires_json"
		message := "邮箱导出必须使用 application/json"
		if mode == mailboxExportAPI {
			code = "mailbox_api_export_requires_json"
			message = "邮箱 API 导出必须使用 application/json"
		}
		writeError(w, http.StatusUnsupportedMediaType, errCode(code, message, false))
		return
	}
	request, err := parseMailboxExportRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := validateMailboxExportedFilter(request.ExportedFilter); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	format, err := parseMailboxExportFormat(request.Format)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	state := s.mailboxExportState(r, request.OwnerID)
	exportOwnerID := ""
	if !s.isAdminRequest(r) {
		exportOwnerID = scopedOwnerID(r, s.store)
		if err := s.ensureOwnerNotDeleting(exportOwnerID); err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
	}
	accountID := request.AccountID
	selectedIDs := request.IDs
	if request.IDsRequested && len(selectedIDs) == 0 {
		writeError(w, http.StatusBadRequest, errCode("mailbox_ids_missing", "请选择要导出的邮箱", false))
		return
	}
	mailboxes := filterMailboxesForExport(state.Mailboxes, accountID, selectedIDs)
	mailboxes = filterMailboxesByAPIExportedState(mailboxes, request.ExportedFilter)
	mailboxes = filterMailboxesBySearchKeyword(mailboxes, mailboxAccountMap(state.Accounts), request.Search)
	if request.IDsRequested && len(mailboxes) == 0 {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "选择的邮箱不存在或无权限", false))
		return
	}
	if request.IDsRequested {
		matchedIDs := make(map[string]struct{}, len(mailboxes))
		for _, mailbox := range mailboxes {
			if id := strings.TrimSpace(mailbox.ID); id != "" {
				matchedIDs[id] = struct{}{}
			}
		}
		if len(matchedIDs) != len(selectedIDs) {
			writeError(w, http.StatusConflict, errCode("mailbox_selection_changed", "选择的邮箱已变化或不符合当前筛选条件，请刷新后重试", true))
			return
		}
	}
	var releaseExportOperations func()
	stable := false
	for attempt := 0; attempt < 4; attempt++ {
		release, acquireErr := s.acquireMailboxExportAccountOperations(r.Context(), mailboxes)
		if acquireErr != nil {
			writeError(w, http.StatusConflict, errCode("mailbox_operation_in_progress", "选中的邮箱账号正在执行同步、登录、创建或删除操作，请稍后重试", true))
			return
		}
		if err := s.ensureOwnerNotDeleting(exportOwnerID); err != nil {
			release()
			writeError(w, http.StatusConflict, err)
			return
		}
		state = s.mailboxExportState(r, request.OwnerID)
		currentMailboxes := filterMailboxesForExport(state.Mailboxes, accountID, selectedIDs)
		currentMailboxes = filterMailboxesByAPIExportedState(currentMailboxes, request.ExportedFilter)
		currentMailboxes = filterMailboxesBySearchKeyword(currentMailboxes, mailboxAccountMap(state.Accounts), request.Search)
		if request.IDsRequested {
			if len(currentMailboxes) == 0 {
				release()
				writeError(w, http.StatusConflict, errCode("mailbox_selection_changed", "选择的邮箱已变化或不符合当前筛选条件，请刷新后重试", true))
				return
			}
			matchedIDs := make(map[string]struct{}, len(currentMailboxes))
			for _, mailbox := range currentMailboxes {
				if id := strings.TrimSpace(mailbox.ID); id != "" {
					matchedIDs[id] = struct{}{}
				}
			}
			if len(matchedIDs) != len(selectedIDs) {
				release()
				writeError(w, http.StatusConflict, errCode("mailbox_selection_changed", "选择的邮箱已变化或不符合当前筛选条件，请刷新后重试", true))
				return
			}
		}
		if mailboxAccountOperationKeysEqual(mailboxes, currentMailboxes) {
			mailboxes = currentMailboxes
			releaseExportOperations = release
			stable = true
			break
		}
		release()
		mailboxes = currentMailboxes
	}
	if !stable {
		writeError(w, http.StatusConflict, errCode("mailbox_operation_in_progress", "选中的邮箱正在切换 Apple 账号归属，请稍后重试", true))
		return
	}
	defer func() {
		if releaseExportOperations != nil {
			releaseExportOperations()
		}
	}()
	var out strings.Builder
	exportedIDs := make([]string, 0, len(mailboxes))
	exportedRecordCount := 0
	if format.jsonl {
		for _, mailbox := range mailboxes {
			record := s.mailboxExportRecord(r, mailbox, mode)
			if len(record) == 0 {
				continue
			}
			exportedRecordCount++
			if id := strings.TrimSpace(mailbox.ID); id != "" {
				exportedIDs = append(exportedIDs, id)
			}
			var line any
			if mode == mailboxExportEmail {
				line = map[string]string{"email": record[0]}
			} else {
				line = map[string]string{
					"email":     record[0],
					"api_url":   record[1],
					"api_token": record[2],
				}
			}
			data, err := json.Marshal(line)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			out.Write(data)
			out.WriteByte('\n')
		}
	} else if format.csv {
		writer := csv.NewWriter(&out)
		if format.separator == "\t" {
			writer.Comma = '\t'
		}
		for _, mailbox := range mailboxes {
			record := s.mailboxExportRecord(r, mailbox, mode)
			if len(record) == 0 {
				continue
			}
			exportedRecordCount++
			if id := strings.TrimSpace(mailbox.ID); id != "" {
				exportedIDs = append(exportedIDs, id)
			}
			if err := writer.Write(record); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	} else {
		for _, mailbox := range mailboxes {
			record := s.mailboxExportRecord(r, mailbox, mode)
			if len(record) == 0 {
				continue
			}
			exportedRecordCount++
			if id := strings.TrimSpace(mailbox.ID); id != "" {
				exportedIDs = append(exportedIDs, id)
			}
			out.WriteString(strings.Join(record, format.separator))
			out.WriteByte('\n')
		}
	}
	if exportedRecordCount == 0 {
		writeError(w, http.StatusNotFound, errCode("mailbox_export_empty", "当前筛选条件下没有可导出的邮箱", false))
		return
	}

	now := time.Now()
	markedAPIExport := false
	var previousExportState map[string]mailboxAPIExportState
	if mode == mailboxExportAPI && len(exportedIDs) > 0 {
		previousExportState = make(map[string]mailboxAPIExportState, len(exportedIDs))
		exportedIDSet := make(map[string]struct{}, len(exportedIDs))
		for _, id := range exportedIDs {
			id = strings.TrimSpace(id)
			if id != "" {
				exportedIDSet[id] = struct{}{}
			}
		}
		if len(exportedIDSet) > 0 {
			for _, mailbox := range mailboxes {
				id := strings.TrimSpace(mailbox.ID)
				if id == "" {
					continue
				}
				if _, ok := exportedIDSet[id]; !ok {
					continue
				}
				previousExportState[id] = mailboxAPIExportState{
					APIExportedAt: mailbox.APIExportedAt,
					UpdatedAt:     mailbox.UpdatedAt,
				}
			}
		}
		var markErr error
		if exportOwnerID != "" {
			_, markErr = s.store.MarkMailboxesAPIExportedForOwner(exportOwnerID, exportedIDs, now)
		} else {
			_, markErr = s.store.MarkMailboxesAPIExported(exportedIDs, now)
		}
		if markErr != nil {
			writeError(w, http.StatusInternalServerError, markErr)
			return
		}
		markedAPIExport = true
		if token := normalizeExportRollbackToken(request.RollbackToken); token != "" {
			s.rememberMailboxAPIExportRollback(token, mailboxAPIExportRollback{
				RequesterID: requestOwnerID(r, s.store),
				IDs:         append([]string(nil), exportedIDs...),
				ExportedAt:  now,
				ExpiresAt:   now.Add(mailboxAPIExportRollbackTTL),
			})
		}
	}

	prefix := "icloud-mailbox-apis"
	if mode == mailboxExportEmail {
		prefix = "icloud-mailbox-emails"
	}
	if accountID != "" {
		prefix += "-" + safeFilenamePart(accountID)
	}
	if len(selectedIDs) > 0 {
		prefix += "-selected"
	}
	filename := prefix + "-" + now.Format("20060102-150405") + "." + format.ext
	w.Header().Set("Content-Type", format.contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	setSensitiveDownloadHeaders(w)
	if markedAPIExport {
		w.Header().Set("X-IPM-API-Exported-At", now.Format(time.RFC3339Nano))
	}
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, out.String()); err != nil {
		if markedAPIExport {
			s.forgetMailboxAPIExportRollback(request.RollbackToken)
			if _, rollbackErr := s.store.RestoreMailboxesAPIExportState(previousExportState); rollbackErr != nil && s.logger != nil {
				s.logger.Warn("mailbox export state rollback failed", "mode", mode, "err", rollbackErr)
			}
		}
		if s.logger != nil {
			s.logger.Warn("mailbox export response write failed", "mode", mode, "err", err)
		}
		return
	}
}

func setSensitiveDownloadHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func isJSONContentType(value string) bool {
	mediaType := strings.TrimSpace(strings.SplitN(value, ";", 2)[0])
	return strings.EqualFold(mediaType, "application/json")
}

func (s *Server) acquireMailboxExportAccountOperations(ctx context.Context, mailboxes []Mailbox) (func(), error) {
	return s.acquireMailboxAccountOperations(ctx, mailboxAccountOperationKeys(mailboxes))
}

func (s *Server) acquireMailboxAccountOperations(ctx context.Context, keys []string) (func(), error) {
	uniqueKeys := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		uniqueKeys[key] = struct{}{}
	}
	orderedKeys := make([]string, 0, len(uniqueKeys))
	for key := range uniqueKeys {
		orderedKeys = append(orderedKeys, key)
	}
	sort.Slice(orderedKeys, func(i, j int) bool {
		return mailboxAccountOperationKeyLess(orderedKeys[i], orderedKeys[j])
	})
	releases := make([]func(), 0, len(orderedKeys))
	for _, key := range orderedKeys {
		release, err := s.acquireMailboxAccountOperationSlot(ctx, key)
		if err != nil {
			for index := len(releases) - 1; index >= 0; index-- {
				releases[index]()
			}
			return nil, err
		}
		releases = append(releases, release)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for index := len(releases) - 1; index >= 0; index-- {
				releases[index]()
			}
		})
	}, nil
}

func mailboxAccountOperationKeyLess(left, right string) bool {
	leftOwner, leftAccount, _ := strings.Cut(left, "\x00")
	rightOwner, rightAccount, _ := strings.Cut(right, "\x00")
	if leftOwner != rightOwner {
		return leftOwner < rightOwner
	}
	if leftAccount == "" && rightAccount != "" {
		return false
	}
	if leftAccount != "" && rightAccount == "" {
		return true
	}
	return left < right
}

func mailboxAccountOperationKeys(mailboxes []Mailbox) []string {
	keys := make(map[string]struct{}, len(mailboxes))
	for _, mailbox := range mailboxes {
		keys[mailboxAccountOperationKey(mailbox.OwnerID, mailbox.AccountID)] = struct{}{}
	}
	orderedKeys := make([]string, 0, len(keys))
	for key := range keys {
		orderedKeys = append(orderedKeys, key)
	}
	sort.Strings(orderedKeys)
	return orderedKeys
}

func mailboxAccountOperationKeysEqual(left, right []Mailbox) bool {
	leftKeys := mailboxAccountOperationKeys(left)
	rightKeys := mailboxAccountOperationKeys(right)
	if len(leftKeys) != len(rightKeys) {
		return false
	}
	for index := range leftKeys {
		if leftKeys[index] != rightKeys[index] {
			return false
		}
	}
	return true
}

type mailboxExportRequest struct {
	Format         string
	AccountID      string
	OwnerID        string
	ExportedFilter string
	Search         string
	IDs            map[string]struct{}
	IDsRequested   bool
	ExportedAt     time.Time
	RollbackToken  string
}

func parseMailboxExportRequest(r *http.Request) (mailboxExportRequest, error) {
	request := mailboxExportRequest{
		Format:         strings.TrimSpace(r.URL.Query().Get("format")),
		AccountID:      normalizeExportAccountID(firstNonEmpty(r.URL.Query().Get("account_id"), r.URL.Query().Get("account_key"))),
		OwnerID:        strings.TrimSpace(r.URL.Query().Get("owner_id")),
		ExportedFilter: strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("api_exported"), r.URL.Query().Get("exported"))),
		Search:         strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("search"), r.URL.Query().Get("q"))),
		IDs:            parseMailboxIDs(r.URL.Query()),
		IDsRequested:   mailboxIDsRequested(r.URL.Query()),
	}
	if r.Method != http.MethodPost || r.Body == nil {
		return request, nil
	}

	var payload struct {
		Format        string          `json:"format"`
		AccountID     string          `json:"account_id"`
		AccountKey    string          `json:"account_key"`
		OwnerID       string          `json:"owner_id"`
		Exported      json.RawMessage `json:"exported"`
		APIExported   json.RawMessage `json:"api_exported"`
		Search        string          `json:"search"`
		Q             string          `json:"q"`
		IDs           json.RawMessage `json:"ids"`
		MailboxIDs    json.RawMessage `json:"mailbox_ids"`
		ExportedAt    string          `json:"exported_at"`
		RollbackToken string          `json:"rollback_token"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 8<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		if errors.Is(err, io.EOF) {
			return request, nil
		}
		return mailboxExportRequest{}, errCode("invalid_export_request", "导出请求格式不正确", false)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return mailboxExportRequest{}, errCode("invalid_export_request", "导出请求格式不正确", false)
	}
	if format := strings.TrimSpace(payload.Format); format != "" {
		request.Format = format
	}
	if accountID := normalizeExportAccountID(firstNonEmpty(payload.AccountID, payload.AccountKey)); accountID != "" || payload.AccountID != "" || payload.AccountKey != "" {
		request.AccountID = accountID
	}
	if ownerID := strings.TrimSpace(payload.OwnerID); ownerID != "" {
		request.OwnerID = ownerID
	}
	if exportedFilter, ok, err := mailboxExportedFilterFromJSON(firstNonEmptyRawMessage(payload.APIExported, payload.Exported)); err != nil {
		return mailboxExportRequest{}, err
	} else if ok {
		request.ExportedFilter = exportedFilter
	}
	if search := strings.TrimSpace(firstNonEmpty(payload.Search, payload.Q)); search != "" {
		request.Search = search
	}
	request.RollbackToken = normalizeExportRollbackToken(payload.RollbackToken)
	ids, idsPresent, err := parseMailboxIDsJSON(payload.IDs)
	if err != nil {
		return mailboxExportRequest{}, err
	}
	mailboxIDs, mailboxIDsPresent, err := parseMailboxIDsJSON(payload.MailboxIDs)
	if err != nil {
		return mailboxExportRequest{}, err
	}
	if idsPresent || mailboxIDsPresent {
		request.IDsRequested = true
		request.IDs = make(map[string]struct{}, len(ids)+len(mailboxIDs))
		for _, id := range append(ids, mailboxIDs...) {
			id = strings.TrimSpace(id)
			if id != "" {
				request.IDs[id] = struct{}{}
			}
		}
	}
	if exportedAt := strings.TrimSpace(payload.ExportedAt); exportedAt != "" {
		parsed, parseErr := time.Parse(time.RFC3339Nano, exportedAt)
		if parseErr != nil {
			parsed, parseErr = time.Parse(time.RFC3339, exportedAt)
		}
		if parseErr != nil {
			return mailboxExportRequest{}, errCode("invalid_export_request", "导出请求格式不正确", false)
		}
		request.ExportedAt = parsed
	}
	return request, nil
}

func normalizeExportRollbackToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) < 8 || len(raw) > 128 {
		return ""
	}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return ""
		}
	}
	return raw
}

func (s *Server) rememberMailboxAPIExportRollback(token string, mark mailboxAPIExportRollback) {
	token = normalizeExportRollbackToken(token)
	if token == "" || s == nil {
		return
	}
	if mark.ExpiresAt.IsZero() {
		mark.ExpiresAt = time.Now().Add(mailboxAPIExportRollbackTTL)
	}
	s.mailboxAPIExportRollbackMu.Lock()
	defer s.mailboxAPIExportRollbackMu.Unlock()
	if s.mailboxAPIExportRollbacks == nil {
		s.mailboxAPIExportRollbacks = make(map[string]mailboxAPIExportRollback)
	}
	now := time.Now()
	for existing, item := range s.mailboxAPIExportRollbacks {
		if item.ExpiresAt.Before(now) {
			delete(s.mailboxAPIExportRollbacks, existing)
		}
	}
	s.mailboxAPIExportRollbacks[token] = mark
}

func (s *Server) forgetMailboxAPIExportRollback(token string) {
	token = normalizeExportRollbackToken(token)
	if token == "" || s == nil {
		return
	}
	s.mailboxAPIExportRollbackMu.Lock()
	defer s.mailboxAPIExportRollbackMu.Unlock()
	delete(s.mailboxAPIExportRollbacks, token)
}

func (s *Server) takeMailboxAPIExportRollback(token, requesterID string) (mailboxAPIExportRollback, bool) {
	token = normalizeExportRollbackToken(token)
	requesterID = strings.TrimSpace(requesterID)
	if token == "" || s == nil {
		return mailboxAPIExportRollback{}, false
	}
	s.mailboxAPIExportRollbackMu.Lock()
	defer s.mailboxAPIExportRollbackMu.Unlock()
	mark, ok := s.mailboxAPIExportRollbacks[token]
	if !ok {
		return mailboxAPIExportRollback{}, false
	}
	delete(s.mailboxAPIExportRollbacks, token)
	if mark.ExpiresAt.Before(time.Now()) {
		return mailboxAPIExportRollback{}, false
	}
	if requesterID != "" && strings.TrimSpace(mark.RequesterID) != "" && !constantTimeEqual(requesterID, mark.RequesterID) {
		return mailboxAPIExportRollback{}, false
	}
	return mark, true
}

func parseMailboxIDsJSON(raw json.RawMessage) ([]string, bool, error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	if strings.TrimSpace(string(raw)) == "null" {
		return nil, true, nil
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil, false, errCode("invalid_export_request", "导出请求格式不正确", false)
	}
	return ids, true, nil
}

func (s *Server) mailboxExportState(r *http.Request, ownerID string) State {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		ownerID = strings.TrimSpace(r.URL.Query().Get("owner_id"))
	}
	if strings.EqualFold(ownerID, "current") {
		ownerID = ""
	}
	if s.isAdminRequest(r) && ownerID == "__global" {
		return s.store.SnapshotForGlobal()
	}
	if s.isAdminRequest(r) && strings.EqualFold(ownerID, "all") {
		return s.scopedState(r)
	}
	if s.isAdminRequest(r) && ownerID != "" {
		return s.store.SnapshotForOwner(ownerID)
	}
	if s.isAdminRequest(r) {
		if requestOwner := requestOwnerID(r, s.store); requestOwner != "" {
			return s.store.SnapshotForOwner(requestOwner)
		}
	}
	return s.scopedState(r)
}

func normalizeExportAccountID(value string) string {
	value = strings.TrimSpace(value)
	switch strings.ToLower(value) {
	case "", "all", "__all", "__current", "current":
		return ""
	case "unbound":
		return "unbound"
	default:
		return value
	}
}

func parseMailboxIDs(values url.Values) map[string]struct{} {
	raw := strings.TrimSpace(firstNonEmpty(values.Get("ids"), values.Get("mailbox_ids")))
	if raw == "" {
		return nil
	}
	out := make(map[string]struct{})
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', ';', ' ', '\n', '\t':
			return true
		default:
			return false
		}
	}) {
		part = strings.TrimSpace(part)
		if part != "" {
			out[part] = struct{}{}
		}
	}
	return out
}

func mailboxIDsRequested(values url.Values) bool {
	return values.Has("ids") || values.Has("mailbox_ids")
}

func firstNonEmptyRawMessage(values ...json.RawMessage) json.RawMessage {
	for _, value := range values {
		if len(value) == 0 {
			continue
		}
		if strings.TrimSpace(string(value)) == "" {
			continue
		}
		return value
	}
	return nil
}

func mailboxExportedFilterFromJSON(raw json.RawMessage) (string, bool, error) {
	if len(raw) == 0 {
		return "", false, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return "", true, nil
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return strings.TrimSpace(asString), true, nil
	}
	var asBool bool
	if err := json.Unmarshal(raw, &asBool); err == nil {
		if asBool {
			return "1", true, nil
		}
		return "0", true, nil
	}
	return "", false, errCode("invalid_export_request", "导出请求格式不正确", false)
}

func validateMailboxExportedFilter(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "all", "1", "true", "yes", "exported", "done", "has", "0", "false", "no", "unexported", "pending", "none":
		return nil
	default:
		return errCode("invalid_export_filter", "导出状态筛选只支持 all、exported 或 unexported", false)
	}
}

func filterMailboxesForExport(mailboxes []Mailbox, accountID string, selectedIDs map[string]struct{}) []Mailbox {
	accountID = strings.TrimSpace(accountID)
	selected := len(selectedIDs) > 0
	if accountID == "" && !selected {
		return mailboxes
	}
	out := make([]Mailbox, 0, len(mailboxes))
	for _, mailbox := range mailboxes {
		if accountID != "" {
			mailboxAccountID := strings.TrimSpace(mailbox.AccountID)
			if accountID == "unbound" {
				if mailboxAccountID != "" {
					continue
				}
			} else if !constantTimeEqual(accountID, mailboxAccountID) {
				continue
			}
		}
		if selected {
			if _, ok := selectedIDs[strings.TrimSpace(mailbox.ID)]; !ok {
				continue
			}
		}
		out = append(out, mailbox)
	}
	return out
}

func filterMailboxesByAPIExportedState(mailboxes []Mailbox, exportedFilter string) []Mailbox {
	switch strings.ToLower(strings.TrimSpace(exportedFilter)) {
	case "", "all":
		return mailboxes
	case "1", "true", "yes", "exported", "done", "has":
		out := make([]Mailbox, 0, len(mailboxes))
		for _, mailbox := range mailboxes {
			if !mailbox.APIExportedAt.IsZero() {
				out = append(out, mailbox)
			}
		}
		return out
	case "0", "false", "no", "unexported", "pending", "none":
		out := make([]Mailbox, 0, len(mailboxes))
		for _, mailbox := range mailboxes {
			if mailbox.APIExportedAt.IsZero() {
				out = append(out, mailbox)
			}
		}
		return out
	default:
		return mailboxes
	}
}

func filterMailboxesBySearchKeyword(mailboxes []Mailbox, accountsByID map[string]Account, keyword string) []Mailbox {
	keyword = strings.ToLower(strings.TrimSpace(keyword))
	if keyword == "" {
		return mailboxes
	}
	out := make([]Mailbox, 0, len(mailboxes))
	for _, mailbox := range mailboxes {
		if mailboxListMatchesSearch(mailbox, accountsByID, keyword) {
			out = append(out, mailbox)
		}
	}
	return out
}

func safeFilenamePart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func (s *Server) mailboxExportRecord(r *http.Request, mailbox Mailbox, mode mailboxExportMode) []string {
	email := strings.TrimSpace(mailbox.Email)
	if email == "" {
		return nil
	}
	if mode == mailboxExportEmail {
		return []string{email}
	}
	return []string{email, s.mailboxAPIURL(r, mailbox), mailbox.APIToken}
}

func parseMailboxExportFormat(value string) (mailboxExportFormat, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "txt", "text", "list":
		return mailboxExportFormat{ext: "txt", contentType: "text/plain; charset=utf-8", separator: "----"}, nil
	case "csv":
		return mailboxExportFormat{ext: "csv", contentType: "text/csv; charset=utf-8", separator: ",", csv: true}, nil
	case "tsv", "tab":
		return mailboxExportFormat{ext: "tsv", contentType: "text/tab-separated-values; charset=utf-8", separator: "\t", csv: true}, nil
	case "jsonl", "ndjson":
		return mailboxExportFormat{ext: "jsonl", contentType: "application/x-ndjson; charset=utf-8", jsonl: true}, nil
	default:
		return mailboxExportFormat{}, errCode("invalid_export_format", "导出格式只支持 txt、csv、tsv、jsonl", false)
	}
}

func (s *Server) handleICloudSession(w http.ResponseWriter, r *http.Request) {
	sessions := s.publicSessionsForHomeRequest(r)
	session := publicSession(nil)
	if len(sessions) > 0 {
		session = sessions[0]
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "session": session, "sessions": sessions})
}

func (s *Server) handleCheckICloudSession(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID string `json:"account_id"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		_ = r.Body.Close()
	}
	ownerID := requestOwnerID(r, s.store)
	accountID := strings.TrimSpace(payload.AccountID)
	sessions := s.sessionsForRequestScope(r, accountID)
	if len(sessions) == 0 {
		writeError(w, http.StatusBadRequest, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先保存旧接口或新接口登录态", true))
		return
	}

	checkedAt := time.Now()
	client := newICloudKeepAliveClient()
	failed := 0
	var lastErr error
	for _, session := range sessions {
		sessionOwnerID := s.dataOwnerIDForSession(ownerID, session)
		releaseAccountOperation, gateErr := s.acquireMailboxAccountOperationSlot(
			r.Context(),
			mailboxAccountOperationKey(sessionOwnerID, session.AccountID),
		)
		if gateErr != nil {
			writeError(w, http.StatusConflict, gateErr)
			return
		}
		if err := s.ensureOwnerNotDeleting(sessionOwnerID); err != nil {
			releaseAccountOperation()
			writeError(w, http.StatusConflict, err)
			return
		}
		currentSession, ok := s.sessionForOwnerAccount(sessionOwnerID, session.AccountID)
		if !ok {
			releaseAccountOperation()
			failed++
			lastErr = errCode("icloud_session_missing", "该账号的 iCloud 登录态已不存在，请重新保存登录态", true)
			continue
		}
		session = currentSession
		checkedSession, ok, err := checkSavedLoginStatesWithKeepAliveInterval(r.Context(), client, session, checkedAt, s.checkSavedIMAPLoginWithProxy, s.appleAccountKeepAliveInterval)
		if !ok {
			failed++
			lastErr = err
		}
		saveErr := s.store.SaveICloudSessionForOwner(sessionOwnerID, checkedSession)
		releaseAccountOperation()
		if saveErr != nil {
			writeError(w, http.StatusInternalServerError, saveErr)
			return
		}
		if !ok {
			s.logger.Warn("login state check failed", "account_id", session.AccountID, "err", err)
		}
	}
	publicSessions := s.publicSessionsForHomeRequest(r)
	if accountID != "" {
		publicSessions = s.publicSessionsForCheckedSessions(s.dataOwnerIDForCheckedSessions(r, sessions), sessions)
	}
	first := publicSession(nil)
	if len(publicSessions) > 0 {
		first = publicSessions[0]
	}
	if failed == len(sessions) {
		message := "全部登录态检测失败"
		if lastErr != nil {
			message += "：" + publicErrorMessage(lastErr)
		}
		s.logger.Warn("login state check failed", "err", lastErr)
		writeError(w, http.StatusBadGateway, errCode("icloud_session_check_failed", message, true))
		return
	}
	message := icloudSessionCheckOKMessage(failed, len(sessions), publicSessions)
	writeJSON(w, http.StatusOK, map[string]any{
		"success":       true,
		"checked_at":    formatTime(checkedAt),
		"message":       message,
		"session":       first,
		"sessions":      publicSessions,
		"checked_count": len(sessions),
		"failed_count":  failed,
	})
}

func icloudSessionCheckOKMessage(failed, total int, sessions []publicICloudSession) string {
	retrying := 0
	deferred := 0
	for _, session := range sessions {
		if session.AppleAccountKeepAliveRetrying && !session.AppleAccountLoginOK {
			retrying++
		}
		if strings.Contains(session.LastStatusMessage, "暂时失败") {
			deferred++
		}
	}
	if failed > 0 {
		msg := fmt.Sprintf("登录态部分检测成功：成功 %d，失败 %d", total-failed, failed)
		if retrying > 0 {
			msg += fmt.Sprintf("，新接口保活重试中 %d 个", retrying)
		}
		if deferred > 0 {
			msg += fmt.Sprintf("，检测暂时失败 %d 个", deferred)
		}
		return msg
	}
	switch {
	case deferred > 0 && retrying > 0:
		return fmt.Sprintf("登录态部分正常：新接口保活重试中 %d 个，检测暂时失败 %d 个", retrying, deferred)
	case deferred > 0:
		for _, session := range sessions {
			if strings.Contains(session.LastStatusMessage, "部分正常") {
				return "登录态部分正常：新接口检测暂时失败，已推迟保活"
			}
		}
		return "新接口检测暂时失败，已推迟保活"
	case retrying == 0:
		return "登录态检测正常"
	case retrying == total:
		return "新接口保活重试中"
	default:
		return fmt.Sprintf("登录态部分正常：新接口保活重试中 %d 个", retrying)
	}
}

func (s *Server) handleSaveICloudIMAPLogin(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID   string `json:"account_id"`
		Email       string `json:"email"`
		AppPassword string `json:"app_password"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ownerID := requestOwnerID(r, s.store)
	accountID := strings.TrimSpace(payload.AccountID)
	ownerID = s.dataOwnerIDForAccount(ownerID, accountID)
	if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	email := normalizeICloudIMAPEmail(payload.Email)
	appPassword := strings.TrimSpace(payload.AppPassword)
	if email == "" {
		writeError(w, http.StatusBadRequest, errCode("imap_email_missing", "请输入 iCloud 邮箱账号", false))
		return
	}
	if appPassword == "" {
		writeError(w, http.StatusBadRequest, errCode("imap_app_password_missing", "请输入 App 专用密码", false))
		return
	}
	if accountID != "" && (!s.canAccessAccountID(r, accountID) || !s.accountInRequestScope(r, accountID)) {
		writeError(w, http.StatusForbidden, errCode("account_forbidden", "无权操作该 Apple 账号", false))
		return
	}
	if accountID == "" {
		if err := s.store.AppleIDOwnedByOtherOwner(ownerID, email); err != nil {
			writeError(w, appleIDConflictHTTPStatus(err), err)
			return
		}
	}

	now := time.Now()
	session, err := s.sessionForIMAPSave(ownerID, accountID, email)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	releaseAccountOperation, gateErr := s.acquireMailboxAccountOperationSlot(
		r.Context(),
		mailboxAccountOperationKey(s.dataOwnerIDForSession(ownerID, session), session.AccountID),
	)
	if gateErr != nil {
		writeError(w, http.StatusConflict, gateErr)
		return
	}
	sessionOwnerID := s.dataOwnerIDForSession(ownerID, session)
	if err := s.ensureOwnerNotDeleting(sessionOwnerID); err != nil {
		releaseAccountOperation()
		writeError(w, http.StatusConflict, err)
		return
	}
	currentSession, currentErr := s.sessionForIMAPSave(ownerID, accountID, email)
	if currentErr != nil {
		releaseAccountOperation()
		writeError(w, http.StatusBadRequest, currentErr)
		return
	}
	session = currentSession
	proxyURL := strings.TrimSpace(session.ProxyURL)
	if accountID != "" {
		if account, ok := s.store.FindAccountByID(accountID); ok {
			proxyURL = strings.TrimSpace(account.ProxyURL)
		}
	}
	proxyURL, err = normalizeProxyURL(proxyURL)
	if err != nil {
		releaseAccountOperation()
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.checkSavedIMAPLoginWithProxy(r.Context(), email, appPassword, proxyURL); err != nil {
		releaseAccountOperation()
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if session.SavedAt.IsZero() {
		session.SavedAt = now
	}
	session.OwnerID = ownerID
	session.ProxyURL = proxyURL
	session.AppleID = firstNonEmpty(strings.TrimSpace(session.AppleID), email)
	session = withICloudIMAPLoginState(session, LoginState{
		Kind:              LoginStateICloudIMAP,
		Host:              defaultICloudIMAPHost,
		Origin:            "imaps://" + defaultICloudIMAPHost,
		ProxyURL:          proxyURL,
		SavedAt:           now,
		IMAPEmail:         email,
		IMAPUsername:      email,
		IMAPHost:          defaultICloudIMAPHost,
		IMAPPort:          defaultICloudIMAPPort,
		IMAPAppPassword:   appPassword,
		LastCheckedAt:     now,
		LastCheckOK:       true,
		LastStatusMessage: "取码登录正常",
	})
	session.LastCheckedAt = now
	session.LastCheckOK = true
	session.LastStatusMessage = "取码登录正常"
	saveErr := s.store.SaveICloudSessionForOwner(ownerID, session)
	releaseAccountOperation()
	if saveErr != nil {
		status := http.StatusInternalServerError
		if isCodedError(saveErr, "apple_id_exists_other_owner") || isCodedError(saveErr, "apple_id_exists") {
			status = appleIDConflictHTTPStatus(saveErr)
		}
		writeError(w, status, saveErr)
		return
	}
	sessions := s.publicSessionsForOwner(ownerID)
	publicSession := publicSessionForAccountID(sessions, session.AccountID)
	if strings.TrimSpace(session.AccountID) == "" {
		publicSession = publicSessionForAppleID(sessions, session.AppleID)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"message":  "取码登录已保存并检测正常",
		"session":  publicSession,
		"sessions": sessions,
	})
}

func (s *Server) handleCheckICloudIMAPLogin(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID string `json:"account_id"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		_ = r.Body.Close()
	}
	ownerID := requestOwnerID(r, s.store)
	accountID := strings.TrimSpace(payload.AccountID)
	sessions := s.sessionsForRequestScope(r, accountID)
	if len(sessions) == 0 {
		writeError(w, http.StatusBadRequest, errCode("imap_session_missing", "未保存取码登录，请先保存 iCloud 邮箱账号和 App 专用密码", true))
		return
	}

	checkedAt := time.Now()
	checks := 0
	failed := 0
	var lastErr error
	for _, session := range sessions {
		state, ok := iCloudIMAPLoginState(session)
		if !ok {
			continue
		}
		releaseAccountOperation, gateErr := s.acquireMailboxAccountOperationSlot(
			r.Context(),
			mailboxAccountOperationKey(s.dataOwnerIDForSession(ownerID, session), session.AccountID),
		)
		if gateErr != nil {
			writeError(w, http.StatusConflict, gateErr)
			return
		}
		sessionOwnerID := s.dataOwnerIDForSession(ownerID, session)
		if err := s.ensureOwnerNotDeleting(sessionOwnerID); err != nil {
			releaseAccountOperation()
			writeError(w, http.StatusConflict, err)
			return
		}
		currentSession, currentOK := s.sessionForOwnerAccount(sessionOwnerID, session.AccountID)
		if !currentOK {
			releaseAccountOperation()
			continue
		}
		session = currentSession
		state, ok = iCloudIMAPLoginState(session)
		if !ok {
			releaseAccountOperation()
			continue
		}
		checks++
		if err := s.checkSavedIMAPLoginWithProxy(r.Context(), state.IMAPEmail, state.IMAPAppPassword, firstNonEmpty(state.ProxyURL, session.ProxyURL)); err != nil {
			failed++
			lastErr = err
			state.LastCheckedAt = checkedAt
			state.LastCheckOK = false
			state.LastStatusMessage = "取码登录异常：" + publicErrorMessage(err)
		} else {
			state.LastCheckedAt = checkedAt
			state.LastCheckOK = true
			state.LastStatusMessage = "取码登录正常"
		}
		session = withICloudIMAPLoginState(session, state)
		saveErr := s.store.SaveICloudSessionForOwner(s.dataOwnerIDForSession(ownerID, session), session)
		releaseAccountOperation()
		if saveErr != nil {
			writeError(w, http.StatusInternalServerError, saveErr)
			return
		}
	}
	if checks == 0 {
		writeError(w, http.StatusBadRequest, errCode("imap_session_missing", "未保存取码登录，请先保存 iCloud 邮箱账号和 App 专用密码", true))
		return
	}
	publicSessions := s.publicSessionsForHomeRequest(r)
	if accountID != "" {
		publicSessions = s.publicSessionsForCheckedSessions(s.dataOwnerIDForCheckedSessions(r, sessions), sessions)
	}
	if failed == checks {
		message := "取码登录检测失败"
		if lastErr != nil {
			message += "：" + publicErrorMessage(lastErr)
		}
		writeError(w, http.StatusBadGateway, errCode("imap_session_check_failed", message, true))
		return
	}
	message := "取码登录检测正常"
	if failed > 0 {
		message = fmt.Sprintf("取码登录部分检测成功：成功 %d，失败 %d", checks-failed, failed)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":       true,
		"message":       message,
		"checked_at":    formatTime(checkedAt),
		"sessions":      publicSessions,
		"checked_count": checks,
		"failed_count":  failed,
	})
}

func (s *Server) checkSavedIMAPLogin(ctx context.Context, email, appPassword string) error {
	if s.checkIMAPLogin != nil {
		return s.checkIMAPLogin(ctx, email, appPassword)
	}
	return CheckICloudIMAPLogin(ctx, email, appPassword)
}

func (s *Server) checkSavedIMAPLoginWithProxy(ctx context.Context, email, appPassword, proxyURL string) error {
	if strings.TrimSpace(proxyURL) == "" {
		return s.checkSavedIMAPLogin(ctx, email, appPassword)
	}
	if s.checkIMAPLoginWithProxy != nil {
		return s.checkIMAPLoginWithProxy(ctx, email, appPassword, proxyURL)
	}
	if s.checkIMAPLogin != nil {
		return s.checkIMAPLogin(ctx, email, appPassword)
	}
	return CheckICloudIMAPLoginWithProxy(ctx, email, appPassword, proxyURL)
}

func (s *Server) sessionForIMAPSave(ownerID, accountID, email string) (ICloudSession, error) {
	accountID = strings.TrimSpace(accountID)
	email = normalizeICloudIMAPEmail(email)
	if accountID != "" {
		accountAppleID := ""
		if account, ok := s.store.FindAccountByID(accountID); ok {
			accountAppleID = strings.TrimSpace(account.AppleID)
		}
		if session, ok := s.sessionForOwnerAccount(ownerID, accountID); ok {
			session.AppleID = firstNonEmpty(strings.TrimSpace(session.AppleID), accountAppleID, email)
			return session, nil
		}
		return ICloudSession{OwnerID: ownerID, AccountID: accountID, AppleID: firstNonEmpty(accountAppleID, email)}, nil
	}
	if session, ok := s.sessionForOwnerCreateEmailLocalPart(ownerID, email); ok {
		return session, nil
	}
	if session, ok, err := s.sessionForOwnerIMAPEmail(ownerID, email); err != nil {
		return ICloudSession{}, err
	} else if ok {
		return session, nil
	}
	return ICloudSession{OwnerID: ownerID, AppleID: email}, nil
}

func (s *Server) sessionForOwnerCreateEmailLocalPart(ownerID, email string) (ICloudSession, bool) {
	local := emailLocalPart(email)
	if local == "" {
		return ICloudSession{}, false
	}
	if match, ok := s.sessionForOwnerCreateEmailLocalPartMatch(ownerID, local, false); ok {
		return match, true
	}
	return s.sessionForOwnerCreateEmailLocalPartMatch(ownerID, local, true)
}

func (s *Server) sessionForOwnerCreateEmailLocalPartMatch(ownerID, local string, allowAppleSecondaryPrefix bool) (ICloudSession, bool) {
	var match ICloudSession
	found := false
	for _, session := range s.sessionsForOwner(ownerID, "") {
		if !appleAccountLoginSaved(session) && !iCloudWebLoginSaved(session) {
			continue
		}
		if !emailLocalPartsMatch(emailLocalPart(session.AppleID), local, allowAppleSecondaryPrefix) {
			continue
		}
		if found && !sameICloudSessionPublicIdentity(match, session) {
			return ICloudSession{}, false
		}
		match = session
		found = true
	}
	return match, found
}

func emailLocalPartsMatch(accountLocal, imapLocal string, allowAppleSecondaryPrefix bool) bool {
	accountLocal = strings.ToLower(strings.TrimSpace(accountLocal))
	imapLocal = strings.ToLower(strings.TrimSpace(imapLocal))
	if accountLocal == "" || imapLocal == "" {
		return false
	}
	if accountLocal == imapLocal {
		return true
	}
	if !allowAppleSecondaryPrefix {
		return false
	}
	return "q"+accountLocal == imapLocal
}

func (s *Server) sessionForOwnerIMAPEmail(ownerID, email string) (ICloudSession, bool, error) {
	email = normalizeICloudIMAPEmail(email)
	var match ICloudSession
	found := false
	for _, session := range s.sessionsForOwner(ownerID, "") {
		matched := email != "" && strings.EqualFold(normalizeICloudIMAPEmail(session.AppleID), email)
		if !matched {
			if state, ok := iCloudIMAPLoginState(session); ok {
				matched = strings.EqualFold(normalizeICloudIMAPEmail(state.IMAPEmail), email)
			}
		}
		if !matched {
			continue
		}
		if found && !sameICloudSessionPublicIdentity(match, session) {
			return ICloudSession{}, false, errCode("imap_account_ambiguous", "该取码邮箱匹配多个 Apple 账号，请明确指定 account_id", false)
		}
		match = session
		found = true
	}
	return match, found, nil
}

func emailLocalPart(value string) string {
	value = normalizeICloudIMAPEmail(value)
	if value == "" {
		return ""
	}
	if at := strings.Index(value, "@"); at > 0 {
		return value[:at]
	}
	return ""
}

func sameICloudSessionPublicIdentity(a, b ICloudSession) bool {
	if strings.TrimSpace(a.AccountID) != "" && strings.TrimSpace(b.AccountID) != "" {
		return constantTimeEqual(a.AccountID, b.AccountID)
	}
	if strings.TrimSpace(a.AppleID) != "" && strings.TrimSpace(b.AppleID) != "" {
		return strings.EqualFold(strings.TrimSpace(a.AppleID), strings.TrimSpace(b.AppleID))
	}
	return false
}

func checkSavedLoginStates(ctx context.Context, client *ICloudClient, session ICloudSession, checkedAt time.Time) (ICloudSession, bool, error) {
	return checkSavedLoginStatesWithKeepAliveInterval(ctx, client, session, checkedAt, CheckICloudIMAPLoginWithProxy, 0)
}

func checkSavedLoginStatesWithIMAP(ctx context.Context, client *ICloudClient, session ICloudSession, checkedAt time.Time, imapChecker func(context.Context, string, string) error) (ICloudSession, bool, error) {
	return checkSavedLoginStatesWithKeepAliveInterval(ctx, client, session, checkedAt, func(ctx context.Context, email, appPassword, _ string) error {
		if imapChecker == nil {
			return CheckICloudIMAPLogin(ctx, email, appPassword)
		}
		return imapChecker(ctx, email, appPassword)
	}, 0)
}

func checkSavedLoginStatesWithIMAPProxy(ctx context.Context, client *ICloudClient, session ICloudSession, checkedAt time.Time, imapChecker func(context.Context, string, string, string) error) (ICloudSession, bool, error) {
	return checkSavedLoginStatesWithKeepAliveInterval(ctx, client, session, checkedAt, imapChecker, 0)
}

func checkSavedLoginStatesWithKeepAliveInterval(ctx context.Context, client *ICloudClient, session ICloudSession, checkedAt time.Time, imapChecker func(context.Context, string, string, string) error, keepAliveInterval time.Duration) (ICloudSession, bool, error) {
	var parts []string
	checks := 0
	successes := 0
	var lastErr error

	if appleAccountLoginSaved(session) {
		checks++
		previousApple, _ := appleAccountLoginState(session)
		updated, err := client.checkAppleAccountManageSession(ctx, session, keepAliveInterval)
		session = updated
		state, _ := appleAccountLoginState(session)
		if err != nil {
			lastErr = err
			if isCodedError(err, "apple_account_keepalive_retrying") {
				state.LastCheckedAt = checkedAt
				state.LastCheckOK = false
				if strings.TrimSpace(state.LastStatusMessage) == "" {
					state.LastStatusMessage = "新接口保活：重试中"
				}
				session = withAppleAccountLoginState(session, state)
				parts = append(parts, "新接口重试中")
			} else if appleAccountKeepAliveTransientError(err) {
				state = appleAccountKeepAlivePersistTransient(previousApple, state)
				state.LastStatusMessage = "新接口检测暂时失败，已推迟保活"
				session = withAppleAccountLoginState(session, state)
				parts = append(parts, "新接口暂时失败")
			} else {
				state.LastCheckedAt = checkedAt
				state.LastCheckOK = false
				state.LastStatusMessage = "新接口登录态异常：" + publicErrorMessage(err)
				session = withAppleAccountLoginState(session, state)
				parts = append(parts, "新接口异常")
			}
		} else {
			state.LastCheckedAt = checkedAt
			state.LastCheckOK = true
			state.LastStatusMessage = "新接口登录态正常"
			state.KeepAliveFailCount = 0
			state.KeepAliveStopped = false
			session = withAppleAccountLoginState(session, state)
			successes++
			parts = append(parts, "新接口正常")
		}
	}

	if iCloudWebLoginSaved(session) {
		checks++
		state, _ := iCloudWebLoginState(session)
		webCtx, cancelWeb := context.WithTimeout(ctx, icloudWebCheckTimeout)
		err := client.CheckMailSession(webCtx, session)
		cancelWeb()
		if err != nil {
			lastErr = err
			state.LastCheckedAt = checkedAt
			state.LastCheckOK = false
			state.LastStatusMessage = "旧接口登录态异常：" + publicErrorMessage(err)
			session = withICloudWebLoginState(session, state)
			parts = append(parts, "旧接口异常")
		} else {
			state.LastCheckedAt = checkedAt
			state.LastCheckOK = true
			state.LastStatusMessage = "旧接口登录态正常"
			session = withICloudWebLoginState(session, state)
			successes++
			parts = append(parts, "旧接口正常")
		}
	}

	if iCloudIMAPLoginSaved(session) {
		checks++
		state, _ := iCloudIMAPLoginState(session)
		if imapChecker == nil {
			imapChecker = CheckICloudIMAPLoginWithProxy
		}
		imapCtx, cancelIMAP := context.WithTimeout(ctx, icloudIMAPCheckTimeout)
		err := imapChecker(imapCtx, state.IMAPEmail, state.IMAPAppPassword, state.ProxyURL)
		cancelIMAP()
		if err != nil {
			lastErr = err
			state.LastCheckedAt = checkedAt
			state.LastCheckOK = false
			state.LastStatusMessage = "取码登录异常：" + publicErrorMessage(err)
			session = withICloudIMAPLoginState(session, state)
			parts = append(parts, "取码登录异常")
		} else {
			state.LastCheckedAt = checkedAt
			state.LastCheckOK = true
			state.LastStatusMessage = "取码登录正常"
			session = withICloudIMAPLoginState(session, state)
			successes++
			parts = append(parts, "取码登录正常")
		}
	}

	if checks == 0 {
		lastErr = errCode("icloud_session_missing", "未保存新接口、旧接口或取码登录态，请先保存登录态", true)
		parts = append(parts, lastErr.Error())
	}

	session.LastCheckedAt = checkedAt
	session.LastCheckOK = successes > 0
	switch {
	case successes == checks && checks > 0:
		session.LastStatusMessage = "登录态正常：" + strings.Join(parts, "；")
	case successes > 0:
		session.LastStatusMessage = "登录态部分正常：" + strings.Join(parts, "；")
	default:
		session.LastStatusMessage = "登录态异常：" + strings.Join(parts, "；")
	}
	if session.LastCheckOK {
		return session, true, nil
	}
	if successes == 0 && (isCodedError(lastErr, "apple_account_keepalive_retrying") || appleAccountKeepAliveTransientError(lastErr)) {
		return session, true, nil
	}
	if lastErr == nil {
		lastErr = errors.New(session.LastStatusMessage)
	}
	return session, false, lastErr
}

func (s *Server) handleStartICloudProtocolLogin(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AppleID         string `json:"apple_id"`
		Password        string `json:"password"`
		TwoFactorMethod string `json:"two_factor_method"`
		ProxyURL        string `json:"proxy_url"`
		AccountID       string `json:"account_id"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ownerID := requestOwnerID(r, s.store)
	target, err := s.resolveLoginTarget(r, payload.AppleID, payload.AccountID)
	if err != nil {
		writeError(w, loginTargetHTTPStatus(err), err)
		return
	}
	if err := s.ensureOwnerNotDeleting(target.OwnerID); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	releaseAccountOperation, gateErr := s.acquireMailboxAccountOperationSlot(
		r.Context(),
		loginAccountOperationKey(target, payload.AppleID),
	)
	if gateErr != nil {
		writeError(w, http.StatusConflict, gateErr)
		return
	}
	defer releaseAccountOperation()
	target, err = s.resolveLoginTarget(r, payload.AppleID, payload.AccountID)
	if err != nil {
		writeError(w, loginTargetHTTPStatus(err), err)
		return
	}
	if err := s.ensureOwnerNotDeleting(target.OwnerID); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	proxyURL, proxyExplicit := s.loginProxySelectionForTarget(r, payload.AppleID, payload.ProxyURL, target)
	startLogin := s.startICloudProtocolLogin
	if startLogin == nil {
		startLogin = func(ctx context.Context, appleID, password, defaultHost, clientID string, pendingStore *appleAuthPendingStore, twoFactorMethod, proxyURL, ownerID string) (appleAuthStartResult, error) {
			return NewAppleAuthClient().StartLoginWithProxyForOwner(ctx, appleID, password, defaultHost, clientID, pendingStore, twoFactorMethod, proxyURL, ownerID)
		}
	}
	result, err := startLogin(
		r.Context(),
		payload.AppleID,
		payload.Password,
		s.cfg.ICloudDefaultHost,
		s.cfg.ICloudClientID,
		s.icloudProtocolLogins,
		payload.TwoFactorMethod,
		proxyURL,
		ownerID,
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if result.Needs2FA {
		s.icloudProtocolLogins.setProxyExplicit(result.PendingID, proxyExplicit)
		s.icloudProtocolLogins.setLoginTarget(result.PendingID, target.OwnerID, target.AccountID)
		s.icloudProtocolLogins.setPassword(result.PendingID, payload.Password)
		s.rememberAppleLoginPassword(target.OwnerID, target.AccountID, result.AppleID, payload.Password)
		if proxyExplicit {
			s.rememberAccountLoginProxy(target.OwnerID, target.AccountID, proxyURL)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"success":    true,
			"needs_2fa":  true,
			"pending_id": result.PendingID,
			"apple_id":   result.AppleID,
			"expires_at": formatTime(result.ExpiresAt),
			"message":    result.Message,
		})
		return
	}
	result.Session = bindLoginSessionTarget(result.Session, target)
	saveSession := s.store.SaveICloudSessionForOwner
	if proxyExplicit {
		saveSession = s.store.SaveICloudSessionForOwnerUpdatingProxy
	}
	if strings.TrimSpace(target.AccountID) != "" {
		s.rememberAppleLoginPassword(target.OwnerID, target.AccountID, firstNonEmpty(result.Session.AppleID, result.AppleID, payload.AppleID), payload.Password)
	}
	if err := saveSession(target.OwnerID, result.Session); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.rememberAppleLoginPassword(target.OwnerID, target.AccountID, firstNonEmpty(result.Session.AppleID, result.AppleID, payload.AppleID), payload.Password)
	sessions := s.publicSessionsForOwner(target.OwnerID)
	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"needs_2fa": false,
		"message":   result.Message,
		"session":   publicSessionForAppleID(sessions, result.Session.AppleID),
		"sessions":  sessions,
	})
}

func (s *Server) handleSubmitICloudProtocol2FA(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		PendingID string `json:"pending_id"`
		Code      string `json:"code"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	pending, ok := s.icloudProtocolLogins.get(payload.PendingID)
	if !ok {
		writeError(w, http.StatusBadRequest, errCode("apple_login_pending_expired", "旧接口登录已过期，请重新输入账号密码发起登录", true))
		return
	}
	if !s.pendingBelongsToRequest(r, pending) {
		writeError(w, http.StatusForbidden, errCode("apple_login_pending_forbidden", "该验证码登录不属于当前登录账号", false))
		return
	}
	releaseAccountOperation, gateErr := s.acquireMailboxAccountOperationSlot(
		r.Context(),
		pendingLoginOperationKey(pending, s.store),
	)
	if gateErr != nil {
		writeError(w, http.StatusConflict, gateErr)
		return
	}
	defer releaseAccountOperation()
	pending, ok = s.icloudProtocolLogins.get(payload.PendingID)
	if !ok {
		writeError(w, http.StatusBadRequest, errCode("apple_login_pending_expired", "旧接口登录已过期，请重新输入账号密码发起登录", true))
		return
	}
	if !s.pendingBelongsToRequest(r, pending) {
		writeError(w, http.StatusForbidden, errCode("apple_login_pending_forbidden", "该验证码登录不属于当前登录账号", false))
		return
	}
	if err := s.validatePendingLoginAccount(pending); err != nil {
		writeError(w, loginTargetHTTPStatus(err), err)
		return
	}
	if err := s.ensureOwnerNotDeleting(pendingLoginTargetOwnerID(pending, s.store)); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	pending = s.pendingLoginWithCurrentProxy(pending)
	submit2FA := s.submitICloudProtocol2FA
	if submit2FA == nil {
		submit2FA = func(ctx context.Context, pending appleAuthPending, code string) (ICloudSession, error) {
			return NewAppleAuthClient().Submit2FA(ctx, pending, code)
		}
	}
	session, err := submit2FA(r.Context(), pending, payload.Code)
	if err != nil {
		if !s.icloudProtocolLogins.update(payload.PendingID, pending) && s.logger != nil {
			s.logger.Warn("failed to refresh pending iCloud protocol login state after 2FA failure", "pending_id", payload.PendingID)
		}
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if err := s.savePendingICloudSession(pending, session); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.icloudProtocolLogins.delete(payload.PendingID)
	sessions := s.publicSessionsForOwner(pendingLoginTargetOwnerID(pending, s.store))
	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"message":  "旧接口验证码登录成功，登录态已保存",
		"session":  publicSessionForAppleID(sessions, session.AppleID),
		"sessions": sessions,
	})
}

func (s *Server) handleStartAppleAccountLogin(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AppleID         string `json:"apple_id"`
		Password        string `json:"password"`
		TwoFactorMethod string `json:"two_factor_method"`
		ProxyURL        string `json:"proxy_url"`
		AccountID       string `json:"account_id"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ownerID := requestOwnerID(r, s.store)
	target, err := s.resolveLoginTarget(r, payload.AppleID, payload.AccountID)
	if err != nil {
		writeError(w, loginTargetHTTPStatus(err), err)
		return
	}
	if err := s.ensureOwnerNotDeleting(target.OwnerID); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	releaseAccountOperation, gateErr := s.acquireMailboxAccountOperationSlot(
		r.Context(),
		loginAccountOperationKey(target, payload.AppleID),
	)
	if gateErr != nil {
		writeError(w, http.StatusConflict, gateErr)
		return
	}
	defer releaseAccountOperation()
	target, err = s.resolveLoginTarget(r, payload.AppleID, payload.AccountID)
	if err != nil {
		writeError(w, loginTargetHTTPStatus(err), err)
		return
	}
	if err := s.ensureOwnerNotDeleting(target.OwnerID); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	proxyURL, proxyExplicit := s.loginProxySelectionForTarget(r, payload.AppleID, payload.ProxyURL, target)
	startLogin := s.startAppleAccountLogin
	if startLogin == nil {
		startLogin = func(ctx context.Context, appleID, password string, pendingStore *appleAuthPendingStore, twoFactorMethod, proxyURL, ownerID string) (appleAuthStartResult, error) {
			return NewAppleAuthClient().StartAppleAccountManageLoginWithProxyForOwner(ctx, appleID, password, pendingStore, twoFactorMethod, proxyURL, ownerID)
		}
	}
	result, err := startLogin(
		r.Context(),
		payload.AppleID,
		payload.Password,
		s.appleAccountLogins,
		payload.TwoFactorMethod,
		proxyURL,
		ownerID,
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if result.Needs2FA {
		s.appleAccountLogins.setProxyExplicit(result.PendingID, proxyExplicit)
		s.appleAccountLogins.setLoginTarget(result.PendingID, target.OwnerID, target.AccountID)
		s.appleAccountLogins.setPassword(result.PendingID, payload.Password)
		s.rememberAppleLoginPassword(target.OwnerID, target.AccountID, result.AppleID, payload.Password)
		if proxyExplicit {
			s.rememberAccountLoginProxy(target.OwnerID, target.AccountID, proxyURL)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"success":    true,
			"needs_2fa":  true,
			"pending_id": result.PendingID,
			"apple_id":   result.AppleID,
			"expires_at": formatTime(result.ExpiresAt),
			"message":    result.Message,
		})
		return
	}
	result.Session = bindLoginSessionTarget(result.Session, target)
	saveSession := s.store.SaveICloudSessionForOwner
	if proxyExplicit {
		saveSession = s.store.SaveICloudSessionForOwnerUpdatingProxy
	}
	if strings.TrimSpace(target.AccountID) != "" {
		s.rememberAppleLoginPassword(target.OwnerID, target.AccountID, firstNonEmpty(result.Session.AppleID, result.AppleID, payload.AppleID), payload.Password)
	}
	if err := saveSession(target.OwnerID, result.Session); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.rememberAppleLoginPassword(target.OwnerID, target.AccountID, firstNonEmpty(result.Session.AppleID, result.AppleID, payload.AppleID), payload.Password)
	sessions := s.publicSessionsForOwner(target.OwnerID)
	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"needs_2fa": false,
		"message":   result.Message,
		"session":   publicSessionForAppleID(sessions, result.Session.AppleID),
		"sessions":  sessions,
	})
}

func (s *Server) handleSubmitAppleAccount2FA(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		PendingID   string          `json:"pending_id"`
		Code        string          `json:"code"`
		PhoneNumber json.RawMessage `json:"phone_number,omitempty"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	pending, ok := s.appleAccountLogins.get(payload.PendingID)
	if !ok {
		writeError(w, http.StatusBadRequest, errCode("apple_login_pending_expired", "新接口登录已过期，请重新输入账号密码发起登录", true))
		return
	}
	if !s.pendingBelongsToRequest(r, pending) {
		writeError(w, http.StatusForbidden, errCode("apple_login_pending_forbidden", "该验证码登录不属于当前登录账号", false))
		return
	}
	releaseAccountOperation, gateErr := s.acquireMailboxAccountOperationSlot(
		r.Context(),
		pendingLoginOperationKey(pending, s.store),
	)
	if gateErr != nil {
		writeError(w, http.StatusConflict, gateErr)
		return
	}
	defer releaseAccountOperation()
	pending, ok = s.appleAccountLogins.get(payload.PendingID)
	if !ok {
		writeError(w, http.StatusBadRequest, errCode("apple_login_pending_expired", "新接口登录已过期，请重新输入账号密码发起登录", true))
		return
	}
	if !s.pendingBelongsToRequest(r, pending) {
		writeError(w, http.StatusForbidden, errCode("apple_login_pending_forbidden", "该验证码登录不属于当前登录账号", false))
		return
	}
	if err := s.validatePendingLoginAccount(pending); err != nil {
		writeError(w, loginTargetHTTPStatus(err), err)
		return
	}
	if err := s.ensureOwnerNotDeleting(pendingLoginTargetOwnerID(pending, s.store)); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	pending = s.pendingLoginWithCurrentProxy(pending)
	submit2FA := s.submitAppleAccount2FA
	if submit2FA == nil {
		submit2FA = func(ctx context.Context, pending appleAuthPending, code string, phoneNumber json.RawMessage) (ICloudSession, error) {
			return NewAppleAuthClient().SubmitAppleAccountManage2FA(ctx, pending, code, phoneNumber)
		}
	}
	session, err := submit2FA(r.Context(), pending, payload.Code, payload.PhoneNumber)
	if err != nil {
		if !s.appleAccountLogins.update(payload.PendingID, pending) && s.logger != nil {
			s.logger.Warn("failed to refresh pending Apple Account login state after 2FA failure", "pending_id", payload.PendingID)
		}
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if err := s.savePendingICloudSession(pending, session); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.appleAccountLogins.delete(payload.PendingID)
	sessions := s.publicSessionsForOwner(pendingLoginTargetOwnerID(pending, s.store))
	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"message":  "新接口验证码登录成功，登录态已保存",
		"session":  publicSessionForAppleID(sessions, session.AppleID),
		"sessions": sessions,
	})
}

func (s *Server) handleCreateICloudMailbox(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID     string   `json:"account_id"`
		AccountIDs    []string `json:"account_ids"`
		Label         string   `json:"label"`
		Note          string   `json:"note"`
		CreateChannel string   `json:"create_channel"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	accountIDs := normalizeAccountIDSelection(payload.AccountID, payload.AccountIDs)
	if !s.canAccessAccountIDs(r, accountIDs) {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "账号不存在", false))
		return
	}
	for _, accountID := range accountIDs {
		if !s.accountInRequestScope(r, accountID) {
			writeError(w, http.StatusNotFound, errCode("account_not_found", "账号不存在", false))
			return
		}
	}
	ownerID := requestOwnerID(r, s.store)
	channel := normalizeMailboxCreateChannel(mailboxCreateChannel(strings.ToLower(strings.TrimSpace(payload.CreateChannel))))
	requests := make([]mailboxCreateRequest, 0, len(accountIDs))
	for _, accountID := range accountIDs {
		requests = append(requests, mailboxCreateRequest{AccountID: accountID, Channel: channel})
	}
	mailboxes, remotes, failures, err := s.createMailboxesForOwnerWithChannels(r.Context(), ownerID, requests, payload.Label, payload.Note)
	if err != nil {
		s.logICloudCreateError(ownerID, err)
		if len(mailboxes) == 0 && len(failures) == 0 {
			writeError(w, http.StatusBadGateway, err)
			return
		}
	}
	out := make([]publicMailbox, 0, len(mailboxes))
	for _, mailbox := range mailboxes {
		out = append(out, s.publicMailbox(r, mailbox))
	}
	status := http.StatusCreated
	if len(failures) > 0 {
		status = http.StatusMultiStatus
	}
	remoteOut := make([]map[string]any, 0, len(remotes))
	for index, remote := range remotes {
		channel := mailboxCreateChannelFromRemote(remote)
		channelValue := string(channel)
		channelLabel := mailboxCreateChannelLabel(channel)
		if index < len(out) {
			out[index].CreateChannel = channelValue
			out[index].CreateChannelLabel = channelLabel
		}
		remoteOut = append(remoteOut, map[string]any{
			"anonymous_id":  remote.AnonymousID,
			"email":         remote.Email,
			"is_active":     remote.IsActive,
			"origin":        remote.Origin,
			"channel":       channelValue,
			"channel_label": channelLabel,
		})
	}
	firstMailbox := publicMailbox{}
	if len(out) > 0 {
		firstMailbox = out[0]
	}
	success := len(out) > 0
	message := "隐私邮箱创建成功"
	if len(failures) > 0 {
		if success {
			message = fmt.Sprintf("隐私邮箱创建部分成功：成功 %d 个，失败 %d 个，请查看失败明细", len(out), len(failures))
		} else {
			message = fmt.Sprintf("所有选中账号创建失败：失败 %d 个，请查看失败明细", len(failures))
		}
	}
	writeJSON(w, status, map[string]any{
		"success":   success,
		"message":   message,
		"remote":    firstMap(remoteOut),
		"remotes":   remoteOut,
		"mailbox":   firstMailbox,
		"mailboxes": out,
		"created":   len(out),
		"failures":  failures,
	})
}

func (s *Server) handleSyncICloudMailboxes(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID string `json:"account_id"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		_ = r.Body.Close()
	}
	if !s.canAccessAccountID(r, payload.AccountID) || !s.accountInRequestScope(r, payload.AccountID) {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "账号不存在", false))
		return
	}
	ownerID := requestOwnerID(r, s.store)
	allSessions := s.sessionsForRequestScope(r, payload.AccountID)
	sessions := allSessions
	if strings.TrimSpace(payload.AccountID) == "" {
		sessions = filterICloudMailboxSyncSessions(sessions)
	} else {
		sessions = filterICloudMailboxSyncSessionsForAccount(sessions)
	}
	if len(sessions) == 0 {
		writeError(w, http.StatusBadRequest, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先保存旧接口或新接口登录态", true))
		return
	}

	created := 0
	updated := 0
	skipped := 0
	remoteMissing := 0
	total := 0
	localProcessed := 0
	failed := 0
	out := make([]publicMailbox, 0)
	type syncJobResult struct {
		result syncICloudMailboxResult
		rows   []publicMailbox
		err    error
	}
	jobResults := make([]syncJobResult, len(sessions))
	var wg sync.WaitGroup
	for index, session := range sessions {
		wg.Add(1)
		go func(index int, session ICloudSession) {
			defer wg.Done()
			syncCtx, cancel := context.WithTimeout(r.Context(), iCloudMailboxListAccountTimeout)
			defer cancel()
			result, rows, err := s.syncICloudMailboxesForSession(syncCtx, r, ownerID, session)
			if err != nil && errors.Is(err, context.DeadlineExceeded) {
				err = errCode("icloud_sync_timeout", "该账号同步已有邮箱超时，请稍后单独重试", true)
				result.Error = publicErrorMessage(err)
			}
			jobResults[index] = syncJobResult{result: result, rows: rows, err: err}
		}(index, session)
	}
	wg.Wait()
	results := make([]syncICloudMailboxResult, 0, len(sessions))
	partialSourceFailure := false
	for _, job := range jobResults {
		result, rows, err := job.result, job.rows, job.err
		results = append(results, result)
		if err != nil {
			failed++
			if isCodedError(err, "icloud_sync_partial") {
				partialSourceFailure = true
			}
			s.logger.Warn("iCloud mailbox list failed", "account_id", result.AccountID, "err", err)
		}
		total += result.RemoteTotal
		localProcessed += result.LocalProcessed
		created += result.Created
		updated += result.Updated
		skipped += result.Skipped
		remoteMissing += result.RemoteMissing
		out = append(out, rows...)
	}
	partial := partialSourceFailure || (failed > 0 && failed < len(sessions))
	message := ""
	if failed == len(sessions) && !partialSourceFailure {
		message = "全部 iCloud 账号同步失败，请看每个账号的失败原因"
	} else if failed > 0 {
		message = "部分 iCloud 账号同步失败，请看每个账号的失败原因并重试失败账号"
	}
	response := map[string]any{
		"success":         failed == 0,
		"partial":         partial,
		"message":         message,
		"total":           total,
		"remote_total":    total,
		"local_processed": localProcessed,
		"created":         created,
		"updated":         updated,
		"skipped":         skipped,
		"remote_missing":  remoteMissing,
		"failed":          failed,
		"results":         results,
		"mailboxes":       out,
	}
	if failed == len(sessions) && !partialSourceFailure {
		response["code"] = "icloud_sync_failed"
		response["retryable"] = true
		writeJSON(w, http.StatusBadGateway, response)
		return
	}
	if partial {
		response["code"] = "icloud_sync_partial"
		response["retryable"] = true
		writeJSON(w, http.StatusMultiStatus, response)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func filterICloudMailboxSyncSessions(sessions []ICloudSession) []ICloudSession {
	out := make([]ICloudSession, 0, len(sessions))
	for _, session := range sessions {
		if iCloudWebLoginSaved(session) || appleAccountLoginSaved(session) {
			out = append(out, session)
		}
	}
	return out
}

func filterICloudMailboxSyncSessionsForAccount(sessions []ICloudSession) []ICloudSession {
	out := make([]ICloudSession, 0, len(sessions))
	for _, session := range sessions {
		if iCloudWebLoginSaved(session) || appleAccountLoginSaved(session) {
			out = append(out, session)
		}
	}
	return out
}

func mailboxSyncSource(session ICloudSession) string {
	sources := mailboxSyncSources(session)
	if len(sources) == 0 {
		return ""
	}
	return strings.Join(sources, ",")
}

func mailboxSyncSources(session ICloudSession) []string {
	sources := make([]string, 0, 2)
	if appleAccountLoginSaved(session) {
		sources = append(sources, string(mailboxCreateChannelAppleAccount))
	}
	if iCloudWebLoginSaved(session) {
		sources = append(sources, string(mailboxCreateChannelICloudWeb))
	}
	return sources
}

func mailboxSyncRemoteOrigin(source string) string {
	switch normalizeMailboxCreateChannel(mailboxCreateChannel(strings.ToLower(strings.TrimSpace(source)))) {
	case mailboxCreateChannelAppleAccount:
		return mailboxRemoteOriginAppleAccount
	case mailboxCreateChannelICloudWeb:
		return mailboxRemoteOriginICloudWeb
	default:
		return ""
	}
}

func appleAccountListClientAndContext(ctx context.Context, source string) (*ICloudClient, context.Context, context.CancelFunc) {
	if strings.EqualFold(strings.TrimSpace(source), string(mailboxCreateChannelAppleAccount)) {
		listCtx, cancel := context.WithTimeout(ctx, appleAccountManageOperationTimeout)
		return newICloudKeepAliveClient(), listCtx, cancel
	}
	return NewICloudClient(), ctx, func() {}
}

func (s *Server) syncICloudMailboxesForSession(ctx context.Context, r *http.Request, ownerID string, session ICloudSession) (syncICloudMailboxResult, []publicMailbox, error) {
	ownerID = s.dataOwnerIDForSession(ownerID, session)
	result := syncICloudMailboxResult{
		AccountID: session.AccountID,
		AppleID:   strings.TrimSpace(session.AppleID),
		Source:    mailboxSyncSource(session),
	}
	if len(mailboxSyncSources(session)) == 0 {
		err := errCode("icloud_session_missing", "该账号没有可用于同步已有邮箱的登录态，请先完成旧接口或新接口登录", true)
		result.Error = publicErrorMessage(err)
		return result, nil, err
	}
	accountOperationKey := mailboxAccountOperationKey(ownerID, session.AccountID)
	releaseAccountOperation, err := s.acquireMailboxAccountOperationSlot(ctx, accountOperationKey)
	if err != nil {
		result.Error = publicErrorMessage(err)
		return result, nil, err
	}
	defer releaseAccountOperation()
	if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
		result.Error = publicErrorMessage(err)
		return result, nil, err
	}
	currentSession, ok := s.sessionForOwnerAccount(ownerID, session.AccountID)
	if !ok {
		err := errCode("icloud_session_missing", "该账号的 iCloud 登录态已不存在，请重新保存旧接口或新接口登录态", true)
		result.Error = publicErrorMessage(err)
		return result, nil, err
	}
	session = currentSession
	ownerID = s.dataOwnerIDForSession(ownerID, session)
	result.AccountID = session.AccountID
	result.AppleID = strings.TrimSpace(session.AppleID)
	result.Source = mailboxSyncSource(session)
	sources := mailboxSyncSources(session)
	if len(sources) == 0 {
		err := errCode("icloud_session_missing", "该账号没有可用于同步已有邮箱的旧接口或新接口登录态，请先完成旧接口或新接口登录", true)
		result.Error = publicErrorMessage(err)
		return result, nil, err
	}
	out := make([]publicMailbox, 0)
	accountID := strings.TrimSpace(session.AccountID)
	var firstErr error
	successfulSources := 0
	successfulRemoteCount := 0
	for _, source := range sources {
		client, listCtx, cancelList := appleAccountListClientAndContext(ctx, source)
		remotes, updatedSession, listErr := client.ListPrivacyMailboxesForOriginWithSessionAndAPIKey(
			listCtx,
			session,
			source,
			s.cfg.AppleAccountAPIKey,
		)
		cancelList()
		if listErr != nil {
			if firstErr == nil {
				firstErr = listErr
			}
			if result.Error != "" {
				result.Error += "；"
			}
			result.Error += source + "：" + publicErrorMessage(listErr)
			continue
		}
		if strings.EqualFold(strings.TrimSpace(source), string(mailboxCreateChannelAppleAccount)) {
			if saveErr := s.store.SaveICloudSessionForOwner(ownerID, updatedSession); saveErr != nil {
				result.Error = publicErrorMessage(saveErr)
				return result, out, saveErr
			}
		}
		session = updatedSession
		successfulSources++
		successfulRemoteCount += len(remotes)
		reconcileLocalState := func() error {
			seenEmails := make(map[string]struct{}, len(remotes))
			for _, remote := range remotes {
				result.LocalProcessed++
				if email := strings.ToLower(strings.TrimSpace(remote.Email)); email != "" {
					seenEmails[email] = struct{}{}
				}
				mailbox, isCreated, upsertErr := s.store.UpsertMailboxFromRemote(ownerID, accountID, remote, "synced from iCloud HME list")
				if upsertErr != nil {
					var coded codedError
					if errors.As(upsertErr, &coded) && (coded.code == "mailbox_exists_other_owner" || coded.code == "mailbox_remote_identity_conflict") {
						result.Skipped++
						continue
					}
					return upsertErr
				}
				if isCreated {
					result.Created++
				} else {
					result.Updated++
				}
				out = append(out, s.publicMailbox(r, mailbox))
			}
			remoteOrigin := mailboxSyncRemoteOrigin(source)
			if remoteOrigin == "" {
				return errCode("icloud_mailbox_remote_origin_unknown", "无法识别隐私邮箱同步来源", false)
			}
			remoteMissing, markErr := s.store.MarkMailboxesRemoteMissingForOrigin(ownerID, accountID, remoteOrigin, seenEmails, time.Now())
			if markErr != nil {
				return markErr
			}
			result.RemoteMissing += remoteMissing
			if accountID != "" {
				if reconciliationOrigin, blocked := s.store.AccountMailboxCreateReconciliationOriginForOwner(ownerID, accountID); blocked &&
					(reconciliationOrigin == "" || strings.EqualFold(reconciliationOrigin, remoteOrigin)) {
					if clearErr := s.store.ClearAccountMailboxCreateReconciliationRequired(ownerID, accountID); clearErr != nil {
						return clearErr
					}
				}
			}
			return nil
		}
		var reconcileErr error
		unboundOperationKey := mailboxAccountOperationKey(ownerID, "")
		if unboundOperationKey != accountOperationKey {
			releaseUnboundOperation, gateErr := s.acquireMailboxAccountOperationSlot(ctx, unboundOperationKey)
			if gateErr != nil {
				reconcileErr = gateErr
			} else {
				reconcileErr = func() error {
					defer releaseUnboundOperation()
					return reconcileLocalState()
				}()
			}
		} else {
			reconcileErr = reconcileLocalState()
		}
		if reconcileErr != nil {
			result.Error = publicErrorMessage(reconcileErr)
			return result, out, reconcileErr
		}
	}
	result.Total = successfulRemoteCount
	result.RemoteTotal = successfulRemoteCount
	result.RemoteEmpty = successfulSources > 0 && successfulRemoteCount == 0
	if successfulSources == 0 {
		if firstErr == nil {
			firstErr = errCode("icloud_sync_failed", "没有任何 iCloud 隐私邮箱来源同步成功", true)
		}
		result.Error = publicErrorMessage(firstErr)
		return result, out, firstErr
	}
	if firstErr != nil {
		return result, out, errCode("icloud_sync_partial", "部分 iCloud 隐私邮箱来源同步失败："+result.Error, true)
	}
	return result, out, nil
}

func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	state := s.homeScopedState(r)
	out := make([]publicAccount, 0, len(state.Accounts))
	for _, account := range state.Accounts {
		out = append(out, s.publicAccountWithSecrets(account))
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "accounts": out})
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Label    string `json:"label"`
		AppleID  string `json:"apple_id"`
		ProxyURL string `json:"proxy_url"`
		Note     string `json:"note"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ownerID := requestOwnerID(r, s.store)
	if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	var releaseOwnerOperation func()
	if ownerID != "" {
		var gateErr error
		releaseOwnerOperation, gateErr = s.acquireMailboxAccountOperationSlot(
			r.Context(),
			mailboxAccountOperationKey(ownerID, ""),
		)
		if gateErr != nil {
			writeError(w, http.StatusConflict, gateErr)
			return
		}
		defer releaseOwnerOperation()
		if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
	}
	account, err := s.store.AddAccountForOwnerWithProxy(ownerID, payload.Label, payload.AppleID, payload.Note, payload.ProxyURL)
	if err != nil {
		status := http.StatusBadRequest
		if isCodedError(err, "account_create_persist_failed") {
			status = http.StatusInternalServerError
		} else if isCodedError(err, "apple_id_exists_other_owner") || isCodedError(err, "apple_id_exists") {
			status = appleIDConflictHTTPStatus(err)
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "account": s.publicAccount(account)})
}

func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if !s.canAccessAccountID(r, id) || !s.accountInRequestScope(r, id) {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "Apple 账号不存在", false))
		return
	}
	var payload struct {
		ProxyURL *string `json:"proxy_url"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	account, ok := s.store.FindAccountByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "Apple 账号不存在", false))
		return
	}
	if payload.ProxyURL == nil {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "account": s.publicAccount(account)})
		return
	}
	if err := s.ensureOwnerNotDeleting(account.OwnerID); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	releaseAccountOperation, err := s.acquireMailboxAccountOperationSlot(
		r.Context(),
		mailboxAccountOperationKey(account.OwnerID, account.ID),
	)
	if err != nil {
		writeError(w, http.StatusConflict, errCode("account_operation_in_progress", "该 Apple 账号正在执行登录、同步、创建或删除操作，请稍后重试", true))
		return
	}
	defer releaseAccountOperation()
	ownerID := requestOwnerID(r, s.store)
	if s.isAdminRequest(r) {
		ownerID = ""
	}
	account, err = s.store.UpdateAccountProxyForOwner(ownerID, id, *payload.ProxyURL)
	if err != nil {
		status := http.StatusBadRequest
		if isCodedError(err, "account_not_found") || isCodedError(err, "account_forbidden") {
			status = http.StatusNotFound
		} else if isCodedError(err, "account_proxy_persist_failed") {
			status = http.StatusInternalServerError
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "account": s.publicAccount(account)})
}

func (s *Server) handleListMailboxes(w http.ResponseWriter, r *http.Request) {
	exportedFilter := strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("exported"), r.URL.Query().Get("api_exported")))
	if err := validateMailboxExportedFilter(exportedFilter); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	state := s.homeScopedState(r)
	accountsByID := mailboxAccountMap(state.Accounts)
	base := filterMailboxesByOwner(state.Mailboxes, strings.TrimSpace(r.URL.Query().Get("owner_id")), scopedOwnerID(r, s.store), s.isAdminRequest(r))
	filtered := filterMailboxesForList(base, accountsByID, r.URL.Query())
	groupValues := r.URL.Query()
	groupValues.Del("account_key")
	groupValues.Del("account_id")
	groups := publicMailboxGroups(filterMailboxesForList(base, accountsByID, groupValues), accountsByID)
	sortMailboxesForList(filtered, accountsByID)

	page, pageSize, paged := mailboxListPagination(r)
	pageRows := filtered
	if paged {
		pageRows = paginateMailboxes(filtered, page, pageSize)
	}
	out := make([]publicMailbox, 0, len(pageRows))
	for _, mailbox := range pageRows {
		out = append(out, s.publicMailbox(r, mailbox))
	}
	response := map[string]any{
		"success":   true,
		"mailboxes": out,
		"groups":    groups,
		"pagination": publicPagination{
			Page:       page,
			PageSize:   pageSize,
			Total:      len(filtered),
			TotalAll:   len(base),
			TotalPages: totalPages(len(filtered), pageSize),
		},
	}
	writeJSON(w, http.StatusOK, response)
}

func filterMailboxesByOwner(mailboxes []Mailbox, ownerFilter, scopedOwner string, admin bool) []Mailbox {
	ownerFilter = strings.TrimSpace(ownerFilter)
	if admin && ownerFilter == "__global" {
		out := make([]Mailbox, 0, len(mailboxes))
		for _, mailbox := range mailboxes {
			if strings.TrimSpace(mailbox.OwnerID) == "" {
				out = append(out, mailbox)
			}
		}
		return out
	}
	if ownerFilter == "" || ownerFilter == "all" {
		return append([]Mailbox(nil), mailboxes...)
	}
	if !admin {
		scopedOwner = strings.TrimSpace(scopedOwner)
		if scopedOwner == "" || !constantTimeEqual(scopedOwner, ownerFilter) {
			return nil
		}
	}
	out := make([]Mailbox, 0, len(mailboxes))
	for _, mailbox := range mailboxes {
		if constantTimeEqual(strings.TrimSpace(mailbox.OwnerID), ownerFilter) {
			out = append(out, mailbox)
		}
	}
	return out
}

func filterMailboxesForList(mailboxes []Mailbox, accountsByID map[string]Account, values url.Values) []Mailbox {
	accountKey := strings.TrimSpace(firstNonEmpty(values.Get("account_key"), values.Get("account_id")))
	keyword := strings.ToLower(strings.TrimSpace(firstNonEmpty(values.Get("search"), values.Get("q"))))
	exportedFilter := strings.TrimSpace(firstNonEmpty(values.Get("exported"), values.Get("api_exported")))
	out := make([]Mailbox, 0, len(mailboxes))
	for _, mailbox := range mailboxes {
		if accountKey != "" && accountKey != "all" && !constantTimeEqual(mailboxListAccountKey(mailbox, accountsByID), accountKey) {
			continue
		}
		if keyword != "" && !mailboxListMatchesSearch(mailbox, accountsByID, keyword) {
			continue
		}
		switch strings.ToLower(exportedFilter) {
		case "", "all":
		case "1", "true", "yes", "exported", "done", "has":
			if mailbox.APIExportedAt.IsZero() {
				continue
			}
		case "0", "false", "no", "unexported", "pending", "none":
			if !mailbox.APIExportedAt.IsZero() {
				continue
			}
		}
		out = append(out, mailbox)
	}
	return out
}

func mailboxListMatchesSearch(mailbox Mailbox, accountsByID map[string]Account, keyword string) bool {
	account := accountsByID[strings.TrimSpace(mailbox.AccountID)]
	haystack := strings.ToLower(strings.Join([]string{
		mailbox.Email,
		mailbox.Label,
		mailbox.ID,
		mailbox.AccountID,
		account.Label,
		account.AppleID,
		mailbox.Status,
		mailbox.OwnerID,
	}, " "))
	return strings.Contains(haystack, keyword)
}

func sortMailboxesForList(mailboxes []Mailbox, accountsByID map[string]Account) {
	sort.Slice(mailboxes, func(i, j int) bool {
		leftTitle := strings.ToLower(mailboxListAccountTitle(mailboxes[i], accountsByID))
		rightTitle := strings.ToLower(mailboxListAccountTitle(mailboxes[j], accountsByID))
		if leftTitle != rightTitle {
			return leftTitle < rightTitle
		}
		return strings.ToLower(mailboxes[i].Email) < strings.ToLower(mailboxes[j].Email)
	})
}

func paginateMailboxes(mailboxes []Mailbox, page, pageSize int) []Mailbox {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = mailboxListDefaultPageSize
	}
	start := (page - 1) * pageSize
	if start >= len(mailboxes) {
		return nil
	}
	end := start + pageSize
	if end > len(mailboxes) {
		end = len(mailboxes)
	}
	return mailboxes[start:end]
}

func mailboxListPagination(r *http.Request) (int, int, bool) {
	values := r.URL.Query()
	paged := values.Has("page") || values.Has("page_size") || values.Has("search") || values.Has("q") || values.Has("account_key") || values.Has("account_id") || values.Has("owner_id") || values.Has("exported") || values.Has("api_exported")
	page := parseBoundedPositiveInt(values.Get("page"), 1, 1, 1_000_000)
	pageSize := parseBoundedPositiveInt(values.Get("page_size"), mailboxListDefaultPageSize, 1, mailboxListMaxPageSize)
	return page, pageSize, paged
}

func parseBoundedPositiveInt(value string, fallback, minValue, maxValue int) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	if n < minValue {
		return minValue
	}
	if n > maxValue {
		return maxValue
	}
	return n
}

func totalPages(total, pageSize int) int {
	if pageSize < 1 {
		pageSize = mailboxListDefaultPageSize
	}
	if total <= 0 {
		return 1
	}
	return (total + pageSize - 1) / pageSize
}

func mailboxAccountMap(accounts []Account) map[string]Account {
	out := make(map[string]Account, len(accounts))
	for _, account := range accounts {
		if strings.TrimSpace(account.ID) != "" {
			out[account.ID] = account
		}
	}
	return out
}

func publicMailboxGroups(mailboxes []Mailbox, accountsByID map[string]Account) []publicMailboxGroup {
	byKey := map[string]publicMailboxGroup{}
	for _, mailbox := range mailboxes {
		key := mailboxListAccountKey(mailbox, accountsByID)
		group := byKey[key]
		if group.Key == "" {
			group = publicMailboxGroup{
				Key:       key,
				Title:     mailboxListAccountTitle(mailbox, accountsByID),
				AccountID: strings.TrimSpace(mailbox.AccountID),
			}
		}
		group.Count++
		byKey[key] = group
	}
	groups := make([]publicMailboxGroup, 0, len(byKey))
	for _, group := range byKey {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool {
		return strings.ToLower(groups[i].Title) < strings.ToLower(groups[j].Title)
	})
	return groups
}

func mailboxListAccountKey(mailbox Mailbox, accountsByID map[string]Account) string {
	if strings.TrimSpace(mailbox.AccountID) != "" {
		return strings.TrimSpace(mailbox.AccountID)
	}
	return "unbound"
}

func mailboxListAccountTitle(mailbox Mailbox, accountsByID map[string]Account) string {
	account := accountsByID[strings.TrimSpace(mailbox.AccountID)]
	return firstNonEmpty(account.Label, account.AppleID, mailbox.AccountID, "未绑定 Apple 账号")
}

func (s *Server) handleCreateMailbox(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID string `json:"account_id"`
		Label     string `json:"label"`
		Email     string `json:"email"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.canAccessAccountID(r, payload.AccountID) || !s.accountInRequestScope(r, payload.AccountID) {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "账号不存在", false))
		return
	}
	accountID := strings.TrimSpace(payload.AccountID)
	ownerID := s.dataOwnerIDForAccount(requestOwnerID(r, s.store), accountID)
	if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	releaseAccountOperation, gateErr := s.acquireMailboxAccountOperationSlot(
		r.Context(),
		mailboxAccountOperationKey(ownerID, accountID),
	)
	if gateErr != nil {
		writeError(w, http.StatusConflict, errCode("mailbox_operation_in_progress", "该邮箱账号正在执行同步、登录、创建或删除操作，请稍后重试", true))
		return
	}
	defer releaseAccountOperation()
	if accountID != "" && (!s.canAccessAccountID(r, accountID) || !s.accountInRequestScope(r, accountID)) {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "账号不存在", false))
		return
	}
	ownerID = s.dataOwnerIDForAccount(requestOwnerID(r, s.store), accountID)
	if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	mailbox, err := s.store.AddMailboxForOwner(ownerID, accountID, payload.Label, payload.Email)
	if err != nil {
		status := http.StatusBadRequest
		if isCodedError(err, "mailbox_create_persist_failed") {
			status = http.StatusInternalServerError
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "mailbox": s.publicMailbox(r, mailbox)})
}

func (s *Server) handleVerifyMailbox(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canAccessMailboxID(r, id) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	active := true
	mailbox, err := s.setMailboxStatusForRequestWithAccess(
		r.Context(),
		id,
		func(current Mailbox) bool { return s.canAccessMailbox(r, current) },
		&active,
		&active,
		StatusAvailable,
		"手动验证通过",
	)
	if err != nil {
		writeError(w, mailboxMutationHTTPStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "mailbox": s.publicMailbox(r, mailbox)})
}

func (s *Server) handleDisableMailbox(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canAccessMailboxID(r, id) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	inactive := false
	mailbox, err := s.setMailboxStatusForRequestWithAccess(
		r.Context(),
		id,
		func(current Mailbox) bool { return s.canAccessMailbox(r, current) },
		&inactive,
		nil,
		StatusDisabled,
		"API 已停用",
	)
	if err != nil {
		writeError(w, mailboxMutationHTTPStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "mailbox": s.publicMailbox(r, mailbox)})
}

func (s *Server) handleSetMailboxStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canAccessMailboxID(r, id) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	var payload struct {
		Status       string `json:"status"`
		Note         string `json:"note"`
		APIActive    *bool  `json:"api_active"`
		ICloudActive *bool  `json:"icloud_active"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	status := strings.ToLower(strings.TrimSpace(payload.Status))
	if status != "" && !validMailboxStatus(status) {
		writeError(w, http.StatusBadRequest, errCode("invalid_status", "状态只能是 available、used、failed、active、disabled", false))
		return
	}
	mailbox, err := s.setMailboxStatusForRequestWithAccess(
		r.Context(),
		id,
		func(current Mailbox) bool { return s.canAccessMailbox(r, current) },
		payload.APIActive,
		payload.ICloudActive,
		status,
		payload.Note,
	)
	if err != nil {
		writeError(w, mailboxMutationHTTPStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "mailbox": s.publicMailbox(r, mailbox)})
}

func (s *Server) handleBindMailbox(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	mailbox, ok := s.store.FindMailboxByID(id)
	if !ok || !s.canAccessMailbox(r, mailbox) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	var payload struct {
		AccountID string `json:"account_id"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	accountID := strings.TrimSpace(payload.AccountID)
	if accountID == "" || !s.canAccessAccountID(r, accountID) {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "Apple 账号不存在", false))
		return
	}
	account, ok := s.store.FindAccountByID(accountID)
	if !ok {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "Apple 账号不存在", false))
		return
	}
	targetOwnerID := strings.TrimSpace(account.OwnerID)
	for attempt := 0; attempt < 4; attempt++ {
		currentKey := mailboxAccountOperationKey(mailbox.OwnerID, mailbox.AccountID)
		targetKey := mailboxAccountOperationKey(targetOwnerID, "")
		releaseOperations, acquireErr := s.acquireMailboxAccountOperations(r.Context(), []string{currentKey, targetKey})
		if acquireErr != nil {
			writeError(w, http.StatusConflict, acquireErr)
			return
		}
		current, currentOK := s.store.FindMailboxByID(id)
		if !currentOK {
			releaseOperations()
			writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
			return
		}
		if mailboxAccountOperationKey(current.OwnerID, current.AccountID) != currentKey {
			releaseOperations()
			mailbox = current
			continue
		}
		if !s.canAccessMailbox(r, current) {
			releaseOperations()
			writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
			return
		}
		if err := s.ensureOwnerNotDeleting(current.OwnerID); err != nil {
			releaseOperations()
			writeError(w, http.StatusConflict, err)
			return
		}
		if err := s.ensureOwnerNotDeleting(targetOwnerID); err != nil {
			releaseOperations()
			writeError(w, http.StatusConflict, err)
			return
		}
		ownerID := requestOwnerID(r, s.store)
		if s.isAdminRequest(r) {
			ownerID = ""
		}
		bound, bindErr := s.store.BindMailboxToAccountForOwner(ownerID, id, accountID)
		releaseOperations()
		if bindErr != nil {
			status := mailboxMutationHTTPStatus(bindErr)
			if isCodedError(bindErr, "mailbox_forbidden") ||
				isCodedError(bindErr, "account_forbidden") ||
				isCodedError(bindErr, "mailbox_account_owner_mismatch") {
				status = http.StatusNotFound
			}
			writeError(w, status, bindErr)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "mailbox": s.publicMailbox(r, bound)})
		return
	}
	writeError(w, http.StatusConflict, errCode("mailbox_operation_in_progress", "该邮箱正在切换 Apple 账号归属，请稍后重试", true))
}

func (s *Server) setMailboxStatusForRequest(ctx context.Context, mailboxID string, apiActive, icloudActive *bool, status, note string) (Mailbox, error) {
	return s.setMailboxStatusForRequestWithAccess(ctx, mailboxID, nil, apiActive, icloudActive, status, note)
}

func (s *Server) setMailboxStatusForRequestWithAccess(
	ctx context.Context,
	mailboxID string,
	canAccess func(Mailbox) bool,
	apiActive, icloudActive *bool,
	status, note string,
) (Mailbox, error) {
	mailbox, releaseAccountOperation, err := s.acquireCurrentMailboxAccountOperation(ctx, mailboxID)
	if err != nil {
		if isCodedError(err, "mailbox_not_found") {
			return Mailbox{}, err
		}
		return Mailbox{}, errCode("mailbox_operation_in_progress", "该邮箱账号正在执行同步、登录、创建或删除操作，请稍后重试", true)
	}
	defer releaseAccountOperation()
	if canAccess != nil && !canAccess(mailbox) {
		return Mailbox{}, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	if err := s.ensureOwnerNotDeleting(mailbox.OwnerID); err != nil {
		return Mailbox{}, err
	}
	return s.store.SetMailboxStatus(mailbox.ID, apiActive, icloudActive, status, note)
}

func (s *Server) handleSyncMailbox(w http.ResponseWriter, r *http.Request) {
	mailbox, ok := s.store.FindMailboxByID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	if !s.canAccessMailbox(r, mailbox) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	after, err := parseAfter(r.URL.Query().Get("after"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	count, err := s.syncMailbox(r.Context(), mailbox, after, strings.TrimSpace(r.URL.Query().Get("keyword")))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "synced": count})
}

func (s *Server) handleCleanRemoteMailbox(w http.ResponseWriter, r *http.Request) {
	mailbox, ok := s.store.FindMailboxByID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	if !s.canAccessMailbox(r, mailbox) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	var payload struct {
		MoveSynced bool `json:"move_synced"`
		EmptyTrash bool `json:"empty_trash"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !payload.MoveSynced && !payload.EmptyTrash {
		payload.MoveSynced = true
	}
	mailbox, releaseAccountOperation, err := s.acquireCurrentMailboxAccountOperation(r.Context(), mailbox.ID)
	if err != nil {
		if isCodedError(err, "mailbox_not_found") {
			writeError(w, http.StatusNotFound, err)
		} else {
			writeError(w, http.StatusConflict, errCode("mailbox_operation_in_progress", "该邮箱账号正在执行同步或删除操作，请稍后重试", true))
		}
		return
	}
	defer releaseAccountOperation()
	if !s.canAccessMailbox(r, mailbox) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	if err := s.ensureOwnerNotDeleting(mailbox.OwnerID); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	currentSession, ok := s.sessionForMailbox(mailbox.OwnerID, mailbox.AccountID)
	if !ok {
		writeError(w, http.StatusBadRequest, errCode("icloud_session_missing", "该账号的 iCloud 登录态已不存在，请重新保存旧接口登录态", true))
		return
	}
	session := currentSession

	client := NewICloudClient()
	result := ICloudMailCleanupResult{}
	if payload.MoveSynced {
		remoteIDs := icloudRemoteIDsFromMessages(s.store.MessagesForMailbox(mailbox.ID))
		moved, err := client.MoveRemoteMessagesToTrash(r.Context(), session, remoteIDs)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		result.MovedToTrash += moved.MovedToTrash
		result.Skipped += moved.Skipped
	}
	if payload.EmptyTrash {
		destroyed, err := client.EmptyTrash(r.Context(), session)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		result.Destroyed = destroyed
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "cleanup": result})
}

func (s *Server) handleCleanRemoteMailboxes(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID  string `json:"account_id"`
		MoveSynced bool   `json:"move_synced"`
		EmptyTrash bool   `json:"empty_trash"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !payload.MoveSynced && !payload.EmptyTrash {
		payload.MoveSynced = true
		payload.EmptyTrash = true
	}
	accountID := strings.TrimSpace(payload.AccountID)
	isUnbound := strings.EqualFold(accountID, "unbound")
	if isUnbound {
		accountID = "unbound"
	}
	if accountID != "" && !isUnbound && !s.canAccessAccountID(r, accountID) {
		writeError(w, http.StatusNotFound, errCode("account_not_found", "账号不存在", false))
		return
	}

	state := s.homeScopedState(r)
	client := NewICloudClient()
	result := ICloudMailCleanupResult{}
	handledMailboxes := 0
	failures := make([]mailboxCleanupFailure, 0)
	addFailure := func(mailbox Mailbox, err error) {
		message := publicErrorMessage(err)
		if strings.TrimSpace(message) == "" {
			message = "远端邮件清理失败"
		}
		failures = append(failures, mailboxCleanupFailure{
			ID:      mailbox.ID,
			Email:   mailbox.Email,
			Message: message,
		})
	}
	type cleanupGroup struct {
		session   ICloudSession
		mailboxes []Mailbox
	}
	groups := make(map[string]*cleanupGroup)
	order := make([]string, 0)
	for _, mailbox := range state.Mailboxes {
		if !mailboxMatchesRemoteCleanupAccount(mailbox, accountID) {
			continue
		}
		if !mailbox.ICloudActive || mailbox.Status == StatusDisabled {
			result.Skipped++
			continue
		}
		if s.ownerDeletionInProgress(mailbox.OwnerID) {
			result.Skipped++
			continue
		}
		session, ok := s.sessionForMailbox(mailbox.OwnerID, mailbox.AccountID)
		if !ok {
			result.Skipped++
			continue
		}
		groupKey := mailboxAccountOperationKey(mailbox.OwnerID, mailbox.AccountID)
		group := groups[groupKey]
		if group == nil {
			group = &cleanupGroup{session: session}
			groups[groupKey] = group
			order = append(order, groupKey)
		}
		group.mailboxes = append(group.mailboxes, mailbox)
	}
	for _, groupKey := range order {
		group := groups[groupKey]
		releaseAccountOperation, err := s.acquireMailboxAccountOperationSlot(r.Context(), groupKey)
		if err != nil {
			for _, mailbox := range group.mailboxes {
				addFailure(mailbox, err)
			}
			if s.logger != nil {
				s.logger.Warn("remote mail cleanup account operation was interrupted", "account_key", groupKey, "err", err)
			}
			continue
		}
		groupErr := func() error {
			defer releaseAccountOperation()
			if s.ownerDeletionInProgress(group.mailboxes[0].OwnerID) {
				group.mailboxes = nil
				return nil
			}
			group.mailboxes = s.currentRemoteCleanupMailboxes(
				group.mailboxes[0].OwnerID,
				group.mailboxes[0].AccountID,
				group.mailboxes,
			)
			if len(group.mailboxes) == 0 {
				return nil
			}
			currentSession, ok := s.sessionForMailbox(group.mailboxes[0].OwnerID, group.mailboxes[0].AccountID)
			if !ok {
				return errCode("icloud_session_missing", "该账号的 iCloud 登录态已不存在，请重新保存旧接口登录态", true)
			}
			group.session = currentSession
			ready := make([]Mailbox, 0, len(group.mailboxes))
			for _, mailbox := range group.mailboxes {
				if payload.MoveSynced {
					remoteIDs := icloudRemoteIDsFromMessages(s.store.MessagesForMailbox(mailbox.ID))
					moved, err := client.MoveRemoteMessagesToTrash(r.Context(), group.session, remoteIDs)
					if err != nil {
						if s.logger != nil {
							s.logger.Warn("remote mail cleanup move failed", "mailbox_id", mailbox.ID, "err", err)
						}
						addFailure(mailbox, err)
						continue
					}
					result.MovedToTrash += moved.MovedToTrash
					result.Skipped += moved.Skipped
				}
				ready = append(ready, mailbox)
			}
			if payload.EmptyTrash && len(ready) > 0 {
				destroyed, err := client.EmptyTrash(r.Context(), group.session)
				if err != nil {
					if s.logger != nil {
						s.logger.Warn("remote mail cleanup empty trash failed", "account_key", groupKey, "err", err)
					}
					for _, mailbox := range ready {
						addFailure(mailbox, err)
					}
					return nil
				}
				result.Destroyed += destroyed
			}
			handledMailboxes += len(ready)
			return nil
		}()
		if groupErr != nil {
			for _, mailbox := range group.mailboxes {
				addFailure(mailbox, groupErr)
			}
		}
	}
	failedMailboxes := len(failures)
	success := failedMailboxes == 0
	message := ""
	if !success {
		if handledMailboxes > 0 {
			message = "部分邮箱清理失败，请查看 failures 中的邮箱明细后重试"
		} else {
			message = "邮箱清理全部失败，请查看 failures 中的邮箱明细后重试"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":          success,
		"message":          message,
		"cleanup":          result,
		"mailboxes":        handledMailboxes,
		"failed_mailboxes": failedMailboxes,
		"failures":         failures,
	})
}

func (s *Server) currentRemoteCleanupMailboxes(ownerID, accountID string, candidates []Mailbox) []Mailbox {
	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	out := make([]Mailbox, 0, len(candidates))
	for _, candidate := range candidates {
		latest, ok := s.store.FindMailboxByID(candidate.ID)
		if !ok ||
			strings.TrimSpace(latest.OwnerID) != ownerID ||
			strings.TrimSpace(latest.AccountID) != accountID ||
			s.ownerDeletionInProgress(latest.OwnerID) ||
			!mailboxEligibleForRemoteCleanup(latest) {
			continue
		}
		out = append(out, latest)
	}
	return out
}

func mailboxEligibleForRemoteCleanup(mailbox Mailbox) bool {
	if !mailbox.ICloudActive || mailbox.Status == StatusDisabled {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(mailbox.RemoteDeleteStatus)) {
	case "pending", "unknown", "failed", "succeeded":
		return false
	default:
		return true
	}
}

func mailboxMatchesRemoteCleanupAccount(mailbox Mailbox, accountID string) bool {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return true
	}
	if strings.EqualFold(accountID, "unbound") {
		return strings.TrimSpace(mailbox.AccountID) == ""
	}
	return constantTimeEqual(accountID, strings.TrimSpace(mailbox.AccountID))
}

func (s *Server) handleDeleteMailbox(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canAccessMailboxID(r, id) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	mailbox, ok := s.store.FindMailboxByID(id)
	if !ok || !s.canAccessMailbox(r, mailbox) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	deleteRemote := truthy(r.URL.Query().Get("delete_remote"))
	confirmUnknown := truthy(r.URL.Query().Get("confirm_unknown"))
	confirmFailed := truthy(r.URL.Query().Get("confirm_failed"))
	if err := s.deleteMailboxForRequestWithAccess(
		r.Context(),
		id,
		func(current Mailbox) bool { return s.canAccessMailbox(r, current) },
		deleteRemote,
		confirmUnknown,
		confirmFailed,
	); err != nil {
		writeError(w, mailboxDeleteHTTPStatus(err, deleteRemote), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "deleted": 1})
}

type mailboxDeleteFailure struct {
	ID      string `json:"id"`
	Email   string `json:"email,omitempty"`
	Message string `json:"message"`
}

type mailboxCleanupFailure struct {
	ID      string `json:"id"`
	Email   string `json:"email,omitempty"`
	Message string `json:"message"`
}

type mailboxSelectionScope struct {
	OwnerID    string `json:"owner_id,omitempty"`
	AccountKey string `json:"account_key,omitempty"`
	Search     string `json:"search,omitempty"`
	Exported   string `json:"exported,omitempty"`
}

func (s *Server) handleBulkDeleteMailboxes(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		IDs            []string               `json:"ids"`
		DeleteRemote   bool                   `json:"delete_remote"`
		ConfirmUnknown bool                   `json:"confirm_unknown"`
		ConfirmFailed  bool                   `json:"confirm_failed"`
		Scope          *mailboxSelectionScope `json:"scope,omitempty"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	seen := make(map[string]struct{}, len(payload.IDs))
	ids := make([]string, 0, len(payload.IDs))
	for _, id := range payload.IDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, errCode("mailbox_ids_missing", "请选择要删除的邮箱", false))
		return
	}
	var scopedIDs map[string]struct{}
	if payload.Scope != nil {
		if err := validateMailboxExportedFilter(payload.Scope.Exported); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		scopedIDs = s.mailboxIDsForSelectionScope(r, *payload.Scope)
	}
	deleted := 0
	remoteDeleted := 0
	failures := make([]mailboxDeleteFailure, 0)
	startedAt := time.Now()
	for index, id := range ids {
		if err := r.Context().Err(); err != nil {
			for _, remaining := range ids[index:] {
				failures = append(failures, mailboxDeleteFailure{ID: remaining, Message: "请求已取消或超时，请重试剩余邮箱"})
			}
			break
		}
		if time.Since(startedAt) > bulkDeleteTimeBudget {
			for _, remaining := range ids[index:] {
				failures = append(failures, mailboxDeleteFailure{ID: remaining, Message: "批量删除已达时间上限，请重试剩余邮箱"})
			}
			break
		}
		mailbox, ok := s.store.FindMailboxByID(id)
		if !ok || !s.canAccessMailbox(r, mailbox) {
			failures = append(failures, mailboxDeleteFailure{ID: id, Message: "邮箱不存在或无权限"})
			continue
		}
		if scopedIDs != nil {
			if _, ok := scopedIDs[id]; !ok {
				failures = append(failures, mailboxDeleteFailure{
					ID:      id,
					Email:   mailbox.Email,
					Message: "邮箱不再符合当前筛选条件，请刷新后重试",
				})
				continue
			}
		}
		remoteAlreadyDeleted := strings.EqualFold(strings.TrimSpace(mailbox.RemoteDeleteStatus), "succeeded")
		if err := s.deleteMailboxForRequestWithAccess(
			r.Context(),
			id,
			func(current Mailbox) bool { return s.canAccessMailbox(r, current) },
			payload.DeleteRemote,
			payload.ConfirmUnknown,
			payload.ConfirmFailed,
		); err != nil {
			failures = append(failures, mailboxDeleteFailure{ID: id, Email: mailbox.Email, Message: publicErrorMessage(err)})
			continue
		}
		if payload.DeleteRemote && !remoteAlreadyDeleted {
			remoteDeleted++
		}
		deleted++
	}
	status := http.StatusOK
	success := true
	message := ""
	if len(failures) > 0 {
		status = http.StatusMultiStatus
		success = false
		if deleted == 0 {
			message = "批量删除全部失败，请查看 failures 中的逐条原因"
		} else {
			message = "批量删除部分成功，请查看 failures 中的逐条原因"
		}
	}
	writeJSON(w, status, map[string]any{
		"success":        success,
		"partial":        deleted > 0 && len(failures) > 0,
		"message":        message,
		"deleted":        deleted,
		"remote_deleted": remoteDeleted,
		"failed":         len(failures),
		"failures":       failures,
	})
}

func (s *Server) mailboxIDsForSelectionScope(r *http.Request, scope mailboxSelectionScope) map[string]struct{} {
	ownerID := strings.TrimSpace(scope.OwnerID)
	state := s.scopedState(r)
	if s.isAdminRequest(r) {
		switch {
		case ownerID == "" || strings.EqualFold(ownerID, "current"):
			if requestOwner := requestOwnerID(r, s.store); requestOwner != "" {
				state = s.store.SnapshotForOwner(requestOwner)
			}
			ownerID = ""
		case ownerID == "__global":
			state = s.store.SnapshotForGlobal()
		case strings.EqualFold(ownerID, "all"):
			state = s.scopedState(r)
		default:
			state = s.store.SnapshotForOwner(ownerID)
		}
	}
	values := make(url.Values)
	if ownerID != "" {
		values.Set("owner_id", ownerID)
	}
	if accountKey := strings.TrimSpace(scope.AccountKey); accountKey != "" {
		values.Set("account_key", accountKey)
	}
	if search := strings.TrimSpace(scope.Search); search != "" {
		values.Set("search", search)
	}
	if exported := strings.TrimSpace(scope.Exported); exported != "" {
		values.Set("exported", exported)
	}
	base := filterMailboxesByOwner(
		state.Mailboxes,
		values.Get("owner_id"),
		scopedOwnerID(r, s.store),
		s.isAdminRequest(r),
	)
	filtered := filterMailboxesForList(base, mailboxAccountMap(state.Accounts), values)
	out := make(map[string]struct{}, len(filtered))
	for _, mailbox := range filtered {
		if id := strings.TrimSpace(mailbox.ID); id != "" {
			out[id] = struct{}{}
		}
	}
	return out
}

func (s *Server) deleteRemoteMailboxForRequest(ctx context.Context, mailbox Mailbox) error {
	for attempt := 0; attempt < 4; attempt++ {
		current, releaseAccountOperation, err := s.acquireCurrentMailboxAccountOperation(ctx, mailbox.ID)
		if err != nil {
			return err
		}
		releaseRemoteDelete, err := s.acquireMailboxRemoteDeleteSlot(ctx, mailbox.ID)
		if err != nil {
			releaseAccountOperation()
			return err
		}
		latest, ok := s.store.FindMailboxByID(mailbox.ID)
		if !ok {
			releaseRemoteDelete()
			releaseAccountOperation()
			return errCode("mailbox_not_found", "邮箱不存在", false)
		}
		if mailboxAccountOperationKey(current.OwnerID, current.AccountID) !=
			mailboxAccountOperationKey(latest.OwnerID, latest.AccountID) {
			releaseRemoteDelete()
			releaseAccountOperation()
			continue
		}
		err = s.deleteRemoteMailboxLocked(ctx, latest, false)
		if isRemoteDeleteCompletedWarning(err) {
			if s.logger != nil {
				s.logger.Warn("remote mailbox delete completed with session persistence warning", "mailbox_id", mailbox.ID, "err", err)
			}
			err = nil
		}
		releaseRemoteDelete()
		releaseAccountOperation()
		return err
	}
	return errCode("mailbox_operation_in_progress", "该邮箱正在切换 Apple 账号归属，请稍后重试", true)
}

func (s *Server) deleteMailboxForRequest(ctx context.Context, mailboxID string, deleteRemote bool) error {
	return s.deleteMailboxForRequestWithOptions(ctx, mailboxID, deleteRemote, false)
}

func (s *Server) deleteMailboxForRequestWithOptions(ctx context.Context, mailboxID string, deleteRemote, confirmUnknown bool) error {
	return s.deleteMailboxForRequestWithAccess(ctx, mailboxID, nil, deleteRemote, confirmUnknown, false)
}

func (s *Server) deleteMailboxForRequestWithAccess(
	ctx context.Context,
	mailboxID string,
	canAccess func(Mailbox) bool,
	deleteRemote, confirmUnknown, confirmFailed bool,
) error {
	for attempt := 0; attempt < 4; attempt++ {
		var (
			mailbox                 Mailbox
			releaseAccountOperation func()
			accountAcquired         bool
			releaseRemoteDelete     func()
			remoteDeleteAcquired    bool
			err                     error
		)
		if deleteRemote {
			mailbox, releaseAccountOperation, err = s.acquireCurrentMailboxAccountOperation(ctx, mailboxID)
			accountAcquired = err == nil
		} else {
			mailbox, releaseAccountOperation, accountAcquired, err = s.tryAcquireCurrentMailboxAccountOperation(mailboxID)
		}
		if err != nil {
			return err
		}
		if !accountAcquired {
			return errCode("mailbox_operation_in_progress", "该邮箱正在执行同步或远端删除操作，请稍后重试", true)
		}

		if deleteRemote {
			releaseRemoteDelete, err = s.acquireMailboxRemoteDeleteSlot(ctx, mailboxID)
			remoteDeleteAcquired = err == nil
		} else {
			releaseRemoteDelete, remoteDeleteAcquired, err = s.tryAcquireMailboxRemoteDeleteSlot(mailboxID)
		}
		if err != nil {
			releaseAccountOperation()
			return err
		}
		if !remoteDeleteAcquired {
			releaseAccountOperation()
			return errCode("mailbox_operation_in_progress", "该邮箱正在执行远端删除操作，请稍后重试", true)
		}

		current, ok := s.store.FindMailboxByID(mailboxID)
		if !ok {
			releaseRemoteDelete()
			releaseAccountOperation()
			return errCode("mailbox_not_found", "邮箱不存在", false)
		}
		if mailboxAccountOperationKey(mailbox.OwnerID, mailbox.AccountID) !=
			mailboxAccountOperationKey(current.OwnerID, current.AccountID) {
			releaseRemoteDelete()
			releaseAccountOperation()
			continue
		}
		mailbox = current
		if canAccess != nil && !canAccess(mailbox) {
			releaseRemoteDelete()
			releaseAccountOperation()
			return errCode("mailbox_not_found", "邮箱不存在", false)
		}
		if err := s.ensureOwnerNotDeleting(mailbox.OwnerID); err != nil {
			releaseRemoteDelete()
			releaseAccountOperation()
			return err
		}
		if deleteRemote && !strings.EqualFold(strings.TrimSpace(mailbox.RemoteDeleteStatus), "succeeded") {
			if err := s.validateRemoteMailboxDelete(mailbox); err != nil {
				releaseRemoteDelete()
				releaseAccountOperation()
				return err
			}
		}
		if deleteRemote {
			if err := s.deleteRemoteMailboxLocked(ctx, mailbox, confirmUnknown); err != nil {
				if isRemoteDeleteCompletedWarning(err) {
					if s.logger != nil {
						s.logger.Warn("remote mailbox delete completed with session persistence warning", "mailbox_id", mailbox.ID, "err", err)
					}
				} else {
					releaseRemoteDelete()
					releaseAccountOperation()
					return err
				}
			}
		} else {
			switch strings.ToLower(strings.TrimSpace(mailbox.RemoteDeleteStatus)) {
			case "unknown":
				if !confirmUnknown {
					releaseRemoteDelete()
					releaseAccountOperation()
					return errCode("remote_delete_unknown", "上次远端删除在进程退出前未确认结果，请先核对 iCloud 远端状态后再清理本地记录", true)
				}
			case "pending":
				releaseRemoteDelete()
				releaseAccountOperation()
				return errCode("remote_delete_in_progress", "该邮箱已有远端删除操作进行中，请稍后重试", true)
			case "failed":
				if !confirmFailed {
					releaseRemoteDelete()
					releaseAccountOperation()
					return errCode("remote_delete_failed", "上次远端删除失败，请先重试远端删除，或确认已核对 iCloud 后再清理本地记录", true)
				}
			}
		}
		err = s.store.DeleteMailbox(mailboxID)
		releaseRemoteDelete()
		releaseAccountOperation()
		return err
	}
	return errCode("mailbox_operation_in_progress", "该邮箱正在切换 Apple 账号归属，请稍后重试", true)
}

func mailboxDeleteHTTPStatus(err error, deleteRemote bool) int {
	switch {
	case isCodedError(err, "mailbox_operation_in_progress"),
		isCodedError(err, "user_delete_in_progress"),
		isCodedError(err, "remote_delete_unknown"),
		isCodedError(err, "remote_delete_in_progress"),
		isCodedError(err, "remote_delete_failed"):
		return http.StatusConflict
	case isCodedError(err, "mailbox_not_found"):
		return http.StatusNotFound
	case isCodedError(err, "mailbox_delete_persist_failed"),
		isCodedError(err, "mailbox_remote_delete_state_persist_failed"):
		return http.StatusInternalServerError
	case deleteRemote:
		return http.StatusBadGateway
	default:
		return http.StatusNotFound
	}
}

func mailboxMutationHTTPStatus(err error) int {
	if isCodedError(err, "mailbox_not_found") {
		return http.StatusNotFound
	}
	if isCodedError(err, "mailbox_operation_in_progress") ||
		isCodedError(err, "user_delete_in_progress") ||
		isCodedError(err, "remote_delete_unknown") ||
		isCodedError(err, "remote_delete_in_progress") ||
		isCodedError(err, "remote_delete_failed") ||
		isCodedError(err, "mailbox_account_already_bound") ||
		isCodedError(err, "mailbox_remote_deleted") ||
		isCodedError(err, "mailbox_remote_missing") {
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

func mailboxCodeHTTPStatus(err error) int {
	switch {
	case isCodedError(err, "mailbox_not_found"):
		return http.StatusNotFound
	case isCodedError(err, "api_disabled"),
		isCodedError(err, "icloud_inactive"):
		return http.StatusForbidden
	case isCodedError(err, "remote_delete_unknown"),
		isCodedError(err, "remote_delete_in_progress"),
		isCodedError(err, "remote_delete_failed"),
		isCodedError(err, "mailbox_remote_deleted"),
		isCodedError(err, "user_delete_in_progress"):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func remoteDeleteOutcomeUnknown(err error) bool {
	return errors.Is(err, context.Canceled) || isAppleTransientNetworkError(err)
}

func (s *Server) deleteRemoteMailboxLocked(ctx context.Context, mailbox Mailbox, confirmUnknown bool) error {
	if strings.EqualFold(strings.TrimSpace(mailbox.RemoteDeleteStatus), "succeeded") {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(mailbox.RemoteDeleteStatus)) {
	case "unknown":
		if !confirmUnknown {
			return errCode("remote_delete_unknown", "上次远端删除在进程退出前未确认结果，请先核对 iCloud 远端状态后再重试", true)
		}
	case "pending":
		return errCode("remote_delete_in_progress", "该邮箱已有远端删除操作进行中，请稍后重试", true)
	}
	if err := s.validateRemoteMailboxDelete(mailbox); err != nil {
		return err
	}
	attemptedAt := time.Now()
	if err := s.store.BeginMailboxRemoteDelete(mailbox.ID, attemptedAt); err != nil {
		if isCodedError(err, "mailbox_not_found") ||
			isCodedError(err, "remote_delete_unknown") ||
			isCodedError(err, "remote_delete_in_progress") ||
			isCodedError(err, "mailbox_remote_delete_state_persist_failed") {
			return err
		}
		return errCode("mailbox_remote_delete_state_persist_failed", "远端删除开始状态写入失败，请稍后重试", true)
	}
	deleteRemote := s.deleteRemoteMailbox
	if deleteRemote == nil {
		deleteRemote = s.deleteICloudMailboxRemote
	}
	if err := deleteRemote(ctx, mailbox); err != nil {
		var completedWarning remoteDeleteCompletedWarning
		if errors.As(err, &completedWarning) {
			if s.logger != nil {
				s.logger.Warn("remote mailbox delete completed with session persistence warning", "mailbox_id", mailbox.ID, "err", completedWarning)
			}
		} else {
			markRemoteDeleteFailed := s.store.MarkMailboxRemoteDeleteFailed
			if remoteDeleteOutcomeUnknown(err) {
				markRemoteDeleteFailed = s.store.MarkMailboxRemoteDeleteUnknown
			}
			if persistErr := markRemoteDeleteFailed(mailbox.ID, publicErrorMessage(err), time.Now()); persistErr != nil {
				if s.logger != nil {
					s.logger.Error("persist remote mailbox delete failure state failed", "mailbox_id", mailbox.ID, "remote_err", err, "persist_err", persistErr)
				}
				return errCode("mailbox_remote_delete_state_persist_failed", "远端删除失败；本地失败状态写入失败，请核对 iCloud 远端状态后再重试", true)
			}
			return err
		}
	}
	if err := s.store.MarkMailboxRemoteDeleteSucceeded(mailbox.ID, time.Now()); err != nil {
		return errCode("mailbox_remote_delete_state_persist_failed", "远端删除已成功，但本地成功状态写入失败，请核对 iCloud 远端状态后再决定是否清理本地记录", true)
	}
	return nil
}

func mailboxAccountOperationKey(ownerID, accountID string) string {
	return strings.TrimSpace(ownerID) + "\x00" + strings.TrimSpace(accountID)
}

func (s *Server) acquireMailboxAccountOperationSlot(ctx context.Context, key string) (func(), error) {
	key, gate := s.registerMailboxAccountOperationGate(key)
	select {
	case gate.ch <- struct{}{}:
		return s.mailboxAccountOperationRelease(key, gate), nil
	case <-ctx.Done():
		s.releaseMailboxAccountOperationReference(key, gate)
		return nil, ctx.Err()
	}
}

func (s *Server) acquireCurrentMailboxAccountOperation(ctx context.Context, mailboxID string) (Mailbox, func(), error) {
	const maxAttempts = 4
	for attempt := 0; attempt < maxAttempts; attempt++ {
		mailbox, ok := s.store.FindMailboxByID(mailboxID)
		if !ok {
			return Mailbox{}, nil, errCode("mailbox_not_found", "邮箱不存在", false)
		}
		key := mailboxAccountOperationKey(mailbox.OwnerID, mailbox.AccountID)
		release, err := s.acquireMailboxAccountOperationSlot(ctx, key)
		if err != nil {
			return Mailbox{}, nil, err
		}
		current, ok := s.store.FindMailboxByID(mailboxID)
		if !ok {
			release()
			return Mailbox{}, nil, errCode("mailbox_not_found", "邮箱不存在", false)
		}
		if mailboxAccountOperationKey(current.OwnerID, current.AccountID) == key {
			return current, release, nil
		}
		release()
		if ctx.Err() != nil {
			return Mailbox{}, nil, ctx.Err()
		}
	}
	return Mailbox{}, nil, errCode("mailbox_operation_in_progress", "该邮箱正在切换 Apple 账号归属，请稍后重试", true)
}

func (s *Server) tryAcquireCurrentMailboxAccountOperation(mailboxID string) (Mailbox, func(), bool, error) {
	const maxAttempts = 4
	for attempt := 0; attempt < maxAttempts; attempt++ {
		mailbox, ok := s.store.FindMailboxByID(mailboxID)
		if !ok {
			return Mailbox{}, nil, false, errCode("mailbox_not_found", "邮箱不存在", false)
		}
		key := mailboxAccountOperationKey(mailbox.OwnerID, mailbox.AccountID)
		release, acquired, err := s.tryAcquireMailboxAccountOperationSlot(key)
		if err != nil {
			return Mailbox{}, nil, false, err
		}
		if !acquired {
			return Mailbox{}, nil, false, nil
		}
		current, ok := s.store.FindMailboxByID(mailboxID)
		if !ok {
			release()
			return Mailbox{}, nil, false, errCode("mailbox_not_found", "邮箱不存在", false)
		}
		if mailboxAccountOperationKey(current.OwnerID, current.AccountID) == key {
			return current, release, true, nil
		}
		release()
	}
	return Mailbox{}, nil, false, errCode("mailbox_operation_in_progress", "该邮箱正在切换 Apple 账号归属，请稍后重试", true)
}

func (s *Server) tryAcquireMailboxAccountOperationSlot(key string) (func(), bool, error) {
	key, gate := s.registerMailboxAccountOperationGate(key)
	select {
	case gate.ch <- struct{}{}:
		return s.mailboxAccountOperationRelease(key, gate), true, nil
	default:
		s.releaseMailboxAccountOperationReference(key, gate)
		return nil, false, nil
	}
}

func (s *Server) registerMailboxAccountOperationGate(key string) (string, *mailboxAccountOperationGate) {
	s.mailboxAccountOperationMu.Lock()
	defer s.mailboxAccountOperationMu.Unlock()
	if s.mailboxAccountOperationGates == nil {
		s.mailboxAccountOperationGates = make(map[string]*mailboxAccountOperationGate)
	}
	gate := s.mailboxAccountOperationGates[key]
	if gate == nil {
		gate = &mailboxAccountOperationGate{ch: make(chan struct{}, 1)}
		s.mailboxAccountOperationGates[key] = gate
	}
	gate.refs++
	return key, gate
}

func (s *Server) mailboxAccountOperationRelease(key string, gate *mailboxAccountOperationGate) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			<-gate.ch
			s.releaseMailboxAccountOperationReference(key, gate)
		})
	}
}

func (s *Server) releaseMailboxAccountOperationReference(key string, gate *mailboxAccountOperationGate) {
	s.mailboxAccountOperationMu.Lock()
	defer s.mailboxAccountOperationMu.Unlock()
	gate.refs--
	if gate.refs <= 0 && s.mailboxAccountOperationGates[key] == gate {
		delete(s.mailboxAccountOperationGates, key)
	}
}

func (s *Server) acquireMailboxRemoteDeleteSlot(ctx context.Context, mailboxID string) (func(), error) {
	key, gate, err := s.registerMailboxRemoteDeleteGate(mailboxID)
	if err != nil {
		return nil, err
	}

	select {
	case gate.ch <- struct{}{}:
		return s.mailboxRemoteDeleteRelease(key, gate), nil
	case <-ctx.Done():
		s.releaseMailboxRemoteDeleteReference(key, gate)
		return nil, ctx.Err()
	}
}

func (s *Server) tryAcquireMailboxRemoteDeleteSlot(mailboxID string) (func(), bool, error) {
	key, gate, err := s.registerMailboxRemoteDeleteGate(mailboxID)
	if err != nil {
		return nil, false, err
	}
	select {
	case gate.ch <- struct{}{}:
		return s.mailboxRemoteDeleteRelease(key, gate), true, nil
	default:
		s.releaseMailboxRemoteDeleteReference(key, gate)
		return nil, false, nil
	}
}

func (s *Server) registerMailboxRemoteDeleteGate(mailboxID string) (string, *mailboxRemoteDeleteGate, error) {
	key := strings.TrimSpace(mailboxID)
	if key == "" {
		return "", nil, errCode("mailbox_id_missing", "邮箱 ID 为空", false)
	}
	s.mailboxRemoteDeleteMu.Lock()
	if s.mailboxRemoteDeleteGates == nil {
		s.mailboxRemoteDeleteGates = make(map[string]*mailboxRemoteDeleteGate)
	}
	gate := s.mailboxRemoteDeleteGates[key]
	if gate == nil {
		gate = &mailboxRemoteDeleteGate{ch: make(chan struct{}, 1)}
		s.mailboxRemoteDeleteGates[key] = gate
	}
	gate.refs++
	s.mailboxRemoteDeleteMu.Unlock()
	return key, gate, nil
}

func (s *Server) mailboxRemoteDeleteRelease(key string, gate *mailboxRemoteDeleteGate) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			<-gate.ch
			s.releaseMailboxRemoteDeleteReference(key, gate)
		})
	}
}

func (s *Server) releaseMailboxRemoteDeleteReference(key string, gate *mailboxRemoteDeleteGate) {
	s.mailboxRemoteDeleteMu.Lock()
	defer s.mailboxRemoteDeleteMu.Unlock()
	gate.refs--
	if gate.refs <= 0 && s.mailboxRemoteDeleteGates[key] == gate {
		delete(s.mailboxRemoteDeleteGates, key)
	}
}

func (s *Server) validateRemoteMailboxDelete(mailbox Mailbox) error {
	remoteID := strings.TrimSpace(mailbox.RemoteAnonymousID)
	if remoteID == "" {
		return errCode("icloud_mailbox_anonymous_id_missing", "该邮箱没有已确认的 iCloud 远端 ID，不能安全删除远端邮箱；请先同步或重新导入邮箱", true)
	}
	remoteOrigin := strings.ToUpper(strings.TrimSpace(mailbox.RemoteOrigin))
	if remoteOrigin == "" {
		return errCode("icloud_mailbox_remote_origin_unknown", "该邮箱没有已确认的 iCloud 远端来源，已拒绝调用删除接口；请先同步或重新导入邮箱", true)
	}
	switch remoteOrigin {
	case "APPLE_ACCOUNT", "ICLOUD_WEB":
	default:
		return errCode("icloud_mailbox_remote_origin_unknown", "该邮箱缺少可识别的 iCloud 远端来源，已拒绝调用错误的删除接口；请先同步或重新导入邮箱", true)
	}
	session, ok := s.sessionForMailbox(mailbox.OwnerID, mailbox.AccountID)
	if !ok {
		if remoteOrigin == "APPLE_ACCOUNT" {
			return errCode("apple_account_session_missing", "未保存 Apple Account 新接口登录态，请先完成新接口登录", true)
		}
		return errCode("icloud_session_missing", "未保存 iCloud 登录态，请先保存旧接口登录态", true)
	}
	if remoteOrigin == "APPLE_ACCOUNT" {
		if _, hasState := appleAccountLoginState(session); !hasState {
			return errCode("apple_account_session_missing", "未保存 Apple Account 新接口登录态，请先完成新接口登录", true)
		}
	}
	if remoteOrigin == "ICLOUD_WEB" {
		if _, hasWeb := iCloudWebSessionForClient(session); !hasWeb {
			return errCode("icloud_session_missing", "未保存 iCloud 登录态，请先保存旧接口登录态", true)
		}
	}
	return nil
}

func (s *Server) deleteICloudMailboxRemote(ctx context.Context, mailbox Mailbox) error {
	if err := s.validateRemoteMailboxDelete(mailbox); err != nil {
		return err
	}
	remoteID := strings.TrimSpace(mailbox.RemoteAnonymousID)
	remoteOrigin := strings.ToUpper(strings.TrimSpace(mailbox.RemoteOrigin))
	session, ok := s.sessionForMailbox(mailbox.OwnerID, mailbox.AccountID)
	if !ok {
		if remoteOrigin == "APPLE_ACCOUNT" {
			return errCode("apple_account_session_missing", "未保存 Apple Account 新接口登录态，请先完成新接口登录", true)
		}
		return errCode("icloud_session_missing", "未保存 iCloud 登录态，请先保存旧接口登录态", true)
	}
	if remoteOrigin == "APPLE_ACCOUNT" {
		opCtx, cancel := context.WithTimeout(ctx, appleAccountManageOperationTimeout)
		defer cancel()
		updatedSession, err := newICloudKeepAliveClient().DeletePrivacyMailboxWithAppleAccount(opCtx, session, s.cfg.AppleAccountAPIKey, remoteID)
		if _, hasUpdatedState := appleAccountLoginState(updatedSession); hasUpdatedState {
			if saveErr := s.store.SaveICloudSessionForOwner(session.OwnerID, updatedSession); saveErr != nil {
				if s.logger != nil {
					s.logger.Warn("save Apple Account state after remote mailbox delete failed", "account_id", session.AccountID, "err", saveErr)
				}
				if err == nil {
					return remoteDeleteCompletedWarning{err: errCode(
						"icloud_session_persist_after_mailbox_delete",
						"远端邮箱已删除，但刷新后的 Apple Account 登录态写入失败："+saveErr.Error(),
						true,
					)}
				}
			}
		}
		return err
	}
	return NewICloudClient().DeletePrivacyMailbox(ctx, session, remoteID)
}

func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	mailbox, ok := s.store.FindMailboxByID(id)
	if !ok || !s.canAccessMailbox(r, mailbox) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	mailbox, releaseAccountOperation, err := s.acquireCurrentMailboxAccountOperation(r.Context(), id)
	if err != nil {
		if isCodedError(err, "mailbox_not_found") {
			writeError(w, http.StatusNotFound, err)
		} else {
			writeError(w, http.StatusConflict, errCode("mailbox_operation_in_progress", "该邮箱账号正在执行同步、登录、创建或删除操作，请稍后重试", true))
		}
		return
	}
	defer releaseAccountOperation()
	if !s.canAccessMailbox(r, mailbox) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	if err := s.ensureOwnerNotDeleting(mailbox.OwnerID); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	messages := s.store.MessagesForMailbox(id)
	out := make([]publicMessage, 0, len(messages))
	for _, msg := range messages {
		out = append(out, publicMessage{
			ID:         msg.ID,
			OwnerID:    msg.OwnerID,
			Owner:      s.ownerName(msg.OwnerID),
			MailboxID:  msg.MailboxID,
			Subject:    msg.Subject,
			From:       msg.From,
			Body:       msg.Body,
			ReceivedAt: formatTime(msg.ReceivedAt),
			CreatedAt:  formatTime(msg.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "messages": out})
}

func (s *Server) handleCreateMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.canAccessMailboxID(r, id) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	var payload struct {
		Subject    string `json:"subject"`
		From       string `json:"from"`
		Body       string `json:"body"`
		ReceivedAt string `json:"received_at"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	receivedAt := time.Now()
	if strings.TrimSpace(payload.ReceivedAt) != "" {
		parsed, err := time.Parse(time.RFC3339, payload.ReceivedAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, errCode("invalid_received_at", "received_at 必须是 RFC3339 时间", false))
			return
		}
		receivedAt = parsed
	}
	mailbox, releaseAccountOperation, err := s.acquireCurrentMailboxAccountOperation(r.Context(), id)
	if err != nil {
		if isCodedError(err, "mailbox_not_found") {
			writeError(w, http.StatusNotFound, err)
		} else {
			writeError(w, http.StatusConflict, errCode("mailbox_operation_in_progress", "该邮箱账号正在执行同步、登录、创建或删除操作，请稍后重试", true))
		}
		return
	}
	defer releaseAccountOperation()
	if !s.canAccessMailbox(r, mailbox) {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	if err := s.ensureOwnerNotDeleting(mailbox.OwnerID); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	msg, err := s.store.AddMessage(mailbox.ID, payload.Subject, payload.From, payload.Body, receivedAt)
	if err != nil {
		writeError(w, mailboxMutationHTTPStatus(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "message": msg})
}

func (s *Server) handleMailboxCodeByID(w http.ResponseWriter, r *http.Request) {
	mailbox, ok := s.store.FindMailboxByID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	s.writeMailboxCode(w, r, mailbox)
}

func (s *Server) handleMailboxCodeByEmail(w http.ResponseWriter, r *http.Request) {
	email, err := url.PathUnescape(r.PathValue("email"))
	if err != nil {
		writeError(w, http.StatusBadRequest, errCode("invalid_email", "邮箱路径非法", false))
		return
	}
	mailbox, ok := s.store.FindMailboxByEmail(email)
	if !ok {
		writeError(w, http.StatusNotFound, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	s.writeMailboxCode(w, r, mailbox)
}

func (s *Server) mailboxMessagesForCodeRequest(r *http.Request, mailboxID string) (Mailbox, []Message, error) {
	mailbox, releaseAccountOperation, err := s.acquireCurrentMailboxAccountOperation(r.Context(), mailboxID)
	if err != nil {
		if isCodedError(err, "mailbox_not_found") {
			return Mailbox{}, nil, err
		}
		return Mailbox{}, nil, errCode("mailbox_operation_in_progress", "该邮箱账号正在执行同步、登录、创建或删除操作，请稍后重试", true)
	}
	defer releaseAccountOperation()
	if !s.authorized(r, mailbox) && !s.authorizedMailboxWebSession(r, mailbox) {
		return Mailbox{}, nil, errCode("invalid_api_key", "API Key 错误", false)
	}
	if err := s.ensureOwnerNotDeleting(mailbox.OwnerID); err != nil {
		return Mailbox{}, nil, err
	}
	if err := mailboxCodeAvailabilityError(mailbox); err != nil {
		return Mailbox{}, nil, err
	}
	return mailbox, s.store.MessagesForMailbox(mailbox.ID), nil
}

func (s *Server) writeMailboxCodeRequestError(w http.ResponseWriter, err error) {
	status := mailboxCodeHTTPStatus(err)
	if isCodedError(err, "invalid_api_key") {
		status = http.StatusUnauthorized
	} else if isCodedError(err, "mailbox_not_found") {
		status = http.StatusNotFound
	}
	writeError(w, status, err)
}

func (s *Server) writeMailboxCode(w http.ResponseWriter, r *http.Request, mailbox Mailbox) {
	current, _, err := s.mailboxMessagesForCodeRequest(r, mailbox.ID)
	if err != nil {
		s.writeMailboxCodeRequestError(w, err)
		return
	}
	mailbox = current
	s.markMailWatcherActive(mailbox.ID)
	after, err := parseAfter(r.URL.Query().Get("after"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	keyword := strings.TrimSpace(r.URL.Query().Get("keyword"))
	if keyword == "" {
		keyword = mailboxCodeKeywordForProject(r.URL.Query().Get("project"))
	}
	if keyword == "" {
		keyword = "OpenAI"
	}
	now := time.Now()
	codeAfter := mailboxCodeAfter(after, now)
	allowStale := truthy(r.URL.Query().Get("allow_stale"))
	cacheOnly := truthy(r.URL.Query().Get("cache"))
	peekOnly := truthy(r.URL.Query().Get("peek")) || truthy(r.URL.Query().Get("preview"))
	skipMessageID := strings.TrimSpace(mailbox.LastCodeMessageID)
	if peekOnly {
		skipMessageID = ""
	}
	_, messages, err := s.mailboxMessagesForCodeRequest(r, mailbox.ID)
	if err != nil {
		s.writeMailboxCodeRequestError(w, err)
		return
	}
	if cacheOnly {
		if msg, code, ok := latestMailboxCode(messages, codeAfter, keyword, now); ok {
			s.writeMailboxCodeSuccess(w, r, mailbox, msg, code, "", false)
			return
		}
		writeError(w, http.StatusOK, errCode("no_code", "暂未收到验证码", true))
		return
	}
	if msg, code, ok := latestMailboxCodeSkipping(messages, codeAfter, keyword, now, skipMessageID); ok {
		s.writeMailboxCodeSuccess(w, r, mailbox, msg, code, "", !peekOnly)
		return
	}

	result := s.waitMailboxCode(r.Context(), mailbox, codeAfter, keyword, true, skipMessageID, s.mailboxCodeWaitDuration(r))
	if result.syncErr != nil {
		s.logger.Warn("icloud sync failed", "mailbox_id", mailbox.ID, "err", result.syncErr)
	}
	if result.ok {
		s.writeMailboxCodeSuccess(w, r, mailbox, result.message, result.code, staleCacheMessage(result.syncErr), !peekOnly)
		return
	}
	if msg, code, ok := latestMailboxCodeSkipping(s.store.MessagesForMailbox(mailbox.ID), codeAfter, keyword, time.Now(), skipMessageID); ok {
		s.writeMailboxCodeSuccess(w, r, mailbox, msg, code, staleCacheMessage(result.syncErr), !peekOnly)
		return
	}
	if result.syncErr != nil && allowStale {
		if msg, code, ok := latestMailboxCodeSkipping(s.store.MessagesForMailbox(mailbox.ID), codeAfter, keyword, time.Now(), skipMessageID); ok {
			s.writeMailboxCodeSuccess(w, r, mailbox, msg, code, "取码同步失败，当前验证码来自本地缓存", !peekOnly)
			return
		}
	}
	if result.syncErr != nil && !allowStale {
		writeError(w, http.StatusBadGateway, errCode("mail_sync_failed", "同步验证码邮件失败，已拒绝返回本地旧验证码；请检查取码登录或稍后重试", true))
		return
	}
	writeError(w, http.StatusOK, errCode("no_code", "暂未收到验证码", true))
}

func (s *Server) writeMailboxCodeSuccess(w http.ResponseWriter, r *http.Request, mailbox Mailbox, msg Message, code string, staleMessage string, markServed bool) {
	current, ok := s.store.FindMailboxByID(mailbox.ID)
	if !ok {
		s.writeMailboxCodeRequestError(w, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	if !s.authorized(r, current) && !s.authorizedMailboxWebSession(r, current) {
		s.writeMailboxCodeRequestError(w, errCode("invalid_api_key", "API Key 错误", false))
		return
	}
	if err := s.ensureOwnerNotDeleting(current.OwnerID); err != nil {
		s.writeMailboxCodeRequestError(w, err)
		return
	}
	if err := mailboxCodeAvailabilityError(current); err != nil {
		s.writeMailboxCodeRequestError(w, err)
		return
	}
	if msg.MailboxID != "" && msg.MailboxID != current.ID {
		s.writeMailboxCodeRequestError(w, errCode("mailbox_not_found", "邮箱不存在", false))
		return
	}
	mailbox = current
	if markServed {
		if _, err := s.store.SetMailboxLastCode(mailbox.ID, msg.ID, time.Now()); err != nil {
			if isCodedError(err, "mailbox_code_already_served") {
				writeError(w, http.StatusOK, errCode("no_code", "暂未收到验证码", true))
				return
			}
			s.logger.Warn("remember mailbox code failed", "mailbox_id", mailbox.ID, "message_id", msg.ID, "err", err)
			if mailboxCodeHTTPStatus(err) != http.StatusInternalServerError {
				writeError(w, mailboxCodeHTTPStatus(err), err)
				return
			}
			writeError(w, http.StatusInternalServerError, errCode("remember_code_failed", "保存验证码发放记录失败，请稍后重试", true))
			return
		}
	}
	payload := map[string]any{
		"success":     true,
		"email":       mailbox.Email,
		"code":        code,
		"subject":     msg.Subject,
		"received_at": formatTime(msg.ReceivedAt),
		"message_id":  msg.ID,
	}
	if staleMessage != "" {
		payload["stale_cache"] = true
		payload["sync_error"] = staleMessage
	}
	writeJSON(w, http.StatusOK, payload)
}

func staleCacheMessage(err error) string {
	if err == nil {
		return ""
	}
	return "取码同步失败，当前验证码来自本地缓存"
}

func mailboxCodeAfter(after, now time.Time) time.Time {
	if now.IsZero() {
		now = time.Now()
	}
	cutoff := now.Add(-mailboxCodeFreshWindow)
	if after.After(cutoff) {
		return after
	}
	return cutoff
}

func mailboxCodeKeywordForProject(project string) string {
	switch strings.ToLower(strings.TrimSpace(project)) {
	case "":
		return ""
	case "openai":
		return "OpenAI"
	case "chatgpt":
		return "ChatGPT"
	default:
		return strings.TrimSpace(project)
	}
}

func (s *Server) authorizedMailboxWebSession(r *http.Request, mailbox Mailbox) bool {
	if !s.authorizedAdminSession(r) && !s.authorizedUserSession(r) {
		return false
	}
	return s.canAccessMailbox(r, mailbox)
}

func latestMailboxCode(messages []Message, after time.Time, keyword string, now time.Time) (Message, string, bool) {
	return latestMailboxCodeSkipping(messages, after, keyword, now, "")
}

func latestMailboxCodeSkipping(messages []Message, after time.Time, keyword string, now time.Time, skipMessageID string) (Message, string, bool) {
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		keyword = "OpenAI"
	}
	skipMessageID = strings.TrimSpace(skipMessageID)
	after = mailboxCodeAfter(after, now)
	sort.SliceStable(messages, func(i, j int) bool {
		left := firstNonZeroTime(messages[i].ReceivedAt, messages[i].CreatedAt)
		right := firstNonZeroTime(messages[j].ReceivedAt, messages[j].CreatedAt)
		return left.After(right)
	})
	for _, msg := range messages {
		if skipMessageID != "" && msg.ID == skipMessageID {
			continue
		}
		msgTime := firstNonZeroTime(msg.ReceivedAt, msg.CreatedAt)
		if msgTime.IsZero() || msgTime.Before(after) {
			continue
		}
		text := msg.Subject + "\n" + msg.Body
		if !strings.Contains(strings.ToLower(text), strings.ToLower(keyword)) && keyword != "OpenAI" {
			continue
		}
		code := extractOTP(text)
		if code == "" {
			continue
		}
		return msg, code, true
	}
	return Message{}, "", false
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func (s *Server) mailboxCodeWaitDuration(r *http.Request) time.Duration {
	fallback := s.mailboxCodeFastWait
	if r == nil {
		return fallback
	}
	raw := strings.TrimSpace(r.URL.Query().Get("wait_ms"))
	if raw == "" {
		return fallback
	}
	fallbackMS := int(fallback / time.Millisecond)
	maxMS := int(mailboxCodeMaxClientWait / time.Millisecond)
	waitMS := parseBoundedPositiveInt(raw, fallbackMS, 1, maxMS)
	return time.Duration(waitMS) * time.Millisecond
}

func (s *Server) waitMailboxCode(ctx context.Context, mailbox Mailbox, after time.Time, keyword string, forceSync bool, skipMessageID string, waitDuration time.Duration) mailboxCodeResult {
	waitCtx := context.Background()
	var requestDone <-chan struct{}
	if ctx != nil {
		waitCtx = context.WithoutCancel(ctx)
		requestDone = ctx.Done()
	}
	waiter := &mailboxCodeWaiter{
		ctx:           waitCtx,
		mailboxID:     mailbox.ID,
		after:         after,
		keyword:       keyword,
		forceSync:     forceSync,
		skipMessageID: skipMessageID,
		result:        make(chan mailboxCodeResult, 1),
	}
	ownerKey := mailboxSyncOwnerKey(mailbox.OwnerID)
	s.mailboxCodeMu.Lock()
	if s.mailboxCodePollers == nil {
		s.mailboxCodePollers = make(map[string]*mailboxCodePoller)
	}
	poller := s.mailboxCodePollers[ownerKey]
	if poller == nil {
		poller = &mailboxCodePoller{ownerID: mailbox.OwnerID}
		s.mailboxCodePollers[ownerKey] = poller
		go s.runMailboxCodePoller(ownerKey, poller)
	}
	poller.waiters = append(poller.waiters, waiter)
	s.mailboxCodeMu.Unlock()

	var timeout <-chan time.Time
	var timer *time.Timer
	if waitDuration > 0 {
		timer = time.NewTimer(waitDuration)
		timeout = timer.C
		defer timer.Stop()
	}
	var localTick <-chan time.Time
	var localTicker *time.Ticker
	if waitDuration > 0 {
		interval := s.mailboxCodeLocalPollInterval
		if interval <= 0 {
			interval = 100 * time.Millisecond
		}
		if interval > waitDuration {
			interval = waitDuration
		}
		localTicker = time.NewTicker(interval)
		localTick = localTicker.C
		defer localTicker.Stop()
	}
	for {
		select {
		case result := <-waiter.result:
			return result
		case <-localTick:
			if msg, code, ok := s.latestMailboxCodeForWaiter(waiter); ok {
				return mailboxCodeResult{message: msg, code: code, ok: true}
			}
		case <-timeout:
			if msg, code, ok := s.latestMailboxCodeForWaiter(waiter); ok {
				return mailboxCodeResult{message: msg, code: code, ok: true}
			}
			return mailboxCodeResult{}
		case <-requestDone:
			return mailboxCodeResult{syncErr: ctx.Err()}
		}
	}
}

func (s *Server) runMailboxCodePoller(ownerKey string, poller *mailboxCodePoller) {
	for {
		if debounce := s.mailboxCodePollDebounce; debounce > 0 {
			time.Sleep(debounce)
		}
		s.mailboxCodeMu.Lock()
		waiters := poller.waiters
		poller.waiters = nil
		if len(waiters) == 0 {
			delete(s.mailboxCodePollers, ownerKey)
			s.mailboxCodeMu.Unlock()
			return
		}
		s.mailboxCodeMu.Unlock()
		s.resolveMailboxCodeWaiters(poller.ownerID, waiters)
	}
}

func (s *Server) resolveMailboxCodeWaiters(ownerID string, waiters []*mailboxCodeWaiter) {
	active := activeMailboxCodeWaiters(waiters)
	if len(active) == 0 {
		return
	}
	pending := make([]*mailboxCodeWaiter, 0, len(active))
	for _, waiter := range active {
		if !waiter.forceSync {
			msg, code, ok := s.latestMailboxCodeForWaiter(waiter)
			if ok {
				deliverMailboxCodeResult(waiter, mailboxCodeResult{message: msg, code: code, ok: true})
				continue
			}
		}
		pending = append(pending, waiter)
	}
	if len(pending) == 0 {
		return
	}
	syncCtx := context.Background()
	if pending[0].ctx != nil {
		syncCtx = context.WithoutCancel(pending[0].ctx)
	}
	syncCtx, cancel := context.WithTimeout(syncCtx, s.mailboxCodeBatchSyncTimeout)
	defer cancel()
	syncErr := s.syncMailboxesForCodeWaiters(syncCtx, ownerID, pending)
	for _, waiter := range pending {
		if waiterCanceled(waiter) {
			continue
		}
		msg, code, ok := s.latestMailboxCodeForWaiter(waiter)
		deliverMailboxCodeResult(waiter, mailboxCodeResult{message: msg, code: code, ok: ok, syncErr: syncErr})
	}
}

func activeMailboxCodeWaiters(waiters []*mailboxCodeWaiter) []*mailboxCodeWaiter {
	active := make([]*mailboxCodeWaiter, 0, len(waiters))
	for _, waiter := range waiters {
		if waiter == nil || waiterCanceled(waiter) {
			continue
		}
		active = append(active, waiter)
	}
	return active
}

func waiterCanceled(waiter *mailboxCodeWaiter) bool {
	if waiter == nil || waiter.ctx == nil {
		return false
	}
	select {
	case <-waiter.ctx.Done():
		return true
	default:
		return false
	}
}

func deliverMailboxCodeResult(waiter *mailboxCodeWaiter, result mailboxCodeResult) {
	select {
	case waiter.result <- result:
	default:
	}
}

func (s *Server) latestMailboxCodeForWaiter(waiter *mailboxCodeWaiter) (Message, string, bool) {
	if waiter == nil {
		return Message{}, "", false
	}
	mailbox, ok := s.store.FindMailboxByID(waiter.mailboxID)
	if !ok || s.ownerDeletionInProgress(mailbox.OwnerID) || !mailboxCanServeCode(mailbox) {
		return Message{}, "", false
	}
	return latestMailboxCodeSkipping(s.store.MessagesForMailbox(waiter.mailboxID), waiter.after, waiter.keyword, time.Now(), waiter.skipMessageID)
}

func (s *Server) syncMailboxesForCodeWaiters(ctx context.Context, ownerID string, waiters []*mailboxCodeWaiter) error {
	type keywordGroup struct {
		keyword  string
		byID     map[string]Mailbox
		minAfter time.Time
	}
	groups := make(map[string]*keywordGroup)
	for _, waiter := range waiters {
		if waiterCanceled(waiter) {
			continue
		}
		mailbox, ok := s.store.FindMailboxByID(waiter.mailboxID)
		if !ok || s.ownerDeletionInProgress(mailbox.OwnerID) || !mailboxCanServeCode(mailbox) {
			continue
		}
		keyword := strings.TrimSpace(waiter.keyword)
		if keyword == "" {
			keyword = "OpenAI"
		}
		groupKey := strings.ToLower(keyword)
		group := groups[groupKey]
		if group == nil {
			group = &keywordGroup{keyword: keyword, byID: make(map[string]Mailbox)}
			groups[groupKey] = group
		}
		if group.minAfter.IsZero() || waiter.after.Before(group.minAfter) {
			group.minAfter = waiter.after
		}
		group.byID[waiter.mailboxID] = mailbox
	}
	if len(groups) == 0 {
		return nil
	}
	var firstErr error
	for _, group := range groups {
		mailboxes := make([]Mailbox, 0, len(group.byID))
		for _, mailbox := range group.byID {
			mailboxes = append(mailboxes, mailbox)
		}
		sort.Slice(mailboxes, func(i, j int) bool {
			return mailboxes[i].Email < mailboxes[j].Email
		})
		_, err := s.syncMailboxCodeBatchForOwnerWithLimit(ctx, ownerID, mailboxes, group.minAfter, group.keyword, 0)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Server) runMailWatcher(ctx context.Context) {
	defer func() {
		s.mailWatcherMu.Lock()
		s.mailWatcherCancel = nil
		s.mailWatcherMu.Unlock()
	}()

	idleWorkers := make(map[string]mailboxWatcherIdleWorker)
	stopIdleWorkers := func() {
		for key, worker := range idleWorkers {
			worker.cancel()
			delete(idleWorkers, key)
		}
	}
	defer stopIdleWorkers()
	s.ensureMailWatcherIdleWorkers(ctx, idleWorkers)
	s.syncMailWatcherRound(ctx, false)
	interval := s.mailWatcherInterval
	if interval <= 0 {
		interval = mailWatcherPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.mailWatcherWake:
			s.ensureMailWatcherIdleWorkers(ctx, idleWorkers)
			s.syncMailWatcherRound(ctx, false)
		case <-ticker.C:
			s.ensureMailWatcherIdleWorkers(ctx, idleWorkers)
			s.syncMailWatcherRound(ctx, false)
		}
	}
}

func (s *Server) runAppleAccountKeepAlive(ctx context.Context) {
	defer func() {
		s.appleAccountKeepAliveMu.Lock()
		s.appleAccountKeepAliveCancel = nil
		s.appleAccountKeepAliveMu.Unlock()
	}()

	s.keepAliveAppleAccountRound(ctx)
	interval := s.appleAccountKeepAliveInterval
	if interval <= 0 {
		interval = appleAccountKeepAliveDefaultInterval
	}
	ticker := time.NewTicker(appleAccountKeepAliveScanInterval(interval))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.keepAliveAppleAccountRound(ctx)
		}
	}
}

func appleAccountKeepAliveScanInterval(base time.Duration) time.Duration {
	if base <= 0 {
		base = appleAccountKeepAliveDefaultInterval
	}
	interval := base / 4
	if interval > 30*time.Second {
		return 30 * time.Second
	}
	if interval < 5*time.Second {
		return 5 * time.Second
	}
	return interval
}

func (s *Server) keepAliveAppleAccountRound(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	keepAliveFn := s.keepAliveAppleAccountState
	if keepAliveFn == nil {
		keepAliveFn = func(ctx context.Context, state LoginState) (LoginState, error) {
			return newICloudKeepAliveClient().keepAliveAppleAccountManageStateUnlocked(ctx, state)
		}
	}
	baseInterval := s.appleAccountKeepAliveInterval
	if baseInterval <= 0 {
		baseInterval = appleAccountKeepAliveDefaultInterval
	}
	now := time.Now()
	for _, session := range s.appleAccountKeepAliveSessions() {
		if ctx.Err() != nil {
			return
		}
		state, ok := appleAccountLoginState(session)
		if !ok || strings.TrimSpace(state.APIKey) == "" {
			continue
		}
		interval := appleAccountKeepAliveIntervalForSession(session, baseInterval)
		if !appleAccountKeepAliveDue(state, now, interval) {
			continue
		}
		releaseAccountOperation, accountGateErr := s.acquireMailboxAccountOperationSlot(
			ctx,
			mailboxAccountOperationKey(session.OwnerID, session.AccountID),
		)
		if accountGateErr != nil {
			if s.logger != nil {
				s.logger.Warn("apple account keepalive mailbox account gate failed", "owner", s.ownerName(session.OwnerID), "account_id", session.AccountID, "apple_id", session.AppleID, "err", accountGateErr)
			}
			continue
		}
		currentSession, ok := s.sessionForOwnerAccount(session.OwnerID, session.AccountID)
		if !ok {
			releaseAccountOperation()
			continue
		}
		if err := s.ensureOwnerNotDeleting(currentSession.OwnerID); err != nil {
			releaseAccountOperation()
			continue
		}
		currentState, ok := appleAccountLoginState(currentSession)
		if !ok || strings.TrimSpace(currentState.APIKey) == "" ||
			!appleAccountKeepAliveEligible(currentSession) ||
			!appleAccountKeepAliveDue(currentState, now, appleAccountKeepAliveIntervalForSession(currentSession, baseInterval)) {
			releaseAccountOperation()
			continue
		}
		session = currentSession
		state = currentState
		release, gateErr := acquireAppleAccountOperationGate(ctx, appleAccountOperationKey(session, state))
		if gateErr != nil {
			releaseAccountOperation()
			if s.logger != nil {
				s.logger.Warn("apple account keepalive gate failed", "owner", s.ownerName(session.OwnerID), "account_id", session.AccountID, "apple_id", session.AppleID, "err", gateErr)
			}
			continue
		}
		callCtx, cancel := context.WithTimeout(ctx, appleAccountKeepAliveTimeout)
		next, err := keepAliveFn(callCtx, state)
		release()
		if err != nil {
			if isCodedError(err, "apple_account_keepalive_retrying") || isCodedError(err, "apple_account_auth_failed") {
				session = withAppleAccountLoginState(session, next)
				if saveErr := s.store.SaveICloudSessionForOwner(session.OwnerID, session); saveErr != nil && s.logger != nil {
					s.logger.Warn("apple account keepalive save failed", "owner", s.ownerName(session.OwnerID), "account_id", session.AccountID, "err", saveErr)
				}
				if s.logger != nil {
					if isCodedError(err, "apple_account_keepalive_retrying") {
						s.logger.Warn("apple account keepalive retry", "owner", s.ownerName(session.OwnerID), "account_id", session.AccountID, "apple_id", session.AppleID, "err", err)
					} else {
						s.logger.Warn("apple account keepalive stopped", "owner", s.ownerName(session.OwnerID), "account_id", session.AccountID, "apple_id", session.AppleID, "err", err)
					}
				}
			} else {
				session = withAppleAccountLoginState(session, appleAccountKeepAlivePersistTransient(state, next))
				if saveErr := s.store.SaveICloudSessionForOwner(session.OwnerID, session); saveErr != nil && s.logger != nil {
					s.logger.Warn("apple account keepalive save failed", "owner", s.ownerName(session.OwnerID), "account_id", session.AccountID, "err", saveErr)
				}
				if s.logger != nil {
					s.logger.Warn("apple account keepalive failed", "owner", s.ownerName(session.OwnerID), "account_id", session.AccountID, "apple_id", session.AppleID, "err", err)
				}
			}
			releaseAccountOperation()
			cancel()
			continue
		}
		session = withAppleAccountLoginState(session, next)
		if err := s.store.SaveICloudSessionForOwner(session.OwnerID, session); err != nil {
			releaseAccountOperation()
			cancel()
			if s.logger != nil {
				s.logger.Warn("apple account keepalive save failed", "owner", s.ownerName(session.OwnerID), "account_id", session.AccountID, "err", err)
			}
			continue
		}
		releaseAccountOperation()
		cancel()
		if s.logger != nil {
			s.logger.Info("apple account keepalive ok", "owner", s.ownerName(session.OwnerID), "account_id", session.AccountID, "apple_id", session.AppleID)
		}
	}
}

func (s *Server) appleAccountKeepAliveSessions() []ICloudSession {
	state := s.store.Snapshot()
	out := make([]ICloudSession, 0, len(state.ICloudSessions)+1)
	if state.ICloudSession != nil && appleAccountKeepAliveEligible(*state.ICloudSession) {
		out = append(out, cloneICloudSession(*state.ICloudSession))
	}
	for _, session := range state.ICloudSessions {
		if !appleAccountKeepAliveEligible(session) {
			continue
		}
		out = append(out, cloneICloudSession(session))
	}
	return out
}

func appleAccountKeepAliveEligible(session ICloudSession) bool {
	state, ok := appleAccountLoginState(session)
	if !ok || strings.TrimSpace(state.APIKey) == "" {
		return false
	}
	if state.KeepAliveStopped {
		return false
	}
	if !state.LastCheckOK && state.KeepAliveFailCount == 0 && !state.LastCheckedAt.IsZero() {
		return false
	}
	return true
}

func appleAccountKeepAliveIntervalForSession(session ICloudSession, base time.Duration) time.Duration {
	if base <= 0 {
		base = appleAccountKeepAliveDefaultInterval
	}
	jitter := base / 5
	if jitter > time.Minute {
		jitter = time.Minute
	}
	if jitter < time.Second {
		return base
	}
	steps := int64(jitter / time.Second)
	if steps <= 0 {
		return base
	}
	h := fnv.New32a()
	_, _ = io.WriteString(h, strings.TrimSpace(session.OwnerID)+"|"+strings.TrimSpace(session.AccountID)+"|"+strings.ToLower(strings.TrimSpace(session.AppleID)))
	offsetSteps := int64(h.Sum32()%uint32(steps*2+1)) - steps
	next := base + time.Duration(offsetSteps)*time.Second
	if base >= time.Minute && next < 30*time.Second {
		return 30 * time.Second
	}
	return next
}

func (s *Server) ensureMailWatcherIdleWorkers(ctx context.Context, workers map[string]mailboxWatcherIdleWorker) {
	groups := s.mailWatcherIMAPGroups()
	seen := make(map[string]struct{}, len(groups))
	for index := range groups {
		group := groups[index]
		initialKey := group.key
		if err := s.ensureMailWatcherIMAPBaseline(ctx, &group); err != nil {
			if s.logger != nil {
				s.logger.Warn("mail watcher imap baseline failed", "owner", s.ownerName(group.ownerID), "mailboxes", len(group.mailboxes), "err", err)
			}
			continue
		}
		seen[group.key] = struct{}{}
		if initialKey != group.key {
			if worker, ok := workers[initialKey]; ok {
				worker.cancel()
				delete(workers, initialKey)
			}
		}
		if worker, ok := workers[group.key]; ok && worker.signature == group.signature {
			continue
		}
		if worker, ok := workers[group.key]; ok {
			worker.cancel()
		}
		workerCtx, cancel := context.WithCancel(ctx)
		workers[group.key] = mailboxWatcherIdleWorker{cancel: cancel, signature: group.signature}
		go s.runMailWatcherIdleWorker(workerCtx, group)
	}
	for key, worker := range workers {
		if _, ok := seen[key]; ok {
			continue
		}
		worker.cancel()
		delete(workers, key)
	}
}

func (s *Server) ensureMailWatcherIMAPBaseline(ctx context.Context, group *mailboxWatcherIMAPGroup) error {
	if group == nil {
		return errCode("mail_watcher_group_missing", "邮件监听账号分组为空", false)
	}
	releaseAccountOperation, err := s.acquireMailboxAccountOperationSlot(
		ctx,
		mailboxAccountOperationKey(group.ownerID, group.accountID),
	)
	if err != nil {
		return err
	}
	defer releaseAccountOperation()
	if err := s.ensureOwnerNotDeleting(group.ownerID); err != nil {
		return err
	}

	currentSession, ok := s.sessionForOwnerAccount(group.ownerID, group.accountID)
	if !ok {
		return errCode("imap_session_missing", "该账号的取码登录态已不存在，请重新保存 iCloud 邮箱账号和 App 专用密码", true)
	}
	currentState, ok := iCloudIMAPLoginState(currentSession)
	if !ok {
		return errCode("imap_session_missing", "该账号的取码登录态已不存在，请重新保存 iCloud 邮箱账号和 App 专用密码", true)
	}
	group.accountID = strings.TrimSpace(currentSession.AccountID)
	group.state = currentState
	group.key = mailWatcherIMAPGroupKey(group.ownerID, group.accountID, group.state)
	group.signature = mailWatcherIMAPGroupSignature(group.state, group.mailboxes)
	if imapUIDNumber(group.state.IMAPLastSyncUID) > 0 {
		return nil
	}
	latestFn := s.latestIMAPUID
	if latestFn == nil {
		latestFn = LatestICloudIMAPUID
	}
	uid, err := latestFn(ctx, group.state)
	if err != nil {
		return err
	}
	if strings.TrimSpace(uid) == "" {
		return nil
	}
	accountID := strings.TrimSpace(group.accountID)
	if _, err := s.store.SetICloudIMAPSyncCursor(group.ownerID, accountID, imapStateKey(group.state), time.Now(), uid); err != nil {
		return err
	}
	return nil
}

func (s *Server) runMailWatcherIdleWorker(ctx context.Context, group mailboxWatcherIMAPGroup) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := WatchICloudIMAPExists(ctx, group.state, func() {
			if ctx.Err() != nil {
				return
			}
			syncCtx, cancel := context.WithTimeout(ctx, mailWatcherSyncTimeout)
			_, syncErr := s.syncMailboxCodeBatchForOwnerWithLimit(syncCtx, group.ownerID, group.mailboxes, time.Time{}, "ChatGPT", s.mailWatcherFetchLimit)
			cancel()
			if syncErr != nil && ctx.Err() == nil && s.logger != nil {
				s.logger.Warn("mail watcher idle sync failed", "owner", s.ownerName(group.ownerID), "mailboxes", len(group.mailboxes), "err", syncErr)
			}
		})
		if ctx.Err() != nil {
			return
		}
		if err != nil && s.logger != nil {
			s.logger.Warn("mail watcher idle disconnected", "owner", s.ownerName(group.ownerID), "mailboxes", len(group.mailboxes), "err", err)
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < 15*time.Second {
			backoff *= 2
		}
	}
}

func (s *Server) syncMailWatcherRound(ctx context.Context, initial bool) {
	if ctx.Err() != nil {
		return
	}
	groups := s.mailWatcherGroups()
	if len(groups) == 0 {
		return
	}
	after := time.Time{}
	fetchLimit := s.mailWatcherFetchLimit
	if initial {
		fetchLimit = s.mailWatcherInitialFetchLimit
		if s.mailWatcherLookback > 0 {
			after = time.Now().Add(-s.mailWatcherLookback)
		}
	}
	if fetchLimit <= 0 {
		fetchLimit = defaultMailWatcherFetchLimit
	}
	for _, group := range groups {
		if ctx.Err() != nil {
			return
		}
		syncCtx, cancel := context.WithTimeout(ctx, mailWatcherSyncTimeout)
		_, err := s.syncMailboxCodeBatchForOwnerWithLimit(syncCtx, group.ownerID, group.mailboxes, after, "OpenAI", fetchLimit)
		cancel()
		if err != nil && ctx.Err() == nil && s.logger != nil {
			s.logger.Warn("mail watcher sync failed", "owner", s.ownerName(group.ownerID), "mailboxes", len(group.mailboxes), "initial", initial, "err", err)
		}
	}
}

func (s *Server) markMailWatcherActive(mailboxID string) {
	mailboxID = strings.TrimSpace(mailboxID)
	if mailboxID == "" {
		return
	}
	ttl := mailWatcherActiveTTL
	if ttl <= 0 {
		ttl = 20 * time.Minute
	}
	s.mailWatcherMu.Lock()
	if s.mailWatcherActiveUntil == nil {
		s.mailWatcherActiveUntil = make(map[string]time.Time)
	}
	s.mailWatcherActiveUntil[mailboxID] = time.Now().Add(ttl)
	s.mailWatcherMu.Unlock()
	s.pokeMailWatcher()
}

func (s *Server) pokeMailWatcher() {
	if s == nil || !s.mailWatcherEnabled || s.mailWatcherWake == nil {
		return
	}
	select {
	case s.mailWatcherWake <- struct{}{}:
	default:
	}
}

func (s *Server) activeMailWatcherMailboxIDs(now time.Time) map[string]struct{} {
	if now.IsZero() {
		now = time.Now()
	}
	s.mailWatcherMu.Lock()
	defer s.mailWatcherMu.Unlock()
	active := make(map[string]struct{})
	for id, until := range s.mailWatcherActiveUntil {
		if until.After(now) {
			active[id] = struct{}{}
			continue
		}
		delete(s.mailWatcherActiveUntil, id)
	}
	return active
}

func (s *Server) mailWatcherGroups() []mailboxWatcherOwnerGroup {
	state := s.store.Snapshot()
	activeIDs := s.activeMailWatcherMailboxIDs(time.Now())
	byOwner := make(map[string][]Mailbox)
	for _, mailbox := range state.Mailboxes {
		if !mailboxEligibleForMessageSync(mailbox) {
			continue
		}
		ownerID := strings.TrimSpace(mailbox.OwnerID)
		if s.ownerDeletionInProgress(ownerID) {
			continue
		}
		if _, ok := s.imapStateForMailbox(ownerID, mailbox); !ok {
			continue
		}
		byOwner[ownerID] = append(byOwner[ownerID], mailbox)
	}
	owners := make([]string, 0, len(byOwner))
	for ownerID := range byOwner {
		owners = append(owners, ownerID)
	}
	sort.Strings(owners)
	groups := make([]mailboxWatcherOwnerGroup, 0, len(owners))
	for _, ownerID := range owners {
		mailboxes := byOwner[ownerID]
		sort.Slice(mailboxes, func(i, j int) bool {
			_, iActive := activeIDs[mailboxes[i].ID]
			_, jActive := activeIDs[mailboxes[j].ID]
			if iActive != jActive {
				return iActive
			}
			return mailboxes[i].Email < mailboxes[j].Email
		})
		groups = append(groups, mailboxWatcherOwnerGroup{ownerID: ownerID, mailboxes: mailboxes})
	}
	return groups
}

func (s *Server) mailWatcherIMAPGroups() []mailboxWatcherIMAPGroup {
	state := s.store.Snapshot()
	type bucket struct {
		ownerID   string
		accountID string
		state     LoginState
		mailboxes []Mailbox
	}
	buckets := make(map[string]*bucket)
	for _, mailbox := range state.Mailboxes {
		if !mailboxEligibleForMessageSync(mailbox) {
			continue
		}
		ownerID := strings.TrimSpace(mailbox.OwnerID)
		if s.ownerDeletionInProgress(ownerID) {
			continue
		}
		session, imapState, ok := s.imapSessionForMailbox(ownerID, mailbox)
		if !ok {
			continue
		}
		accountID := strings.TrimSpace(session.AccountID)
		key := mailWatcherIMAPGroupKey(ownerID, accountID, imapState)
		item := buckets[key]
		if item == nil {
			item = &bucket{ownerID: ownerID, accountID: accountID, state: imapState}
			buckets[key] = item
		}
		item.mailboxes = append(item.mailboxes, mailbox)
	}
	keys := make([]string, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	groups := make([]mailboxWatcherIMAPGroup, 0, len(keys))
	for _, key := range keys {
		item := buckets[key]
		sort.Slice(item.mailboxes, func(i, j int) bool {
			return item.mailboxes[i].Email < item.mailboxes[j].Email
		})
		groups = append(groups, mailboxWatcherIMAPGroup{
			key:       key,
			ownerID:   item.ownerID,
			accountID: item.accountID,
			state:     item.state,
			mailboxes: item.mailboxes,
			signature: mailWatcherIMAPGroupSignature(item.state, item.mailboxes),
		})
	}
	return groups
}

func mailWatcherIMAPGroupKey(ownerID, accountID string, state LoginState) string {
	return strings.TrimSpace(ownerID) + "|" +
		firstNonEmpty(strings.TrimSpace(accountID), "__imap__") + "|" +
		imapStateKey(state) + "|" +
		imapStateSensitiveKey(state)
}

func mailWatcherIMAPGroupSignature(state LoginState, mailboxes []Mailbox) string {
	parts := []string{
		normalizeICloudIMAPEmail(state.IMAPEmail),
		strings.TrimSpace(state.IMAPUsername),
		state.IMAPHost,
		strconv.Itoa(state.IMAPPort),
		strings.TrimSpace(state.ProxyURL),
		imapStateSensitiveKey(state),
	}
	for _, mailbox := range mailboxes {
		parts = append(parts, strings.TrimSpace(mailbox.ID), normalizeICloudIMAPEmail(mailbox.Email))
	}
	return strings.Join(parts, "|")
}

func (s *Server) syncMailbox(ctx context.Context, mailbox Mailbox, after time.Time, keyword string) (int, error) {
	return s.syncMailboxCodeBatchForOwnerWithLimit(ctx, mailbox.OwnerID, []Mailbox{mailbox}, after, keyword, mailboxSyncThreadLimit(mailbox))
}

func (s *Server) syncMailboxCodeBatchForOwnerWithLimit(ctx context.Context, ownerID string, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (int, error) {
	if len(mailboxes) == 0 {
		return 0, nil
	}
	release, err := s.acquireMailboxSyncSlot(ctx, ownerID)
	if err != nil {
		return 0, err
	}
	defer release()
	if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
		return 0, err
	}

	refreshed := make([]Mailbox, 0, len(mailboxes))
	for _, mailbox := range mailboxes {
		latest, ok := s.store.FindMailboxByID(mailbox.ID)
		if !ok || !mailboxEligibleForMessageSync(latest) {
			continue
		}
		refreshed = append(refreshed, latest)
	}
	if len(refreshed) == 0 {
		return 0, nil
	}
	if err := s.waitMailboxSyncInterval(ctx, ownerID); err != nil {
		return 0, err
	}
	defer s.markMailboxSyncFinished(ownerID)

	syncFn := s.syncCodeMailboxBatchWithCursor
	if syncFn == nil && s.syncCodeMailboxBatch != nil {
		syncFn = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (iCloudIMAPSyncResult, error) {
			messagesByMailbox, err := s.syncCodeMailboxBatch(ctx, state, mailboxes, after, keyword, maxMessages)
			return iCloudIMAPSyncResult{
				MessagesByMailbox: messagesByMailbox,
				LastUID:           highestICloudMessageUID(messagesByMailbox),
			}, err
		}
	}
	if syncFn == nil {
		syncFn = SyncICloudIMAPMessagesWithCursor
	}
	type imapGroup struct {
		session   ICloudSession
		state     LoginState
		mailboxes []Mailbox
	}
	groups := make(map[string]*imapGroup)
	order := make([]string, 0)
	resolver := s.imapSessionResolverForOwner(ownerID)
	for _, mailbox := range refreshed {
		session, state, ok := resolver.sessionForMailbox(mailbox)
		if !ok {
			return 0, errCode("imap_session_missing", "未保存取码登录，请先保存 iCloud 邮箱账号和 App 专用密码", true)
		}
		key := mailboxAccountOperationKey(ownerID, mailbox.AccountID) + "|" +
			firstNonEmpty(strings.TrimSpace(session.AccountID), "__imap__") + "|" + imapStateKey(state)
		group := groups[key]
		if group == nil {
			group = &imapGroup{session: session, state: state}
			groups[key] = group
			order = append(order, key)
		}
		group.mailboxes = append(group.mailboxes, mailbox)
	}
	now := time.Now()
	synced := 0
	for _, key := range order {
		group := groups[key]
		accountID := strings.TrimSpace(group.mailboxes[0].AccountID)
		releaseAccountOperation, err := s.acquireMailboxAccountOperationSlot(
			ctx,
			mailboxAccountOperationKey(ownerID, accountID),
		)
		if err != nil {
			return synced, err
		}
		groupErr := func() error {
			defer releaseAccountOperation()
			if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
				return err
			}
			currentMailboxes := s.currentMessageSyncMailboxes(ownerID, accountID, group.mailboxes)
			if len(currentMailboxes) == 0 {
				return nil
			}
			group.mailboxes = currentMailboxes
			currentSession, currentState, ok := s.imapSessionForMailbox(ownerID, group.mailboxes[0])
			if !ok {
				return errCode("imap_session_missing", "未保存取码登录，请先保存 iCloud 邮箱账号和 App 专用密码", true)
			}
			group.session = currentSession
			group.state = currentState

			syncResult, err := syncFn(ctx, group.state, group.mailboxes, after, keyword, maxMessages)
			if err != nil {
				return err
			}
			messagesByMailbox := syncResult.MessagesByMailbox
			if messagesByMailbox == nil {
				messagesByMailbox = map[string][]ICloudSyncedMessage{}
			}
			lastAccountUID := firstNonEmpty(syncResult.LastUID, highestICloudMessageUID(messagesByMailbox))
			for _, mailbox := range group.mailboxes {
				lastSyncUID := mailbox.LastSyncUID
				latestMessageAt := mailbox.LastSyncAt
				mailboxChanged := false
				for _, msg := range messagesByMailbox[mailbox.ID] {
					if extractOTP(msg.Subject+"\n"+msg.Body) == "" {
						continue
					}
					remoteID := strings.TrimSpace(msg.RemoteID)
					if remoteID == "" && strings.TrimSpace(msg.UID) != "" {
						remoteID = "imap:" + strings.TrimSpace(msg.UID)
					}
					_, created, err := s.store.UpsertMessage(mailbox.ID, remoteID, "imap", msg.Subject, msg.From, msg.Body, msg.ReceivedAt)
					if err != nil {
						return err
					}
					if created {
						synced++
						mailboxChanged = true
					}
					candidateUID := firstNonEmpty(msg.UID, remoteID)
					if msg.ReceivedAt.After(latestMessageAt) {
						latestMessageAt = msg.ReceivedAt
						lastSyncUID = candidateUID
						mailboxChanged = true
					} else if strings.TrimSpace(lastSyncUID) == "" && strings.TrimSpace(candidateUID) != "" {
						lastSyncUID = candidateUID
						mailboxChanged = true
					}
				}
				if mailboxChanged {
					syncedAt := latestMessageAt
					if syncedAt.IsZero() {
						syncedAt = now
					}
					if _, err := s.store.SetMailboxSyncCursor(mailbox.ID, syncedAt, lastSyncUID); err != nil {
						return err
					}
				}
			}
			_, err = s.store.SetICloudIMAPSyncCursor(ownerID, group.session.AccountID, imapStateKey(group.state), now, lastAccountUID)
			return err
		}()
		if groupErr != nil {
			return synced, groupErr
		}
	}
	return synced, nil
}

func (s *Server) syncMailboxBatchForOwner(ctx context.Context, ownerID string, mailboxes []Mailbox, after time.Time, keyword string) error {
	return s.syncMailboxBatchForOwnerWithLimit(ctx, ownerID, mailboxes, after, keyword, 0)
}

func (s *Server) syncMailboxBatchForOwnerWithLimit(ctx context.Context, ownerID string, mailboxes []Mailbox, after time.Time, keyword string, maxThreadsOverride int) error {
	if len(mailboxes) == 0 {
		return nil
	}
	release, err := s.acquireMailboxSyncSlot(ctx, ownerID)
	if err != nil {
		return err
	}
	defer release()
	if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
		return err
	}

	refreshed := make([]Mailbox, 0, len(mailboxes))
	for _, mailbox := range mailboxes {
		latest, ok := s.store.FindMailboxByID(mailbox.ID)
		if !ok || !mailboxEligibleForMessageSync(latest) {
			continue
		}
		refreshed = append(refreshed, latest)
	}
	if len(refreshed) == 0 {
		return nil
	}
	if err := s.waitMailboxSyncInterval(ctx, ownerID); err != nil {
		return err
	}
	defer s.markMailboxSyncFinished(ownerID)
	syncFn := s.syncMailboxBatch
	if syncFn == nil {
		syncFn = func(ctx context.Context, session ICloudSession, mailboxes []Mailbox, after time.Time, keyword string, maxThreads int) (map[string][]ICloudSyncedMessage, error) {
			return NewICloudClient().SyncMailboxMessagesBatch(ctx, session, mailboxes, after, keyword, maxThreads)
		}
	}
	type sessionGroup struct {
		session   ICloudSession
		mailboxes []Mailbox
	}
	groups := make(map[string]*sessionGroup)
	order := make([]string, 0)
	for _, mailbox := range refreshed {
		session, ok := s.sessionForMailbox(ownerID, mailbox.AccountID)
		if !ok {
			return errCode("icloud_session_missing", "未保存 iCloud 登录态，请先保存旧接口登录态", true)
		}
		key := mailboxAccountOperationKey(ownerID, mailbox.AccountID) + "|" +
			firstNonEmpty(session.AccountID, session.DSID, session.AppleID, "__legacy__")
		group := groups[key]
		if group == nil {
			group = &sessionGroup{session: session}
			groups[key] = group
			order = append(order, key)
		}
		group.mailboxes = append(group.mailboxes, mailbox)
	}
	now := time.Now()
	for _, key := range order {
		group := groups[key]
		maxThreads := mailboxBatchThreadLimit(group.mailboxes)
		if maxThreadsOverride > 0 {
			maxThreads = maxThreadsOverride
		}
		accountID := strings.TrimSpace(group.mailboxes[0].AccountID)
		releaseAccountOperation, err := s.acquireMailboxAccountOperationSlot(
			ctx,
			mailboxAccountOperationKey(ownerID, accountID),
		)
		if err != nil {
			return err
		}
		groupErr := func() error {
			defer releaseAccountOperation()
			if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
				return err
			}
			currentMailboxes := s.currentMessageSyncMailboxes(ownerID, accountID, group.mailboxes)
			if len(currentMailboxes) == 0 {
				return nil
			}
			group.mailboxes = currentMailboxes
			currentSession, ok := s.sessionForMailbox(ownerID, group.mailboxes[0].AccountID)
			if !ok || !iCloudWebLoginSaved(currentSession) {
				return errCode("icloud_session_missing", "未保存 iCloud 登录态，请先保存旧接口登录态", true)
			}
			group.session = currentSession

			messagesByMailbox, err := syncFn(ctx, group.session, group.mailboxes, after, keyword, maxThreads)
			if err != nil {
				return err
			}
			for _, mailbox := range group.mailboxes {
				lastSyncUID := mailbox.LastSyncUID
				latestMessageAt := mailbox.LastSyncAt
				for _, msg := range messagesByMailbox[mailbox.ID] {
					if extractOTP(msg.Subject+"\n"+msg.Body) == "" {
						continue
					}
					_, _, err := s.store.UpsertMessage(mailbox.ID, msg.RemoteID, "icloud", msg.Subject, msg.From, msg.Body, msg.ReceivedAt)
					if err != nil {
						return err
					}
					if msg.ReceivedAt.After(latestMessageAt) {
						latestMessageAt = msg.ReceivedAt
						lastSyncUID = firstNonEmpty(msg.UID, msg.RemoteID)
					}
				}
				if _, err := s.store.SetMailboxSyncCursor(mailbox.ID, now, lastSyncUID); err != nil {
					return err
				}
			}
			return nil
		}()
		if groupErr != nil {
			return groupErr
		}
	}
	return nil
}

func (s *Server) currentMessageSyncMailboxes(ownerID, accountID string, candidates []Mailbox) []Mailbox {
	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	out := make([]Mailbox, 0, len(candidates))
	for _, candidate := range candidates {
		latest, ok := s.store.FindMailboxByID(candidate.ID)
		if !ok ||
			strings.TrimSpace(latest.OwnerID) != ownerID ||
			strings.TrimSpace(latest.AccountID) != accountID ||
			!mailboxEligibleForMessageSync(latest) {
			continue
		}
		out = append(out, latest)
	}
	return out
}

func mailboxEligibleForMessageSync(mailbox Mailbox) bool {
	if !mailbox.APIActive || !mailbox.ICloudActive || mailbox.Status == StatusDisabled {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(mailbox.RemoteDeleteStatus)) {
	case "pending", "unknown", "failed", "succeeded":
		return false
	default:
		return true
	}
}

func highestICloudMessageUID(messagesByMailbox map[string][]ICloudSyncedMessage) string {
	highest := 0
	for _, messages := range messagesByMailbox {
		for _, msg := range messages {
			uid := imapUIDNumber(firstNonEmpty(msg.UID, msg.RemoteID))
			if uid > highest {
				highest = uid
			}
		}
	}
	if highest <= 0 {
		return ""
	}
	return strconv.Itoa(highest)
}

func icloudRemoteIDsFromMessages(messages []Message) []string {
	ids := make([]string, 0, len(messages))
	for _, msg := range messages {
		if extractOTP(msg.Subject+"\n"+msg.Body) == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(msg.RemoteID), "icloud:") {
			ids = append(ids, msg.RemoteID)
		}
	}
	return uniqueStrings(ids)
}

func (s *Server) acquireMailboxSyncSlot(ctx context.Context, ownerID string) (func(), error) {
	key := mailboxSyncOwnerKey(ownerID)
	s.icloudMailSyncMu.Lock()
	if s.icloudMailSyncGates == nil {
		s.icloudMailSyncGates = make(map[string]chan struct{})
	}
	gate := s.icloudMailSyncGates[key]
	if gate == nil {
		gate = make(chan struct{}, 1)
		s.icloudMailSyncGates[key] = gate
	}
	s.icloudMailSyncMu.Unlock()

	select {
	case gate <- struct{}{}:
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Server) waitMailboxSyncInterval(ctx context.Context, ownerID string) error {
	interval := s.mailboxSyncMinInterval
	if interval <= 0 {
		return nil
	}
	key := mailboxSyncOwnerKey(ownerID)
	s.icloudMailSyncMu.Lock()
	last := s.icloudMailSyncLast[key]
	s.icloudMailSyncMu.Unlock()
	if last.IsZero() {
		return nil
	}
	wait := interval - time.Since(last)
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) markMailboxSyncFinished(ownerID string) {
	key := mailboxSyncOwnerKey(ownerID)
	s.icloudMailSyncMu.Lock()
	if s.icloudMailSyncLast == nil {
		s.icloudMailSyncLast = make(map[string]time.Time)
	}
	s.icloudMailSyncLast[key] = time.Now()
	s.icloudMailSyncMu.Unlock()
}

func mailboxSyncOwnerKey(ownerID string) string {
	key := strings.TrimSpace(ownerID)
	if key == "" {
		return "__legacy__"
	}
	return key
}

func mailboxSyncThreadLimit(mailbox Mailbox) int {
	if mailbox.LastSyncAt.IsZero() {
		return 20
	}
	return 10
}

func mailboxBatchThreadLimit(mailboxes []Mailbox) int {
	limit := 20
	for _, mailbox := range mailboxes {
		if mailbox.LastSyncAt.IsZero() {
			limit = 50
			break
		}
	}
	if len(mailboxes) >= 5 && limit < 50 {
		limit = 50
	}
	return limit
}

func (s *Server) createICloudMailboxForOwner(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
	if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
		return Mailbox{}, ICloudRemoteMailbox{}, err
	}
	session, ok := s.sessionForOwnerAccount(ownerID, accountID)
	if !ok {
		return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先保存登录态", true)
	}
	accountID = firstNonEmpty(strings.TrimSpace(accountID), session.AccountID)
	ownerID = s.dataOwnerIDForSession(ownerID, session)
	releaseAccountOperation, err := s.acquireMailboxAccountOperationSlot(ctx, mailboxAccountOperationKey(ownerID, accountID))
	if err != nil {
		return Mailbox{}, ICloudRemoteMailbox{}, err
	}
	defer releaseAccountOperation()
	if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
		return Mailbox{}, ICloudRemoteMailbox{}, err
	}
	currentSession, ok := s.sessionForOwnerAccount(ownerID, accountID)
	if !ok {
		return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_session_missing", "该账号的 iCloud 登录态已不存在，请重新保存登录态", true)
	}
	session = currentSession
	accountID = firstNonEmpty(strings.TrimSpace(accountID), session.AccountID)
	ownerID = s.dataOwnerIDForSession(ownerID, session)
	if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
		return Mailbox{}, ICloudRemoteMailbox{}, err
	}
	if message, blocked := s.store.AccountMailboxCreateReconciliationForOwner(ownerID, accountID); blocked {
		return Mailbox{}, ICloudRemoteMailbox{}, errCode("mailbox_create_reconciliation_required", message+"；请先同步 iCloud 远端邮箱列表确认后再重试", true)
	}
	createChannel := mailboxCreateChannelFromContext(ctx)
	if createChannel == mailboxCreateChannelAuto {
		if _, ok := appleAccountLoginState(session); ok {
			createChannel = mailboxCreateChannelAppleAccount
		} else {
			createChannel = mailboxCreateChannelICloudWeb
		}
	}
	remote, err := s.createICloudMailboxRemoteWithChannel(ctx, ownerID, session, label, note, createChannel)
	if err != nil {
		if strings.TrimSpace(remote.AnonymousID) == "" {
			return Mailbox{}, remote, s.recordMailboxCreateReconciliationRequired(ownerID, accountID, createChannel, err)
		}
		if cleanupErr := s.cleanupCreatedRemoteMailbox(ctx, ownerID, accountID, remote); cleanupErr != nil {
			if s.logger != nil {
				s.logger.Warn("remote mailbox create failed and rollback failed", "account_id", accountID, "create_err", err, "cleanup_err", cleanupErr)
			}
			return Mailbox{}, remote, s.recordMailboxCreateReconciliationRequired(ownerID, accountID, createChannel, errCode(
				"mailbox_create_remote_cleanup_failed",
				"远端邮箱创建链路失败："+publicErrorMessage(err)+"；远端回滚也失败："+publicErrorMessage(cleanupErr),
				true,
			))
		}
		return Mailbox{}, remote, err
	}
	if strings.TrimSpace(remote.AnonymousID) == "" {
		return Mailbox{}, remote, s.recordMailboxCreateReconciliationRequired(ownerID, accountID, createChannel, errCode(
			"icloud_mailbox_anonymous_id_missing",
			"Provider 创建成功但未返回远端匿名 ID，未写入本地邮箱记录",
			true,
		))
	}
	storeNote := strings.TrimSpace(remote.Note)
	if storeNote == "" {
		storeNote = "created by iCloud protocol"
	}
	mailbox, err := s.store.AddMailboxForOwnerWithRemote(ownerID, accountID, remote, storeNote)
	if err != nil {
		if cleanupErr := s.cleanupCreatedRemoteMailbox(ctx, ownerID, accountID, remote); cleanupErr != nil {
			if s.logger != nil {
				s.logger.Warn("local mailbox save failed and remote rollback failed", "account_id", accountID, "err", err, "cleanup_err", cleanupErr)
			}
			return Mailbox{}, remote, s.recordMailboxCreateReconciliationRequired(ownerID, accountID, createChannel, errCode(
				"mailbox_create_persist_and_cleanup_failed",
				"本地邮箱记录保存失败："+publicErrorMessage(err)+"；远端回滚也失败："+publicErrorMessage(cleanupErr),
				true,
			))
		}
		return Mailbox{}, remote, err
	}
	return mailbox, remote, nil
}

func mailboxCreateRequiresReconciliation(err error) bool {
	var coded codedError
	if !errors.As(err, &coded) {
		return false
	}
	switch strings.TrimSpace(coded.code) {
	case "apple_account_create_uncertain",
		"icloud_create_uncertain",
		"apple_account_create_empty",
		"mailbox_create_reconciliation_required",
		"mailbox_create_reconciliation_state_persist_failed",
		"mailbox_create_remote_cleanup_failed",
		"mailbox_create_persist_and_cleanup_failed",
		"icloud_mailbox_anonymous_id_missing":
		return true
	default:
		return false
	}
}

func mailboxCreateChannelRemoteOrigin(channel mailboxCreateChannel) string {
	switch normalizeMailboxCreateChannel(channel) {
	case mailboxCreateChannelAppleAccount:
		return mailboxRemoteOriginAppleAccount
	case mailboxCreateChannelICloudWeb:
		return mailboxRemoteOriginICloudWeb
	default:
		return ""
	}
}

func (s *Server) recordMailboxCreateReconciliationRequired(ownerID, accountID string, channel mailboxCreateChannel, err error) error {
	if !mailboxCreateRequiresReconciliation(err) {
		return err
	}
	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return errCode(
			"mailbox_create_reconciliation_required",
			publicErrorMessage(err)+"；无法关联本地 Apple 账号，请先同步 iCloud 远端邮箱列表确认结果后再重试",
			true,
		)
	}
	origin := mailboxCreateChannelRemoteOrigin(channel)
	if markErr := s.store.MarkAccountMailboxCreateReconciliationRequiredForOrigin(ownerID, accountID, origin, publicErrorMessage(err), time.Now()); markErr != nil {
		if s.logger != nil {
			s.logger.Error("persist mailbox create reconciliation state failed", "account_id", accountID, "create_err", err, "persist_err", markErr)
		}
		return errCode(
			"mailbox_create_reconciliation_state_persist_failed",
			publicErrorMessage(err)+"；远端结果待核对状态写入失败："+markErr.Error(),
			true,
		)
	}
	return err
}

func (s *Server) cleanupCreatedRemoteMailbox(ctx context.Context, ownerID, accountID string, remote ICloudRemoteMailbox) error {
	remoteID := strings.TrimSpace(remote.AnonymousID)
	if remoteID == "" {
		return errCode("icloud_mailbox_anonymous_id_missing", "远端已创建邮箱但未返回匿名 ID，无法执行回滚删除", true)
	}
	deleteRemote := s.deleteRemoteMailbox
	if deleteRemote == nil {
		deleteRemote = s.deleteICloudMailboxRemote
	}
	cleanupBase := context.Background()
	if ctx != nil {
		cleanupBase = context.WithoutCancel(ctx)
	}
	cleanupCtx, cancel := context.WithTimeout(cleanupBase, mailboxRemoteCleanupTimeout)
	defer cancel()
	err := deleteRemote(cleanupCtx, Mailbox{
		OwnerID:           strings.TrimSpace(ownerID),
		AccountID:         strings.TrimSpace(accountID),
		RemoteAnonymousID: remoteID,
		RemoteOrigin:      strings.TrimSpace(remote.Origin),
		Email:             strings.TrimSpace(remote.Email),
	})
	var completedWarning remoteDeleteCompletedWarning
	if errors.As(err, &completedWarning) {
		if s.logger != nil {
			s.logger.Warn("created remote mailbox cleanup completed with session persistence warning", "remote_id", remoteID, "err", completedWarning)
		}
		return nil
	}
	return err
}

func (s *Server) createMailboxesForOwner(ctx context.Context, ownerID string, accountIDs []string, label, note string) ([]Mailbox, []ICloudRemoteMailbox, []createMailboxFailure, error) {
	accountIDs = normalizeAccountIDSelection("", accountIDs)
	requests := make([]mailboxCreateRequest, 0, len(accountIDs))
	for _, accountID := range accountIDs {
		requests = append(requests, mailboxCreateRequest{AccountID: accountID})
	}
	return s.createMailboxesForOwnerWithChannels(ctx, ownerID, requests, label, note)
}

func (s *Server) createMailboxesForOwnerWithChannels(ctx context.Context, ownerID string, requests []mailboxCreateRequest, label, note string) ([]Mailbox, []ICloudRemoteMailbox, []createMailboxFailure, error) {
	accountIDs, channels := normalizeMailboxCreateRequests(requests)
	sessions := s.sessionsForOwnerAccounts(ownerID, accountIDs)
	if len(sessions) == 0 {
		if len(accountIDs) > 0 {
			failures := make([]createMailboxFailure, 0, len(accountIDs))
			var firstErr error
			for _, accountID := range accountIDs {
				err := errCode("icloud_session_missing", "未找到可用于创建的 iCloud 登录态，请先保存该账号登录态", true)
				if firstErr == nil {
					firstErr = err
				}
				appleID := ""
				if account, ok := s.store.FindAccountByID(accountID); ok {
					appleID = strings.TrimSpace(account.AppleID)
				}
				failures = append(failures, createMailboxFailure{
					AccountID: accountID,
					AppleID:   appleID,
					Channel:   string(channels[accountID]),
					Code:      "icloud_session_missing",
					Error:     publicErrorMessage(err),
				})
			}
			return nil, nil, failures, firstErr
		}
		return nil, nil, nil, errCode("icloud_session_missing", "未找到可用于创建的 iCloud 登录态，请检查参与账号 ID 或先保存登录态", true)
	}
	mailboxes := make([]Mailbox, 0, len(sessions))
	remotes := make([]ICloudRemoteMailbox, 0, len(sessions))
	failures := make([]createMailboxFailure, 0)
	if len(accountIDs) > 0 {
		sessionsByAccountID := make(map[string]ICloudSession, len(sessions))
		for _, session := range sessions {
			if accountID := strings.TrimSpace(session.AccountID); accountID != "" {
				sessionsByAccountID[accountID] = session
			}
		}
		for _, accountID := range accountIDs {
			if _, ok := sessionsByAccountID[accountID]; ok {
				continue
			}
			err := errCode("icloud_session_missing", "未找到可用于创建的 iCloud 登录态，请先保存该账号登录态", true)
			appleID := ""
			if account, ok := s.store.FindAccountByID(accountID); ok {
				appleID = strings.TrimSpace(account.AppleID)
			}
			failures = append(failures, createMailboxFailure{
				AccountID: accountID,
				AppleID:   appleID,
				Channel:   string(channels[accountID]),
				Code:      "icloud_session_missing",
				Error:     publicErrorMessage(err),
			})
		}
	}
	var firstErr error
	type createResult struct {
		session   ICloudSession
		mailbox   Mailbox
		remote    ICloudRemoteMailbox
		err       error
		accountID string
		channel   mailboxCreateChannel
	}
	results := make([]createResult, len(sessions))
	var wg sync.WaitGroup
	for index, session := range sessions {
		index, session := index, session
		wg.Add(1)
		go func() {
			defer wg.Done()
			effectiveAccountID := session.AccountID
			channel := channels[strings.TrimSpace(effectiveAccountID)]
			createCtx := contextWithMailboxCreateChannel(ctx, channel)
			effectiveOwnerID := s.dataOwnerIDForSession(ownerID, session)
			if message, blocked := s.store.AccountMailboxCreateReconciliationForOwner(effectiveOwnerID, effectiveAccountID); blocked {
				results[index] = createResult{
					session:   session,
					err:       errCode("mailbox_create_reconciliation_required", message+"；请先同步 iCloud 远端邮箱列表确认后再重试", true),
					accountID: effectiveAccountID,
					channel:   channel,
				}
				return
			}
			mailbox, remote, err := s.createMailboxForOwner(createCtx, effectiveOwnerID, effectiveAccountID, label, note)
			effectiveChannel := channel
			if effectiveChannel == mailboxCreateChannelAuto {
				if _, ok := appleAccountLoginState(session); ok {
					effectiveChannel = mailboxCreateChannelAppleAccount
				} else {
					effectiveChannel = mailboxCreateChannelICloudWeb
				}
			}
			err = s.recordMailboxCreateReconciliationRequired(effectiveOwnerID, effectiveAccountID, effectiveChannel, err)
			results[index] = createResult{
				session:   session,
				mailbox:   mailbox,
				remote:    remote,
				err:       err,
				accountID: effectiveAccountID,
				channel:   channel,
			}
		}()
	}
	wg.Wait()
	for _, result := range results {
		if result.err != nil {
			if firstErr == nil {
				firstErr = result.err
			}
			var coded codedError
			if !errors.As(result.err, &coded) {
				coded = codedError{}
			}
			failures = append(failures, createMailboxFailure{
				AccountID: result.accountID,
				AppleID:   strings.TrimSpace(result.session.AppleID),
				Channel:   string(result.channel),
				Code:      strings.TrimSpace(coded.code),
				Error:     publicErrorMessage(result.err),
			})
			continue
		}
		mailboxes = append(mailboxes, result.mailbox)
		remotes = append(remotes, result.remote)
	}
	if len(mailboxes) == 0 && firstErr != nil {
		return mailboxes, remotes, failures, firstErr
	}
	return mailboxes, remotes, failures, nil
}

func (s *Server) createICloudMailboxRemote(ctx context.Context, ownerID string, session ICloudSession, label, note string) (ICloudRemoteMailbox, error) {
	return s.createICloudMailboxRemoteWithChannel(ctx, ownerID, session, label, note, mailboxCreateChannelAuto)
}

func (s *Server) createICloudMailboxRemoteWithChannel(ctx context.Context, ownerID string, session ICloudSession, label, note string, channel mailboxCreateChannel) (ICloudRemoteMailbox, error) {
	if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
		return ICloudRemoteMailbox{}, err
	}
	key := mailboxCreateAccountKey(ownerID, session)

	release, err := s.acquireMailboxCreateGate(ctx, key)
	if err != nil {
		return ICloudRemoteMailbox{}, err
	}
	defer release()
	if err := s.waitMailboxCreateInterval(ctx, key); err != nil {
		return ICloudRemoteMailbox{}, err
	}
	if err := s.ensureOwnerNotDeleting(ownerID); err != nil {
		return ICloudRemoteMailbox{}, err
	}

	switch normalizeMailboxCreateChannel(channel) {
	case mailboxCreateChannelAppleAccount:
		return s.createICloudMailboxRemoteAppleAccount(ctx, ownerID, session, label, note, key)
	case mailboxCreateChannelICloudWeb:
		return s.createICloudMailboxRemoteICloudWeb(ctx, session, label, note, key)
	}

	if _, ok := appleAccountLoginState(session); ok {
		remote, err := s.createICloudMailboxRemoteAppleAccount(ctx, ownerID, session, label, note, key)
		if err == nil {
			return remote, nil
		}
		if strings.TrimSpace(remote.AnonymousID) != "" {
			return remote, err
		}
		// An Apple Account create request may have reached the remote service
		// even when the response is lost or malformed. Never switch providers
		// automatically in that state: doing so can create a second remote
		// mailbox for one user action. The caller can explicitly choose the
		// iCloud Web channel after reconciling the remote state.
		return ICloudRemoteMailbox{}, err
	}
	remote, err := s.createICloudMailboxRemoteICloudWeb(ctx, session, label, note, key)
	return remote, err
}

func mailboxCreateAccountKey(ownerID string, session ICloudSession) string {
	key := strings.TrimSpace(ownerID)
	if key == "" {
		key = "global"
	}
	key += ":" + firstNonEmpty(session.AccountID, session.DSID, session.AppleID, "default")
	return key
}

func mailboxCreateChannelCooldownKey(accountKey string, channel mailboxCreateChannel) string {
	key := strings.TrimSpace(accountKey)
	if key == "" {
		key = "global:default"
	}
	channel = normalizeMailboxCreateChannel(channel)
	if channel == mailboxCreateChannelAuto {
		channel = mailboxCreateChannelICloudWeb
	}
	return key + ":cooldown:" + string(channel)
}

func (s *Server) createICloudMailboxRemoteAppleAccount(ctx context.Context, ownerID string, session ICloudSession, label, note, key string) (ICloudRemoteMailbox, error) {
	if _, ok := appleAccountLoginState(session); !ok {
		return ICloudRemoteMailbox{}, errCode("apple_account_session_missing", "未保存新接口登录态，请先完成新接口登录", true)
	}
	cooldownKey := mailboxCreateChannelCooldownKey(key, mailboxCreateChannelAppleAccount)
	opCtx, cancel := context.WithTimeout(ctx, appleAccountManageOperationTimeout)
	defer cancel()
	remote, updatedSession, err := newICloudKeepAliveClient().CreatePrivacyMailboxWithAppleAccount(opCtx, session, s.cfg.AppleAccountAPIKey, label, note)
	s.markMailboxCreateFinished(key)
	if isCodedError(err, "apple_account_hme_limit") {
		s.markMailboxCreateCooldown(cooldownKey, mailboxCreateLimitCooldown)
	}
	if _, ok := appleAccountLoginState(updatedSession); ok {
		if saveErr := s.store.SaveICloudSessionForOwner(s.dataOwnerIDForSession(ownerID, session), updatedSession); saveErr != nil {
			if err == nil {
				return remote, errCode(
					"icloud_session_persist_after_mailbox_create",
					"远端隐私邮箱已创建，但刷新后的 Apple Account 登录态写入失败，请稍后检查账号状态",
					true,
				)
			}
			s.logger.Warn("failed to save updated Apple Account login state after failed mailbox create", "account_id", session.AccountID, "err", saveErr)
		}
	}
	return remote, err
}

func (s *Server) createICloudMailboxRemoteICloudWeb(ctx context.Context, session ICloudSession, label, note, key string) (ICloudRemoteMailbox, error) {
	if !iCloudWebLoginSaved(session) {
		return ICloudRemoteMailbox{}, errCode("icloud_session_missing", "未保存旧接口登录态，请先完成旧接口登录", true)
	}
	cooldownKey := mailboxCreateChannelCooldownKey(key, mailboxCreateChannelICloudWeb)
	if cooldownRemaining := s.mailboxCreateCooldownRemaining(cooldownKey); cooldownRemaining > 0 {
		remaining := int(cooldownRemaining.Round(time.Second).Seconds())
		if remaining < 1 {
			remaining = 1
		}
		return ICloudRemoteMailbox{}, errCode("icloud_hme_limit", fmt.Sprintf("iCloud 创建上限冷却中，请约 %d 秒后再试", remaining), true)
	}

	remote, err := NewICloudClient().CreatePrivacyMailbox(ctx, session, label, note)
	s.markMailboxCreateFinished(key)
	var coded codedError
	if errors.As(err, &coded) && coded.code == "icloud_hme_limit" {
		s.markMailboxCreateCooldown(cooldownKey, mailboxCreateLimitCooldown)
	}
	return remote, err
}

func normalizeMailboxCreateRequests(requests []mailboxCreateRequest) ([]string, map[string]mailboxCreateChannel) {
	accountIDs := make([]string, 0, len(requests))
	channels := make(map[string]mailboxCreateChannel, len(requests))
	for _, request := range requests {
		for _, accountID := range splitAccountIDTokens(request.AccountID) {
			if accountID == "" {
				continue
			}
			if _, ok := channels[accountID]; ok {
				continue
			}
			channels[accountID] = normalizeMailboxCreateChannel(request.Channel)
			accountIDs = append(accountIDs, accountID)
		}
	}
	return accountIDs, channels
}

func (s *Server) acquireMailboxCreateGate(ctx context.Context, key string) (func(), error) {
	s.icloudCreateMu.Lock()
	gate := s.icloudCreateGates[key]
	if gate == nil {
		gate = make(chan struct{}, 1)
		s.icloudCreateGates[key] = gate
	}
	s.icloudCreateMu.Unlock()

	select {
	case gate <- struct{}{}:
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Server) waitMailboxCreateInterval(ctx context.Context, key string) error {
	interval := mailboxCreateMinInterval
	if interval <= 0 {
		return nil
	}
	s.icloudCreateMu.Lock()
	last := s.icloudCreateLast[key]
	s.icloudCreateMu.Unlock()
	if last.IsZero() {
		return nil
	}
	wait := interval - time.Since(last)
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) markMailboxCreateFinished(key string) {
	s.icloudCreateMu.Lock()
	if s.icloudCreateLast == nil {
		s.icloudCreateLast = make(map[string]time.Time)
	}
	s.icloudCreateLast[key] = time.Now()
	s.icloudCreateMu.Unlock()
}

func (s *Server) mailboxCreateCooldownRemaining(key string) time.Duration {
	now := time.Now()
	s.icloudCreateMu.Lock()
	defer s.icloudCreateMu.Unlock()
	cooldownUntil := s.icloudCreateCooldown[key]
	if cooldownUntil.IsZero() {
		return 0
	}
	if !cooldownUntil.After(now) {
		delete(s.icloudCreateCooldown, key)
		return 0
	}
	return cooldownUntil.Sub(now)
}

func (s *Server) markMailboxCreateCooldown(key string, duration time.Duration) {
	if duration <= 0 {
		return
	}
	s.icloudCreateMu.Lock()
	if s.icloudCreateCooldown == nil {
		s.icloudCreateCooldown = make(map[string]time.Time)
	}
	s.icloudCreateCooldown[key] = time.Now().Add(duration)
	s.icloudCreateMu.Unlock()
}

func (s *Server) logICloudCreateError(ownerID string, err error) {
	var coded codedError
	if errors.As(err, &coded) {
		s.logger.Warn("iCloud mailbox create failed", "owner", s.ownerName(ownerID), "code", coded.code, "retryable", coded.retryable)
		return
	}
	s.logger.Warn("iCloud mailbox create failed", "owner", s.ownerName(ownerID), "err", err)
}

func (s *Server) authorized(r *http.Request, mailbox Mailbox) bool {
	queryKey := strings.TrimSpace(r.URL.Query().Get("key"))
	if constantTimeEqual(queryKey, mailbox.APIToken) {
		return true
	}
	candidates := []string{
		strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
		r.Header.Get("X-API-Key"),
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if constantTimeEqual(candidate, mailbox.APIToken) {
			return true
		}
		if strings.TrimSpace(s.cfg.APIKey) != "" && constantTimeEqual(candidate, s.cfg.APIKey) {
			return true
		}
	}
	return false
}

func (s *Server) authorizedGlobalAPI(r *http.Request) bool {
	want := strings.TrimSpace(s.cfg.APIKey)
	if want == "" {
		return false
	}
	candidates := []string{
		strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
		r.Header.Get("X-API-Key"),
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if constantTimeEqual(candidate, want) {
			return true
		}
	}
	return false
}

func scopedOwnerID(r *http.Request, store *FileStore) string {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		session, user, ok := store.WebSessionByToken(cookie.Value)
		if ok && !session.IsAdmin && user.ID != "" {
			return user.ID
		}
	}
	return ""
}

func requestOwnerID(r *http.Request, store *FileStore) string {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		_, user, ok := store.WebSessionByToken(cookie.Value)
		if ok && user.ID != "" {
			return user.ID
		}
	}
	return ""
}

type loginTarget struct {
	OwnerID   string
	AccountID string
}

func loginAccountOperationKey(target loginTarget, appleID string) string {
	accountID := strings.TrimSpace(target.AccountID)
	if accountID == "" {
		accountID = "__login__" + strings.ToLower(strings.TrimSpace(appleID))
	}
	return mailboxAccountOperationKey(target.OwnerID, accountID)
}

func pendingLoginOperationKey(pending appleAuthPending, store *FileStore) string {
	ownerID := pendingLoginTargetOwnerID(pending, store)
	appleID := ""
	if pending.Session != nil {
		appleID = pending.Session.AppleID
	}
	return loginAccountOperationKey(loginTarget{
		OwnerID:   ownerID,
		AccountID: pending.AccountID,
	}, appleID)
}

func (s *Server) resolveLoginTarget(r *http.Request, appleID, requestedAccountID string) (loginTarget, error) {
	appleID = strings.ToLower(strings.TrimSpace(appleID))
	requesterID := requestOwnerID(r, s.store)
	requestedAccountID = strings.TrimSpace(requestedAccountID)
	if requestedAccountID != "" {
		account, ok := s.store.FindAccountByID(requestedAccountID)
		if !ok {
			return loginTarget{}, errCode("account_not_found", "指定的 Apple 账号不存在", false)
		}
		if !s.isAdminRequest(r) && !constantTimeEqual(requesterID, account.OwnerID) {
			return loginTarget{}, errCode("account_forbidden", "无权为该 Apple 账号登录", false)
		}
		if !s.accountInRequestScope(r, requestedAccountID) {
			return loginTarget{}, errCode("account_not_found", "指定的 Apple 账号不存在", false)
		}
		if configuredAppleID := strings.ToLower(strings.TrimSpace(account.AppleID)); configuredAppleID != "" && configuredAppleID != appleID {
			return loginTarget{}, errCode("apple_id_account_mismatch", "输入的 Apple ID 与指定账号不一致", false)
		}
		return loginTarget{
			OwnerID:   strings.TrimSpace(account.OwnerID),
			AccountID: account.ID,
		}, nil
	}

	state := s.store.Snapshot()
	candidates := make([]Account, 0, 1)
	for _, account := range state.Accounts {
		if strings.ToLower(strings.TrimSpace(account.AppleID)) != appleID {
			continue
		}
		if !s.accountInRequestScope(r, account.ID) {
			continue
		}
		candidates = append(candidates, account)
	}
	if len(candidates) > 1 {
		return loginTarget{}, errCode("account_ambiguous", "该 Apple ID 对应多个账号，请明确指定 account_id", false)
	}
	if len(candidates) == 1 {
		return loginTarget{
			OwnerID:   strings.TrimSpace(candidates[0].OwnerID),
			AccountID: candidates[0].ID,
		}, nil
	}
	if appleID != "" {
		for _, account := range state.Accounts {
			if strings.ToLower(strings.TrimSpace(account.AppleID)) != appleID {
				continue
			}
			if s.isAdminRequest(r) {
				return loginTarget{}, errCode("apple_id_exists_other_owner", "该 Apple ID 已存在于其他归属，请到管理页选择对应用户或全局范围后再登录", false)
			}
			return loginTarget{}, errCode("apple_id_exists_other_owner", "该 Apple ID 已归属其他账号，无法在当前账号下登录", false)
		}
	}
	return loginTarget{OwnerID: requesterID}, nil
}

func (s *Server) validatePendingLoginAccount(pending appleAuthPending) error {
	accountID := strings.TrimSpace(pending.AccountID)
	if accountID == "" {
		return nil
	}
	account, ok := s.store.FindAccountByID(accountID)
	if !ok {
		return errCode("account_not_found", "登录目标 Apple 账号已不存在，请重新发起登录", false)
	}
	if pending.TargetOwnerSet || strings.TrimSpace(pending.TargetOwnerID) != "" {
		expectedOwnerID := strings.TrimSpace(pending.TargetOwnerID)
		if expectedOwnerID != strings.TrimSpace(account.OwnerID) {
			return errCode("account_forbidden", "登录目标 Apple 账号已变更归属，请重新发起登录", false)
		}
	}
	ownerID := pendingLoginTargetOwnerID(pending, s.store)
	if !pending.TargetOwnerSet && strings.TrimSpace(pending.TargetOwnerID) == "" &&
		ownerID != "" && !constantTimeEqual(ownerID, account.OwnerID) {
		return errCode("account_forbidden", "登录目标 Apple 账号已变更归属，请重新发起登录", false)
	}
	return nil
}

func loginTargetHTTPStatus(err error) int {
	switch {
	case isCodedError(err, "account_forbidden"):
		return http.StatusForbidden
	case isCodedError(err, "account_not_found"):
		return http.StatusNotFound
	case isCodedError(err, "apple_id_exists_other_owner"):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}

func appleIDConflictHTTPStatus(err error) int {
	if isCodedError(err, "apple_id_exists_other_owner") || isCodedError(err, "apple_id_exists") {
		return http.StatusConflict
	}
	return http.StatusBadRequest
}

func (s *Server) loginProxySelectionForTarget(r *http.Request, appleID, requested string, target loginTarget) (string, bool) {
	if strings.TrimSpace(requested) != "" {
		return requested, true
	}
	if accountID := strings.TrimSpace(target.AccountID); accountID != "" {
		if account, ok := s.store.FindAccountByID(accountID); ok {
			return strings.TrimSpace(account.ProxyURL), false
		}
	}
	return s.loginProxyForRequest(r, appleID, ""), false
}

func (s *Server) loginProxyForRequest(r *http.Request, appleID, requested string) string {
	if proxyURL := strings.TrimSpace(requested); proxyURL != "" {
		return proxyURL
	}
	ownerID := requestOwnerID(r, s.store)
	if proxyURL, ok := s.store.AccountProxyForOwnerAppleID(ownerID, appleID); ok {
		return proxyURL
	}
	if !s.isAdminRequest(r) {
		return ""
	}
	switch scope := s.adminOwnerScope(r); {
	case scope == "all":
		if proxyURL, ok := s.store.AccountProxyForAppleID(appleID); ok {
			return proxyURL
		}
	case scope == "__global":
		if proxyURL, ok := s.store.AccountProxyForOwnerAppleID("", appleID); ok {
			return proxyURL
		}
	case scope != "" && !constantTimeEqual(scope, ownerID):
		if proxyURL, ok := s.store.AccountProxyForOwnerAppleID(scope, appleID); ok {
			return proxyURL
		}
	}
	return ""
}

func (s *Server) loginProxySelectionForRequest(r *http.Request, appleID, requested string) (string, bool) {
	if strings.TrimSpace(requested) != "" {
		return requested, true
	}
	return s.loginProxyForRequest(r, appleID, ""), false
}

func bindLoginSessionTarget(session ICloudSession, target loginTarget) ICloudSession {
	session.OwnerID = strings.TrimSpace(target.OwnerID)
	if accountID := strings.TrimSpace(target.AccountID); accountID != "" {
		session.AccountID = accountID
	}
	return session
}

func pendingLoginTargetOwnerID(pending appleAuthPending, store *FileStore) string {
	if pending.TargetOwnerSet || strings.TrimSpace(pending.TargetOwnerID) != "" {
		return strings.TrimSpace(pending.TargetOwnerID)
	}
	if strings.TrimSpace(pending.AccountID) != "" {
		if account, ok := store.FindAccountByID(pending.AccountID); ok {
			return strings.TrimSpace(account.OwnerID)
		}
		return strings.TrimSpace(pending.TargetOwnerID)
	}
	return strings.TrimSpace(pending.OwnerID)
}

func (s *Server) pendingLoginWithCurrentProxy(pending appleAuthPending) appleAuthPending {
	if pending.Session == nil {
		return pending
	}
	session := *pending.Session
	if pending.ProxyExplicit {
		pending.Session = &session
		return pending
	}
	if accountID := strings.TrimSpace(pending.AccountID); accountID != "" {
		if account, ok := s.store.FindAccountByID(accountID); ok {
			session.ProxyURL = strings.TrimSpace(account.ProxyURL)
		}
		pending.Session = &session
		return pending
	}
	if proxyURL, matched := s.store.AccountProxyConfigForOwnerAppleID(pending.OwnerID, session.AppleID); matched {
		session.ProxyURL = proxyURL
	}
	pending.Session = &session
	return pending
}

func (s *Server) savePendingICloudSession(pending appleAuthPending, session ICloudSession) error {
	targetOwnerID := pendingLoginTargetOwnerID(pending, s.store)
	if accountID := strings.TrimSpace(pending.AccountID); accountID != "" {
		account, ok := s.store.FindAccountByID(accountID)
		if !ok {
			return errCode("account_not_found", "登录目标 Apple 账号已不存在，请重新选择账号", false)
		}
		if (pending.TargetOwnerSet || strings.TrimSpace(pending.TargetOwnerID) != "") &&
			strings.TrimSpace(pending.TargetOwnerID) != strings.TrimSpace(account.OwnerID) {
			return errCode("account_forbidden", "登录目标 Apple 账号已变更归属，请重新发起登录", false)
		}
		session.AccountID = account.ID
		session.OwnerID = strings.TrimSpace(account.OwnerID)
		session.AppleID = firstNonEmpty(strings.TrimSpace(session.AppleID), strings.TrimSpace(account.AppleID))
	} else {
		session.OwnerID = targetOwnerID
	}
	var err error
	if pending.ProxyExplicit {
		err = s.store.SaveICloudSessionForOwnerUpdatingProxy(targetOwnerID, session)
	} else {
		err = s.store.SaveICloudSessionForOwner(targetOwnerID, session)
	}
	if err != nil {
		return err
	}
	s.rememberAppleLoginPassword(targetOwnerID, session.AccountID, session.AppleID, pending.Password)
	return nil
}

func (s *Server) rememberAppleLoginPassword(ownerID, accountID, appleID, password string) {
	accountID = strings.TrimSpace(accountID)
	appleID = strings.TrimSpace(appleID)
	if accountID == "" && appleID != "" && s != nil && s.store != nil {
		if account, ok := s.store.FindAccountForOwnerAppleID(ownerID, appleID); ok {
			accountID = account.ID
		}
	}
	if err := s.persistAppleLoginPassword(ownerID, accountID, appleID, password); err != nil && s != nil && s.logger != nil {
		s.logger.Warn("failed to persist Apple ID password after login", "owner_id", ownerID, "account_id", accountID, "err", err)
	}
}

func (s *Server) rememberAccountLoginProxy(ownerID, accountID, proxyURL string) {
	accountID = strings.TrimSpace(accountID)
	if s == nil || s.store == nil || accountID == "" {
		return
	}
	if _, err := s.store.UpdateAccountProxyForOwner(ownerID, accountID, proxyURL); err != nil && s.logger != nil {
		s.logger.Warn("failed to persist account proxy after login", "owner_id", ownerID, "account_id", accountID, "err", err)
	}
}

func (s *Server) persistAppleLoginPassword(ownerID, accountID, appleID, password string) error {
	if s == nil || s.store == nil {
		return nil
	}
	err := s.store.SaveAccountApplePasswordForOwner(ownerID, accountID, appleID, password)
	if err == nil || isCodedError(err, "account_not_found") {
		return nil
	}
	return err
}

func (s *Server) pendingBelongsToRequest(r *http.Request, pending appleAuthPending) bool {
	ownerID := requestOwnerID(r, s.store)
	return ownerID != "" && constantTimeEqual(ownerID, pending.OwnerID)
}

func (s *Server) scopedState(r *http.Request) State {
	if s.isAdminRequest(r) {
		return s.store.Snapshot()
	}
	if key := scopedOwnerID(r, s.store); key != "" {
		return s.store.SnapshotForOwner(key)
	}
	return s.store.Snapshot()
}

func (s *Server) homeScopedState(r *http.Request) State {
	if !s.isAdminRequest(r) {
		return s.scopedState(r)
	}
	switch scope := s.adminOwnerScope(r); {
	case scope == "all":
		return s.scopedState(r)
	case scope == "__global":
		return s.store.SnapshotForGlobal()
	case scope != "":
		return s.store.SnapshotForOwner(scope)
	default:
		return s.scopedState(r)
	}
}

func requestOwnerScopeFilter(r *http.Request) string {
	return strings.TrimSpace(r.URL.Query().Get("owner_id"))
}

func (s *Server) adminOwnerScope(r *http.Request) string {
	if !s.isAdminRequest(r) {
		return requestOwnerID(r, s.store)
	}
	filter := requestOwnerScopeFilter(r)
	switch {
	case filter == "" || strings.EqualFold(filter, "current"):
		return requestOwnerID(r, s.store)
	case strings.EqualFold(filter, "all"):
		return "all"
	case filter == "__global":
		return "__global"
	default:
		return filter
	}
}

func (s *Server) accountInRequestScope(r *http.Request, accountID string) bool {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return true
	}
	account, ok := s.store.FindAccountByID(accountID)
	if !ok {
		return false
	}
	if !s.isAdminRequest(r) {
		ownerID := requestOwnerID(r, s.store)
		if ownerID == "" {
			return true
		}
		return constantTimeEqual(account.OwnerID, ownerID)
	}
	switch scope := s.adminOwnerScope(r); {
	case scope == "all":
		return true
	case scope == "__global":
		return strings.TrimSpace(account.OwnerID) == ""
	default:
		return constantTimeEqual(account.OwnerID, scope)
	}
}

func (s *Server) sessionsForRequestScope(r *http.Request, accountID string) []ICloudSession {
	accountID = strings.TrimSpace(accountID)
	if !s.isAdminRequest(r) {
		return s.sessionsForOwner(requestOwnerID(r, s.store), accountID)
	}
	scope := s.adminOwnerScope(r)
	if scope == "all" {
		sessions := s.allICloudSessionsForManagement()
		if accountID == "" {
			return sessions
		}
		out := make([]ICloudSession, 0, 1)
		for _, session := range sessions {
			if constantTimeEqual(strings.TrimSpace(session.AccountID), accountID) {
				out = append(out, session)
			}
		}
		return out
	}
	ownerID := scope
	if scope == "__global" {
		ownerID = ""
	}
	if accountID != "" {
		if session, ok := s.store.ICloudSessionForOwnerAccount(ownerID, accountID); ok {
			return []ICloudSession{session}
		}
		return nil
	}
	return s.store.ICloudSessionsForOwner(ownerID)
}

func (s *Server) publicSessionsForHomeRequest(r *http.Request) []publicICloudSession {
	if s.isAdminRequest(r) && s.adminOwnerScope(r) == "all" {
		return s.publicSessionsForManagementRequest(r)
	}
	sessions := s.sessionsForRequestScope(r, "")
	out := make([]publicICloudSession, 0, len(sessions))
	for i := range sessions {
		out = append(out, s.publicSession(&sessions[i]))
	}
	return out
}

func (s *Server) dataOwnerIDForCheckedSessions(r *http.Request, sessions []ICloudSession) string {
	if len(sessions) == 1 {
		return s.dataOwnerIDForSession(requestOwnerID(r, s.store), sessions[0])
	}
	scope := s.adminOwnerScope(r)
	if scope == "all" || scope == "__global" {
		return requestOwnerID(r, s.store)
	}
	return scope
}

func (s *Server) sessionForRequest(r *http.Request) (ICloudSession, bool) {
	session, _, ok := s.sessionForRequestWithOwner(r)
	return session, ok
}

func (s *Server) sessionForOwner(ownerID string) (ICloudSession, bool) {
	if ownerID = strings.TrimSpace(ownerID); ownerID != "" {
		return s.store.ICloudSessionForOwner(ownerID)
	}
	return s.store.ICloudSession()
}

func (s *Server) sessionForOwnerAccount(ownerID, accountID string) (ICloudSession, bool) {
	if ownerID = strings.TrimSpace(ownerID); ownerID != "" {
		if session, ok := s.store.ICloudSessionForOwnerAccount(ownerID, accountID); ok {
			return session, true
		}
		if user, ok := s.store.UserByID(ownerID); ok && user.IsAdmin {
			if account, ok := s.store.FindAccountByID(accountID); ok && strings.TrimSpace(account.OwnerID) != "" {
				if session, ok := s.store.ICloudSessionForOwnerAccount(account.OwnerID, accountID); ok {
					return session, true
				}
			}
			return s.store.ICloudSessionForOwnerAccount("", accountID)
		}
		return ICloudSession{}, false
	}
	return s.store.ICloudSessionForOwnerAccount("", accountID)
}

func (s *Server) dataOwnerIDForAccount(requestOwnerID, accountID string) string {
	requestOwnerID = strings.TrimSpace(requestOwnerID)
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return requestOwnerID
	}
	if account, ok := s.store.FindAccountByID(accountID); ok {
		return strings.TrimSpace(account.OwnerID)
	}
	return requestOwnerID
}

func (s *Server) dataOwnerIDForSession(requestOwnerID string, session ICloudSession) string {
	if ownerID := strings.TrimSpace(session.OwnerID); ownerID != "" {
		return ownerID
	}
	return s.dataOwnerIDForAccount(requestOwnerID, session.AccountID)
}

func (s *Server) sessionsForOwner(ownerID, accountID string) []ICloudSession {
	accountID = strings.TrimSpace(accountID)
	if accountID != "" {
		if session, ok := s.sessionForOwnerAccount(ownerID, accountID); ok {
			return []ICloudSession{session}
		}
		return nil
	}
	if ownerID = strings.TrimSpace(ownerID); ownerID != "" {
		return s.store.ICloudSessionsForOwner(ownerID)
	}
	return s.store.ICloudSessionsForOwner("")
}

func (s *Server) allICloudSessionsForManagement() []ICloudSession {
	return s.store.ICloudSessionsForAllOwners()
}

func (s *Server) sessionsForOwnerAccounts(ownerID string, accountIDs []string) []ICloudSession {
	accountIDs = normalizeAccountIDSelection("", accountIDs)
	if len(accountIDs) == 0 {
		return s.sessionsForOwner(ownerID, "")
	}
	sessions := make([]ICloudSession, 0, len(accountIDs))
	for _, accountID := range accountIDs {
		if session, ok := s.sessionForOwnerAccount(ownerID, accountID); ok {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

func (s *Server) sessionForMailbox(ownerID, accountID string) (ICloudSession, bool) {
	if accountID = strings.TrimSpace(accountID); accountID != "" {
		return s.sessionForOwnerAccount(ownerID, accountID)
	}
	sessions := s.sessionsForOwner(ownerID, "")
	if len(sessions) != 1 {
		return ICloudSession{}, false
	}
	return sessions[0], true
}

func (s *Server) imapSessionForMailbox(ownerID string, mailbox Mailbox) (ICloudSession, LoginState, bool) {
	if session, ok := s.sessionForOwnerAccount(ownerID, mailbox.AccountID); ok {
		if state, ok := iCloudIMAPLoginState(session); ok {
			return session, state, true
		}
	}
	type match struct {
		session ICloudSession
		state   LoginState
	}
	var found []match
	for _, session := range s.sessionsForOwner(ownerID, "") {
		if state, ok := iCloudIMAPLoginState(session); ok {
			found = append(found, match{session: session, state: state})
		}
	}
	if strings.TrimSpace(mailbox.AccountID) == "" && len(found) == 1 {
		return found[0].session, found[0].state, true
	}
	return ICloudSession{}, LoginState{}, false
}

func (s *Server) imapStateForMailbox(ownerID string, mailbox Mailbox) (LoginState, bool) {
	_, state, ok := s.imapSessionForMailbox(ownerID, mailbox)
	return state, ok
}

type imapSessionResolver struct {
	byAccount map[string]imapSessionMatch
	single    imapSessionMatch
	hasSingle bool
}

type imapSessionMatch struct {
	session ICloudSession
	state   LoginState
}

func (s *Server) imapSessionResolverForOwner(ownerID string) imapSessionResolver {
	sessions := s.sessionsForOwner(ownerID, "")
	resolver := imapSessionResolver{byAccount: make(map[string]imapSessionMatch, len(sessions))}
	matches := make([]imapSessionMatch, 0, len(sessions))
	for _, session := range sessions {
		state, ok := iCloudIMAPLoginState(session)
		if !ok {
			continue
		}
		match := imapSessionMatch{session: session, state: state}
		if accountID := strings.TrimSpace(session.AccountID); accountID != "" {
			resolver.byAccount[accountID] = match
		}
		matches = append(matches, match)
	}
	if len(matches) == 1 {
		resolver.single = matches[0]
		resolver.hasSingle = true
	}
	return resolver
}

func (r imapSessionResolver) sessionForMailbox(mailbox Mailbox) (ICloudSession, LoginState, bool) {
	if match, ok := r.byAccount[strings.TrimSpace(mailbox.AccountID)]; ok {
		return match.session, match.state, true
	}
	if strings.TrimSpace(mailbox.AccountID) == "" && r.hasSingle {
		return r.single.session, r.single.state, true
	}
	return ICloudSession{}, LoginState{}, false
}

func imapStateKey(state LoginState) string {
	return strings.ToLower(strings.TrimSpace(firstNonEmpty(state.IMAPEmail, state.IMAPUsername))) + "|" +
		strings.ToLower(strings.TrimSpace(firstNonEmpty(state.IMAPHost, defaultICloudIMAPHost))) + "|" +
		strconv.Itoa(state.IMAPPort)
}

func imapStateSensitiveKey(state LoginState) string {
	h := fnv.New64a()
	_, _ = io.WriteString(h, strings.TrimSpace(state.ProxyURL)+"|"+state.IMAPAppPassword)
	return fmt.Sprintf("%x", h.Sum64())
}

func (s *Server) publicSessionForRequest(r *http.Request) publicICloudSession {
	session, ok := s.sessionForRequest(r)
	if !ok {
		return publicSession(nil)
	}
	return s.publicSession(&session)
}

func (s *Server) publicSessionsForRequest(r *http.Request) []publicICloudSession {
	return s.publicSessionsForOwner(requestOwnerID(r, s.store))
}

func (s *Server) publicSessionsForManagementRequest(r *http.Request) []publicICloudSession {
	if !s.isAdminRequest(r) {
		return s.publicSessionsForRequest(r)
	}
	state := s.store.Snapshot()
	sessions := make([]ICloudSession, 0, len(state.ICloudSessions)+1)
	if state.ICloudSession != nil {
		sessions = appendMergedOwnedICloudSession(sessions, *state.ICloudSession)
	}
	for _, session := range state.ICloudSessions {
		sessions = appendMergedOwnedICloudSession(sessions, session)
	}
	out := make([]publicICloudSession, 0, len(sessions))
	for i := range sessions {
		out = append(out, s.publicSession(&sessions[i]))
	}
	return out
}

func appendMergedOwnedICloudSession(sessions []ICloudSession, session ICloudSession) []ICloudSession {
	ownerID := strings.TrimSpace(session.OwnerID)
	for i := range sessions {
		if strings.TrimSpace(sessions[i].OwnerID) != ownerID || !sameICloudSessionIdentity(sessions[i], session) {
			continue
		}
		sessions[i] = mergeICloudSession(sessions[i], session)
		return sessions
	}
	return append(sessions, session)
}

func publicCreateSettings(settings CreateSettings) map[string]any {
	settings = normalizeCreateSettings(settings.OwnerID, settings)
	createChannel := normalizeMailboxCreateChannel(mailboxCreateChannel(settings.CreateChannel))
	schedulerChannel := normalizeMailboxCreateChannel(mailboxCreateChannel(settings.SchedulerCreateChannel))
	return map[string]any{
		"label":                            settings.Label,
		"note":                             settings.Note,
		"account_ids":                      append([]string(nil), settings.AccountIDs...),
		"create_channel":                   string(createChannel),
		"create_channel_label":             mailboxCreateChannelLabel(createChannel),
		"scheduler_create_channel":         string(schedulerChannel),
		"scheduler_create_channel_label":   mailboxCreateChannelLabel(schedulerChannel),
		"apple_account_two_factor_method":  normalizeAppleTwoFactorMethod(settings.AppleAccountTwoFactorMethod),
		"icloud_web_two_factor_method":     normalizeAppleTwoFactorMethod(settings.ICloudWebTwoFactorMethod),
		"scheduler_interval_minutes":       settings.SchedulerIntervalMinutes,
		"scheduler_round_interval_seconds": settings.SchedulerRoundIntervalSeconds,
		"mailbox_page_size":                settings.MailboxPageSize,
		"updated_at":                       formatTime(settings.UpdatedAt),
	}
}

func (s *Server) publicSessionsForOwner(ownerID string) []publicICloudSession {
	sessions := s.sessionsForOwner(ownerID, "")
	out := make([]publicICloudSession, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, s.publicSession(&session))
	}
	return out
}

func (s *Server) publicSessionsForCheckedSessions(requestOwnerID string, checked []ICloudSession) []publicICloudSession {
	ownerID := strings.TrimSpace(requestOwnerID)
	for _, session := range checked {
		if accountID := strings.TrimSpace(session.AccountID); accountID != "" {
			if account, ok := s.store.FindAccountByID(accountID); ok {
				return s.publicSessionsForOwner(strings.TrimSpace(account.OwnerID))
			}
		}
		if sessionOwnerID := strings.TrimSpace(session.OwnerID); sessionOwnerID != "" {
			return s.publicSessionsForOwner(sessionOwnerID)
		}
		return s.publicSessionsForOwner("")
	}
	return s.publicSessionsForOwner(ownerID)
}

func (s *Server) sessionForRequestWithOwner(r *http.Request) (ICloudSession, string, bool) {
	if ownerID := requestOwnerID(r, s.store); ownerID != "" {
		if session, ok := s.store.ICloudSessionForOwner(ownerID); ok {
			return session, ownerID, true
		}
	}
	if s.isAdminRequest(r) {
		session, ok := s.store.ICloudSession()
		return session, "", ok
	}
	ownerID := scopedOwnerID(r, s.store)
	session, ok := s.store.ICloudSessionForOwner(ownerID)
	return session, ownerID, ok
}

func (s *Server) currentWebSession(r *http.Request) (WebSession, User, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return WebSession{}, User{}, false
	}
	return s.store.WebSessionByToken(cookie.Value)
}

func (s *Server) authorizedUserSession(r *http.Request) bool {
	session, user, ok := s.currentWebSession(r)
	return ok && !session.IsAdmin && user.ID != ""
}

func (s *Server) authorizedAdminSession(r *http.Request) bool {
	session, user, ok := s.currentWebSession(r)
	return ok && (session.IsAdmin || user.IsAdmin)
}

func (s *Server) isAdminRequest(r *http.Request) bool {
	return s.authorizedAdminSession(r)
}

func (s *Server) allowsUserSession(r *http.Request) bool {
	if r.Method == http.MethodGet && r.URL.Path == "/api/status" {
		return true
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/update/status" {
		return true
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/create-settings" {
		return true
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/manage/data" {
		return true
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/icloud/session" {
		return true
	}
	if r.Method == http.MethodPost {
		switch r.URL.Path {
		case "/api/create-settings",
			"/api/icloud/protocol-login/start",
			"/api/icloud/protocol-login/2fa",
			"/api/apple-account/login/start",
			"/api/apple-account/login/2fa",
			"/api/icloud/session/check",
			"/api/icloud/imap-login/save",
			"/api/icloud/imap-login/check",
			"/api/icloud/mailboxes/create",
			"/api/icloud/mailboxes/sync",
			"/api/icloud/scheduler/start",
			"/api/icloud/scheduler/stop",
			"/api/icloud/scheduler/logs/clear",
			"/api/runtime/export-mailbox-apis",
			"/api/runtime/export-mailbox-emails",
			"/api/runtime/unmark-mailbox-apis":
			return true
		}
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/icloud/scheduler/status" {
		return true
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/accounts" {
		return true
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/accounts" {
		return true
	}
	if r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/accounts/") {
		return true
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/mailboxes" {
		return true
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/mailboxes" {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/mailboxes/") {
		return true
	}
	return false
}

func (s *Server) canAccessMailboxID(r *http.Request, id string) bool {
	mailbox, ok := s.store.FindMailboxByID(id)
	return ok && s.canAccessMailbox(r, mailbox)
}

func (s *Server) canAccessMailbox(r *http.Request, mailbox Mailbox) bool {
	if s.isAdminRequest(r) {
		return true
	}
	ownerID := scopedOwnerID(r, s.store)
	if ownerID == "" {
		return true
	}
	return constantTimeEqual(ownerID, mailbox.OwnerID)
}

func (s *Server) canAccessAccountID(r *http.Request, id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return true
	}
	account, ok := s.store.FindAccountByID(id)
	if !ok {
		return false
	}
	if s.isAdminRequest(r) {
		return true
	}
	ownerID := scopedOwnerID(r, s.store)
	if ownerID == "" {
		return true
	}
	return constantTimeEqual(ownerID, account.OwnerID)
}

func (s *Server) canAccessAccountIDs(r *http.Request, ids []string) bool {
	for _, id := range normalizeAccountIDSelection("", ids) {
		if !s.canAccessAccountID(r, id) {
			return false
		}
	}
	return true
}

func (s *Server) requiresAdmin(r *http.Request) bool {
	if r.URL.Path == "/" {
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/api/auth/") {
		return false
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/v1/health" {
		return false
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/mailboxes/claim" {
		return false
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/mailboxes/lookup" {
		return false
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/mailboxes/") && strings.HasSuffix(r.URL.Path, "/code") {
		return false
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/mailboxes/") && strings.HasSuffix(r.URL.Path, "/code") {
		return false
	}
	return strings.HasPrefix(r.URL.Path, "/api/")
}

func constantTimeEqual(candidate, want string) bool {
	candidate = strings.TrimSpace(candidate)
	want = strings.TrimSpace(want)
	if candidate == "" || want == "" || len(candidate) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(want)) == 1
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    csrfTokenForSession(token),
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: false,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: false,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) secureCookie(r *http.Request) bool {
	if requestExternalScheme(r) == "https" {
		return true
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s.cfg.PublicBaseURL)), "https://")
}

func publicUserFromUser(user User) publicUser {
	return publicUser{
		ID:          user.ID,
		Username:    user.Username,
		Status:      user.Status,
		IsAdmin:     user.IsAdmin,
		CreatedAt:   formatTime(user.CreatedAt),
		UpdatedAt:   formatTime(user.UpdatedAt),
		LastLoginAt: formatTime(user.LastLoginAt),
	}
}

func (s *Server) ownerName(ownerID string) string {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return "管理员/全局"
	}
	if user, ok := s.store.UserByID(ownerID); ok {
		return user.Username
	}
	return "旧数据/未知归属"
}

func (s *Server) publicUserSummaries(users []User, state State) []publicUserSummary {
	type counter struct {
		publicUserSummary
	}
	rows := make(map[string]*counter, len(users)+1)
	order := make([]string, 0, len(users)+1)

	ensure := func(ownerID, username string) *counter {
		ownerID = strings.TrimSpace(ownerID)
		if row, ok := rows[ownerID]; ok {
			if row.Username == "" && username != "" {
				row.Username = username
			}
			return row
		}
		if username == "" {
			username = s.ownerName(ownerID)
		}
		row := &counter{publicUserSummary: publicUserSummary{
			OwnerID:  ownerID,
			Username: username,
			Status:   StatusActive,
		}}
		rows[ownerID] = row
		order = append(order, ownerID)
		return row
	}

	for _, user := range users {
		row := ensure(user.ID, user.Username)
		row.Status = user.Status
		row.IsAdmin = user.IsAdmin
		row.LastLoginAt = formatTime(user.LastLoginAt)
	}

	mailboxOwner := make(map[string]string, len(state.Mailboxes))
	for _, account := range state.Accounts {
		ensure(account.OwnerID, "").AccountCount++
	}
	for _, mailbox := range state.Mailboxes {
		row := ensure(mailbox.OwnerID, "")
		row.MailboxCount++
		switch mailbox.Status {
		case StatusAvailable:
			row.AvailableMailboxCount++
		case StatusUsed:
			row.UsedMailboxCount++
		}
		mailboxOwner[mailbox.ID] = mailbox.OwnerID
	}
	for _, msg := range state.Messages {
		ownerID := strings.TrimSpace(msg.OwnerID)
		if ownerID == "" {
			ownerID = mailboxOwner[msg.MailboxID]
		}
		ensure(ownerID, "").MessageCount++
	}
	if state.ICloudSession != nil && sessionHasSavedLoginState(*state.ICloudSession) {
		ensure("", "管理员/全局").ICloudSessionSaved = true
	}
	for _, session := range state.ICloudSessions {
		if sessionHasSavedLoginState(session) {
			ensure(session.OwnerID, "").ICloudSessionSaved = true
		}
	}

	out := make([]publicUserSummary, 0, len(order))
	for _, ownerID := range order {
		row := rows[ownerID]
		if ownerID == "" && row.AccountCount == 0 && row.MailboxCount == 0 && row.MessageCount == 0 && !row.ICloudSessionSaved {
			continue
		}
		out = append(out, row.publicUserSummary)
	}
	return out
}

func sessionHasSavedLoginState(session ICloudSession) bool {
	return iCloudWebLoginSaved(session) || appleAccountLoginSaved(session) || iCloudIMAPLoginSaved(session)
}

func sessionCanCreatePrivacyMailbox(session ICloudSession) bool {
	if appleAccountManageReady(session) {
		return true
	}
	return session.IsICloudPlus && session.CanCreateHME && iCloudWebLoginSaved(session)
}

func (s *Server) publicAccount(account Account) publicAccount {
	return s.encodePublicAccount(account, false)
}

func (s *Server) publicAccountWithSecrets(account Account) publicAccount {
	return s.encodePublicAccount(account, true)
}

func (s *Server) encodePublicAccount(account Account, includePassword bool) publicAccount {
	reconciliationError := ""
	if account.MailboxCreateReconciliationRequired {
		reconciliationError = "邮箱创建后的远端结果不确定，请先同步 iCloud 远端邮箱列表"
	}
	password := ""
	if includePassword {
		password = account.ApplePassword
	}
	return publicAccount{
		ID:                                  account.ID,
		OwnerID:                             account.OwnerID,
		Owner:                               s.ownerName(account.OwnerID),
		Label:                               account.Label,
		AppleID:                             strings.TrimSpace(account.AppleID),
		ApplePassword:                       password,
		ProxyConfigured:                     strings.TrimSpace(account.ProxyURL) != "",
		ProxyURL:                            strings.TrimSpace(account.ProxyURL),
		MailboxCreateReconciliationRequired: account.MailboxCreateReconciliationRequired,
		MailboxCreateReconciliationAt:       formatTime(account.MailboxCreateReconciliationAt),
		MailboxCreateReconciliationError:    reconciliationError,
		Status:                              account.Status,
		ICloudStatus:                        account.ICloudStatus,
		Note:                                account.Note,
		CreatedAt:                           formatTime(account.CreatedAt),
		UpdatedAt:                           formatTime(account.UpdatedAt),
	}
}

func (s *Server) publicMailbox(r *http.Request, mailbox Mailbox) publicMailbox {
	accountLabel := ""
	accountAppleID := ""
	if strings.TrimSpace(mailbox.AccountID) != "" {
		if account, ok := s.store.FindAccountByID(mailbox.AccountID); ok {
			accountLabel = account.Label
			accountAppleID = strings.TrimSpace(account.AppleID)
		}
	}
	apiActive := mailbox.APIActive
	if strings.EqualFold(strings.TrimSpace(mailbox.RemoteDeleteStatus), "succeeded") {
		apiActive = false
	}
	return publicMailbox{
		ID:                 mailbox.ID,
		OwnerID:            mailbox.OwnerID,
		Owner:              s.ownerName(mailbox.OwnerID),
		AccountID:          mailbox.AccountID,
		AccountLabel:       accountLabel,
		AccountAppleID:     accountAppleID,
		RemoteAnonymousID:  mailbox.RemoteAnonymousID,
		RemoteOrigin:       mailbox.RemoteOrigin,
		RemoteMissingAt:    formatTime(mailbox.RemoteMissingAt),
		RemoteDeleteStatus: mailbox.RemoteDeleteStatus,
		RemoteDeleteError:  mailbox.RemoteDeleteError,
		RemoteDeleteAt:     formatTime(mailbox.RemoteDeleteAt),
		Label:              mailbox.Label,
		Email:              mailbox.Email,
		APITokenMask:       maskSecret(mailbox.APIToken, 6),
		APIToken:           mailbox.APIToken,
		APIURL:             s.mailboxAPIURL(r, mailbox),
		APIActive:          apiActive,
		ICloudActive:       mailbox.ICloudActive,
		APIExported:        !mailbox.APIExportedAt.IsZero(),
		APIExportedAt:      formatTime(mailbox.APIExportedAt),
		ReceiveCount:       mailbox.ReceiveCount,
		Status:             mailbox.Status,
		Note:               mailbox.Note,
		LastSyncAt:         formatTime(mailbox.LastSyncAt),
		LastSyncUID:        mailbox.LastSyncUID,
		CreatedAt:          formatTime(mailbox.CreatedAt),
		UpdatedAt:          formatTime(mailbox.UpdatedAt),
	}
}

func (s *Server) publicExternalMailbox(r *http.Request, mailbox Mailbox) publicMailbox {
	full := s.publicMailbox(r, mailbox)
	return publicMailbox{
		ID:            full.ID,
		Label:         full.Label,
		Email:         full.Email,
		APITokenMask:  full.APITokenMask,
		APIToken:      mailbox.APIToken,
		APIURL:        full.APIURL,
		APIActive:     full.APIActive,
		ICloudActive:  full.ICloudActive,
		APIExported:   full.APIExported,
		APIExportedAt: full.APIExportedAt,
		ReceiveCount:  full.ReceiveCount,
		Status:        full.Status,
		Note:          full.Note,
		LastSyncAt:    full.LastSyncAt,
		LastSyncUID:   full.LastSyncUID,
		CreatedAt:     full.CreatedAt,
		UpdatedAt:     full.UpdatedAt,
	}
}

func (s *Server) mailboxAPIURL(r *http.Request, mailbox Mailbox) string {
	baseURL := firstNonEmpty(s.cfg.PublicBaseURL, requestBaseURL(r))
	return fmt.Sprintf("%s/api/v1/mailboxes/%s/code", strings.TrimRight(baseURL, "/"), url.PathEscape(mailbox.Email))
}

func (s *Server) publicSession(session *ICloudSession) publicICloudSession {
	interval := s.appleAccountKeepAliveInterval
	if interval <= 0 {
		interval = appleAccountKeepAliveDefaultInterval
	}
	return publicSessionWithKeepAliveInterval(session, interval)
}

func publicSession(session *ICloudSession) publicICloudSession {
	return publicSessionWithKeepAliveInterval(session, appleAccountKeepAliveDefaultInterval)
}

func publicSessionWithKeepAliveInterval(session *ICloudSession, keepAliveInterval time.Duration) publicICloudSession {
	if session == nil {
		return publicICloudSession{
			Saved:              false,
			NeedsManualLogin:   true,
			LastStatusMessage:  "未保存 iCloud 登录态",
			ProviderConfigured: false,
		}
	}
	message := strings.TrimSpace(session.LastStatusMessage)
	if message == "" {
		message = "登录态已保存；Cookie 原文只写入本地 data/state.json，不会返回前端"
	}
	icloudWebLoginSaved := iCloudWebLoginSaved(*session)
	appleAccountLoginSaved := appleAccountLoginSaved(*session)
	icloudIMAPLoginSaved := iCloudIMAPLoginSaved(*session)
	icloudWebState, _ := iCloudWebLoginState(*session)
	appleAccountState, _ := appleAccountLoginState(*session)
	icloudIMAPState, _ := iCloudIMAPLoginState(*session)
	cookieCount := len(session.Cookies)
	if cookieCount == 0 {
		cookieCount = len(icloudWebState.Cookies)
	}
	appleAccountNextRefreshAt := time.Time{}
	if appleAccountKeepAliveEligible(*session) && !appleAccountState.LastCheckedAt.IsZero() {
		appleAccountNextRefreshAt = appleAccountState.LastCheckedAt.Add(appleAccountKeepAliveIntervalForSession(*session, keepAliveInterval))
	}
	return publicICloudSession{
		Saved:                         true,
		AccountID:                     session.AccountID,
		ProxyConfigured:               strings.TrimSpace(session.ProxyURL) != "",
		ProxyURL:                      strings.TrimSpace(session.ProxyURL),
		SavedAt:                       formatTime(session.SavedAt),
		AppleID:                       strings.TrimSpace(session.AppleID),
		DSIDMask:                      maskSecret(session.DSID, 4),
		ClientBuildNumber:             session.ClientBuildNumber,
		MasteringNumber:               session.MasteringNumber,
		PremiumMailBaseURL:            session.PremiumMailBaseURL,
		MailGatewayBaseURL:            session.MailGatewayBaseURL,
		MailBaseURL:                   session.MailBaseURL,
		Host:                          session.Host,
		IsICloudPlus:                  session.IsICloudPlus,
		CanCreateHME:                  session.CanCreateHME,
		CookieCount:                   cookieCount,
		ICloudWebLoginSaved:           icloudWebLoginSaved,
		ICloudWebLoginChecked:         !icloudWebState.LastCheckedAt.IsZero(),
		ICloudWebLoginOK:              icloudWebState.LastCheckOK,
		ICloudWebLoginStatus:          loginStatePublicStatus(icloudWebLoginSaved, icloudWebState),
		AppleAccountLoginSaved:        appleAccountLoginSaved,
		AppleAccountLoginChecked:      !appleAccountState.LastCheckedAt.IsZero(),
		AppleAccountLoginOK:           appleAccountPublicLoginOK(appleAccountState),
		AppleAccountLoginStatus:       loginStatePublicStatus(appleAccountLoginSaved, appleAccountState),
		AppleAccountNextRefreshAt:     formatTime(appleAccountNextRefreshAt),
		AppleAccountManageExpiresAt:   formatTime(appleAccountState.ManageExpiresAt),
		AppleAccountKeepAliveStopped:  appleAccountState.KeepAliveStopped,
		AppleAccountKeepAliveRetrying: appleAccountKeepAliveRetrying(appleAccountState),
		AppleAccountManageReady:       appleAccountManageReady(*session),
		ICloudIMAPLoginSaved:          icloudIMAPLoginSaved,
		ICloudIMAPLoginChecked:        !icloudIMAPState.LastCheckedAt.IsZero(),
		ICloudIMAPLoginOK:             icloudIMAPState.LastCheckOK,
		ICloudIMAPLoginStatus:         loginStatePublicStatus(icloudIMAPLoginSaved, icloudIMAPState),
		ICloudIMAPEmail:               normalizeICloudIMAPEmail(icloudIMAPState.IMAPEmail),
		ICloudIMAPHost:                firstNonEmpty(strings.TrimSpace(icloudIMAPState.IMAPHost), strings.TrimSpace(icloudIMAPState.Host)),
		ProviderConfigured:            sessionCanCreatePrivacyMailbox(*session),
		NeedsManualLogin:              !icloudWebLoginSaved && !appleAccountLoginSaved && !icloudIMAPLoginSaved,
		LastCheckedAt:                 formatTime(session.LastCheckedAt),
		LastCheckOK:                   session.LastCheckOK,
		LastStatusMessage:             message,
	}
}

func loginStatePublicStatus(saved bool, state LoginState) string {
	if !saved {
		return "未登录"
	}
	if state.LastCheckedAt.IsZero() {
		return "已登录"
	}
	if appleAccountKeepAliveDeferred(state) {
		return strings.TrimSpace(state.LastStatusMessage)
	}
	if state.LastCheckOK {
		return "登录态正常"
	}
	return "登录态异常"
}

func iCloudWebLoginSaved(session ICloudSession) bool {
	hasWebState := false
	for _, state := range session.LoginStates {
		if state.Kind != LoginStateICloudWeb {
			continue
		}
		hasWebState = true
		if len(state.Cookies) > 0 || len(session.Cookies) > 0 {
			return true
		}
	}
	if hasWebState && len(session.Cookies) > 0 {
		return true
	}
	if len(session.LoginStates) == 0 {
		return len(session.Cookies) > 0
	}
	if !hasAnyNonAppleAccountLoginState(session.LoginStates) {
		// Apple Account cookies are not iCloud Web cookies. Without an
		// explicit Web state, do not infer Web login from the shared root
		// cookie jar when Apple Account is the only saved login state.
		return false
	}
	// Legacy sessions stored Web cookies at the session root. They may now
	// coexist with IMAP or other non-Web states, so their presence must not
	// hide the legacy Web capability.
	return len(session.Cookies) > 0
}

func iCloudWebLoginState(session ICloudSession) (LoginState, bool) {
	hasWebState := false
	for _, state := range session.LoginStates {
		if state.Kind != LoginStateICloudWeb {
			continue
		}
		hasWebState = true
		if len(state.Cookies) > 0 {
			state.ProxyURL = firstNonEmpty(state.ProxyURL, session.ProxyURL)
			return state, true
		}
	}
	if len(session.Cookies) == 0 {
		return LoginState{}, false
	}
	if len(session.LoginStates) == 0 {
		goto synthesize
	}
	if !hasAnyNonAppleAccountLoginState(session.LoginStates) {
		return LoginState{}, false
	}
	if hasWebState {
		for _, state := range session.LoginStates {
			if state.Kind != LoginStateICloudWeb {
				continue
			}
			state.ProxyURL = firstNonEmpty(state.ProxyURL, session.ProxyURL)
			state.Cookies = append([]SessionCookie(nil), session.Cookies...)
			return state, true
		}
	}

synthesize:
	return LoginState{
		Kind:      LoginStateICloudWeb,
		Host:      session.Host,
		Origin:    iCloudOrigin(session),
		ProxyURL:  session.ProxyURL,
		SavedAt:   session.SavedAt,
		Cookies:   append([]SessionCookie(nil), session.Cookies...),
		UserAgent: appleAuthUserAgent,
		Note:      "iCloud webservices login state",
	}, true
}

func withICloudWebLoginState(session ICloudSession, next LoginState) ICloudSession {
	next.Kind = LoginStateICloudWeb
	next.ProxyURL = firstNonEmpty(next.ProxyURL, session.ProxyURL)
	session.ProxyURL = firstNonEmpty(session.ProxyURL, next.ProxyURL)
	if len(next.Cookies) == 0 && len(session.Cookies) > 0 {
		next.Cookies = append([]SessionCookie(nil), session.Cookies...)
	}
	for i, state := range session.LoginStates {
		if state.Kind == LoginStateICloudWeb {
			session.LoginStates[i] = next
			return session
		}
	}
	session.LoginStates = append(session.LoginStates, next)
	return session
}

func iCloudIMAPLoginSaved(session ICloudSession) bool {
	_, ok := iCloudIMAPLoginState(session)
	return ok
}

func iCloudIMAPLoginState(session ICloudSession) (LoginState, bool) {
	for _, state := range session.LoginStates {
		if state.Kind != LoginStateICloudIMAP {
			continue
		}
		email := normalizeICloudIMAPEmail(state.IMAPEmail)
		if email == "" {
			email = normalizeICloudIMAPEmail(session.AppleID)
		}
		if email == "" || strings.TrimSpace(state.IMAPAppPassword) == "" {
			continue
		}
		state.IMAPEmail = email
		state.IMAPUsername = firstNonEmpty(strings.TrimSpace(state.IMAPUsername), email)
		state.IMAPHost = firstNonEmpty(strings.TrimSpace(state.IMAPHost), defaultICloudIMAPHost)
		state.ProxyURL = firstNonEmpty(state.ProxyURL, session.ProxyURL)
		if state.IMAPPort == 0 {
			state.IMAPPort = defaultICloudIMAPPort
		}
		return state, true
	}
	return LoginState{}, false
}

func withICloudIMAPLoginState(session ICloudSession, next LoginState) ICloudSession {
	next.Kind = LoginStateICloudIMAP
	next.ProxyURL = firstNonEmpty(next.ProxyURL, session.ProxyURL)
	session.ProxyURL = firstNonEmpty(session.ProxyURL, next.ProxyURL)
	next.IMAPEmail = normalizeICloudIMAPEmail(firstNonEmpty(next.IMAPEmail, session.AppleID))
	next.IMAPUsername = firstNonEmpty(strings.TrimSpace(next.IMAPUsername), next.IMAPEmail)
	next.IMAPHost = firstNonEmpty(strings.TrimSpace(next.IMAPHost), defaultICloudIMAPHost)
	next.Host = firstNonEmpty(strings.TrimSpace(next.Host), next.IMAPHost)
	next.Origin = firstNonEmpty(strings.TrimSpace(next.Origin), "imaps://"+next.IMAPHost)
	if next.IMAPPort == 0 {
		next.IMAPPort = defaultICloudIMAPPort
	}
	for i, state := range session.LoginStates {
		if state.Kind == LoginStateICloudIMAP {
			session.LoginStates[i] = next
			return session
		}
	}
	session.LoginStates = append(session.LoginStates, next)
	return session
}

func appleAccountLoginSaved(session ICloudSession) bool {
	_, ok := appleAccountLoginState(session)
	return ok
}

func normalizeICloudIMAPEmail(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func publicSessionForAppleID(sessions []publicICloudSession, appleID string) publicICloudSession {
	appleID = strings.TrimSpace(appleID)
	for _, session := range sessions {
		if appleID != "" && strings.EqualFold(strings.TrimSpace(session.AppleID), appleID) {
			return session
		}
	}
	if len(sessions) > 0 {
		return sessions[0]
	}
	return publicSession(nil)
}

func publicSessionForAccountID(sessions []publicICloudSession, accountID string) publicICloudSession {
	accountID = strings.TrimSpace(accountID)
	for _, session := range sessions {
		if accountID != "" && constantTimeEqual(strings.TrimSpace(session.AccountID), accountID) {
			return session
		}
	}
	if len(sessions) > 0 {
		return sessions[0]
	}
	return publicSession(nil)
}

func firstMap(rows []map[string]any) map[string]any {
	if len(rows) == 0 {
		return map[string]any{}
	}
	return rows[0]
}

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, 1<<20)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errCode("bad_json", "JSON 请求体非法："+err.Error(), false)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return errCode("bad_json", "JSON 请求体非法："+err.Error(), false)
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return errors.New("JSON 请求体包含多个值")
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(payload)
}

func publicErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	var coded codedError
	if errors.As(err, &coded) {
		return coded.message
	}
	return "操作失败"
}

func writeError(w http.ResponseWriter, status int, err error) {
	var coded codedError
	if errors.As(err, &coded) {
		writeJSON(w, status, apiError{
			Success:   false,
			Code:      coded.code,
			Message:   coded.message,
			Retryable: coded.retryable,
		})
		return
	}
	writeJSON(w, status, apiError{
		Success: false,
		Code:    "internal_error",
		Message: "操作失败",
	})
}

func requestBaseURL(r *http.Request) string {
	if r == nil {
		return ""
	}
	scheme := requestExternalScheme(r)
	host := requestExternalHost(r)
	if scheme == "" || host == "" {
		return ""
	}
	return scheme + "://" + host
}

func parseAfter(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, errCode("invalid_after", "after 必须是 RFC3339 时间", false)
	}
	return parsed, nil
}

var (
	contextOTPRegex = regexp.MustCompile(`(?i)(?:openai|chatgpt|otp|code|verification|验证码|验证|代码)[^\d]{0,80}(\d{6})`)
	plainOTPRegex   = regexp.MustCompile(`\b(\d{6})\b`)
)

func extractOTP(text string) string {
	if matches := contextOTPRegex.FindStringSubmatch(text); len(matches) == 2 && validOTP(matches[1]) {
		return matches[1]
	}
	for _, matches := range plainOTPRegex.FindAllStringSubmatch(text, -1) {
		if len(matches) == 2 && validOTP(matches[1]) {
			return matches[1]
		}
	}
	return ""
}

func validOTP(code string) bool {
	return len(code) == 6 && code != "000000"
}

func validMailboxStatus(status string) bool {
	switch status {
	case StatusActive, StatusAvailable, StatusUsed, StatusFailed, StatusDisabled:
		return true
	default:
		return false
	}
}

func maskAppleID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	at := strings.Index(value, "@")
	if at <= 1 {
		return maskSecret(value, 4)
	}
	return value[:1] + "***" + value[at:]
}
