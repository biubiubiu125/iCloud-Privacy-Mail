package app

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

func TestExtractOTP(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{name: "openai subject", text: "Your OpenAI code is 123456", want: "123456"},
		{name: "chinese", text: "验证码：654321，请勿泄露", want: "654321"},
		{name: "fallback", text: "Use 246810 to continue.", want: "246810"},
		{name: "zero invalid", text: "code 000000", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractOTP(tt.text); got != tt.want {
				t.Fatalf("extractOTP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func testIMAPSession(ownerID, accountID, email string) ICloudSession {
	email = normalizeICloudIMAPEmail(email)
	if email == "" {
		email = "receiver@example.com"
	}
	return ICloudSession{
		OwnerID:   ownerID,
		AccountID: accountID,
		AppleID:   email,
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:              LoginStateICloudIMAP,
			Host:              defaultICloudIMAPHost,
			Origin:            "imaps://" + defaultICloudIMAPHost,
			SavedAt:           time.Now(),
			IMAPEmail:         email,
			IMAPUsername:      email,
			IMAPHost:          defaultICloudIMAPHost,
			IMAPPort:          defaultICloudIMAPPort,
			IMAPAppPassword:   "app-specific-password",
			LastCheckedAt:     time.Now(),
			LastCheckOK:       true,
			LastStatusMessage: "取码登录正常",
		}},
	}
}

func TestGenerateAppleHashcash(t *testing.T) {
	challenge := "0123456789abcdef0123456789abcdef"
	now := time.Date(2026, 6, 29, 14, 2, 22, 0, time.UTC)
	got, err := generateAppleHashcash(8, challenge, now)
	if err != nil {
		t.Fatalf("generateAppleHashcash() error = %v", err)
	}
	parts := strings.Split(got, ":")
	if len(parts) != 6 {
		t.Fatalf("hashcash parts = %d, want 6 in %q", len(parts), got)
	}
	if parts[0] != "1" || parts[1] != "8" || parts[2] != "20260629140222" || parts[3] != challenge || parts[4] != "" || parts[5] == "" {
		t.Fatalf("hashcash format mismatch: %q", got)
	}
	sum := sha1.Sum([]byte(got))
	if leadingZeroBits(sum[:]) < 8 {
		t.Fatalf("hashcash does not satisfy requested difficulty")
	}
}

func TestAppleAccountFDClientInfoUsesBrowserFingerprint(t *testing.T) {
	var info map[string]string
	if err := json.Unmarshal([]byte(appleAccountFDClientInfo(appleAccountManageUserAgent)), &info); err != nil {
		t.Fatal(err)
	}
	if info["U"] != appleAccountManageUserAgent {
		t.Fatalf("U = %q, want manage user agent", info["U"])
	}
	if info["L"] != appleAccountManageLanguage || info["Z"] != appleAccountManageGMTOffset || info["V"] != "1.1" {
		t.Fatalf("unexpected locale fields: %+v", info)
	}
	if len(info["F"]) < 80 {
		t.Fatalf("F length = %d, want browser fingerprint", len(info["F"]))
	}
}

func TestAppleDomainRedirectMapsDomainToHost(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{domain: "iCloud.com", want: "www.icloud.com"},
		{domain: "www.icloud.com", want: "www.icloud.com"},
		{domain: "https://www.icloud.com.cn/", want: "www.icloud.com.cn"},
		{domain: "example.com", want: ""},
	}
	for _, tt := range tests {
		if got := appleDomainToHost(tt.domain); got != tt.want {
			t.Fatalf("appleDomainToHost(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}

func TestParseAppleDomainRedirect(t *testing.T) {
	redirect, ok := parseAppleDomainRedirect(http.StatusFound, []byte(`{"domainToUse":"iCloud.com"}`))
	if !ok {
		t.Fatal("parseAppleDomainRedirect did not detect redirect")
	}
	if redirect.Host != "www.icloud.com" || redirect.DomainToUse != "iCloud.com" {
		t.Fatalf("redirect = %+v, want www.icloud.com", redirect)
	}

	if _, ok := parseAppleDomainRedirect(http.StatusOK, []byte(`{"domainToUse":"iCloud.com"}`)); ok {
		t.Fatal("parseAppleDomainRedirect detected non-redirect status")
	}
}

func TestAppleAuthSessionSwitchHost(t *testing.T) {
	session := &appleAuthSession{Endpoints: appleAuthEndpointsForHost("www.icloud.com.cn")}
	if !session.switchHost("www.icloud.com") {
		t.Fatal("switchHost returned false, want true")
	}
	if session.Endpoints.Host != "www.icloud.com" || !strings.Contains(session.Endpoints.Auth, "idmsa.apple.com/appleauth") {
		t.Fatalf("endpoints after switch = %+v", session.Endpoints)
	}
	if session.switchHost("www.icloud.com") {
		t.Fatal("switchHost returned true for same host")
	}
}

func TestAppleHostForAccountCountry(t *testing.T) {
	tests := []struct {
		country string
		want    string
	}{
		{country: "", want: ""},
		{country: "CHN", want: "www.icloud.com.cn"},
		{country: "CN", want: "www.icloud.com.cn"},
		{country: "USA", want: "www.icloud.com"},
		{country: "sgp", want: "www.icloud.com"},
	}
	for _, tt := range tests {
		if got := appleHostForAccountCountry(tt.country); got != tt.want {
			t.Fatalf("appleHostForAccountCountry(%q) = %q, want %q", tt.country, got, tt.want)
		}
	}
}

func TestAppleAuthSessionRedirectForAccountCountry(t *testing.T) {
	session := &appleAuthSession{
		Endpoints:      appleAuthEndpointsForHost("www.icloud.com.cn"),
		AccountCountry: "USA",
	}
	redirect, ok := session.redirectForAccountCountry()
	if !ok {
		t.Fatal("redirectForAccountCountry returned ok=false")
	}
	if redirect.Host != "www.icloud.com" || redirect.DomainToUse != "iCloud.com" {
		t.Fatalf("redirect = %+v, want www.icloud.com", redirect)
	}

	session = &appleAuthSession{
		Endpoints:      appleAuthEndpointsForHost("www.icloud.com.cn"),
		AccountCountry: "CHN",
	}
	if _, ok := session.redirectForAccountCountry(); ok {
		t.Fatal("redirectForAccountCountry returned ok=true for matching China host")
	}
}

func TestAppleTransientNetworkErrorDetection(t *testing.T) {
	if !isAppleTransientNetworkError(&url.Error{Op: "Post", URL: "https://setup.icloud.com/setup/ws/1/accountLogin", Err: io.EOF}) {
		t.Fatal("EOF url error should be transient")
	}
	if !isAppleTransientNetworkError(fmt.Errorf("net/http: timeout awaiting response headers")) {
		t.Fatal("timeout should be transient")
	}
	if isAppleTransientNetworkError(errCode("apple_protocol_http_error", "Apple 协议 HTTP 401", true)) {
		t.Fatal("HTTP business error should not be transient")
	}
}

func TestRetryAppleTransientRetriesEOF(t *testing.T) {
	attempts := 0
	err := retryAppleTransient(t.Context(), func() error {
		attempts++
		if attempts < 2 {
			return io.EOF
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestCookieHeaderFiltersByDomainAndExpiry(t *testing.T) {
	cookies := []SessionCookie{
		{Name: "ok", Value: "1", Domain: ".icloud.com.cn", Path: "/"},
		{Name: "other", Value: "2", Domain: ".example.com", Path: "/"},
		{Name: "expired", Value: "3", Domain: ".icloud.com.cn", Path: "/", Expires: 1},
	}
	got := cookieHeader(cookies, "https://p213-maildomainws.icloud.com.cn/v1/hme/generate")
	if got != "ok=1" {
		t.Fatalf("cookieHeader() = %q, want ok=1", got)
	}
}

func TestAppleDebugBodyRedactsSecrets(t *testing.T) {
	got := appleDebugBody([]byte(`{"apiKey":"secret-api","emailAddress":"alias@example.com","nested":{"sessionToken":"secret-token","forwardToEmail":"main@example.com"},"ok":true}`))
	if strings.Contains(got, "secret-api") || strings.Contains(got, "secret-token") || strings.Contains(got, "alias@example.com") || strings.Contains(got, "main@example.com") {
		t.Fatalf("debug body leaked secret: %s", got)
	}
	if !strings.Contains(got, "<redacted>") || !strings.Contains(got, `"ok":true`) {
		t.Fatalf("debug body = %s, want redacted secret and visible safe fields", got)
	}
}

func TestAppleAccountManageFingerprintUsesCapturedLocale(t *testing.T) {
	var info map[string]string
	if err := json.Unmarshal([]byte(appleAccountFDClientInfo("test-agent")), &info); err != nil {
		t.Fatal(err)
	}
	if info["U"] != "test-agent" || info["L"] != appleAccountManageLanguage || info["Z"] != "GMT+08:00" {
		t.Fatalf("fingerprint info = %#v, want zh/GMT+08:00", info)
	}
	if strings.TrimSpace(info["F"]) == "" {
		t.Fatalf("fingerprint info missing compressed fingerprint: %#v", info)
	}
}

func TestAppleAccountAPIErrorDoesNotTreatGenericHTTPAsAuthExpired(t *testing.T) {
	generic := appleAccountAPIError(http.StatusUnauthorized, []byte(`<html><body>401 Unauthorized</body></html>`), "测试阶段")
	if isCodedError(generic, "apple_account_auth_failed") {
		t.Fatalf("HTML 401 classified as auth failed: %v", generic)
	}
	if !isCodedError(generic, "apple_account_api_failed") {
		t.Fatalf("HTML 401 = %v, want apple_account_api_failed so WAF pages do not fill keepalive strikes", generic)
	}

	expired := appleAccountAPIError(http.StatusUnauthorized, []byte(`{"service_errors":[{"message":"authentication_failed"}]}`), "测试阶段")
	if !isCodedError(expired, "apple_account_auth_failed") {
		t.Fatalf("explicit auth error = %v, want apple_account_auth_failed", expired)
	}

	serverErr := appleAccountAPIError(http.StatusInternalServerError, []byte(`<html><body>temporary</body></html>`), "测试阶段")
	if !isCodedError(serverErr, "apple_account_api_failed") {
		t.Fatalf("generic 500 = %v, want apple_account_api_failed", serverErr)
	}
}

func TestAppleAccountAPIErrorTreatsEmptyAndJSONUnauthorizedAsAuthExpired(t *testing.T) {
	empty := appleAccountAPIError(http.StatusUnauthorized, nil, "读取转发邮箱")
	if !isCodedError(empty, "apple_account_auth_failed") {
		t.Fatalf("empty 401 = %v, want apple_account_auth_failed", empty)
	}
	coded := appleAccountAPIError(http.StatusForbidden, []byte(`{"service_errors":[{"code":"-20101"}]}`), "刷新管理 token")
	if !isCodedError(coded, "apple_account_auth_failed") {
		t.Fatalf("json 403 without message = %v, want apple_account_auth_failed", coded)
	}
}

func TestLoadConfigPublicCodeSyncSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"mail_watcher_enabled":false,"mail_watcher_poll_ms":2500,"mail_watcher_fetch_limit":6,"mail_watcher_initial_fetch_limit":16,"mail_watcher_lookback_hours":12,"public_fast_sync_wait_ms":250,"public_sync_min_interval_ms":1500,"apple_account_keep_alive_enabled":true,"apple_account_keep_alive_ms":123000}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MailWatcherEnabled {
		t.Fatal("mail watcher enabled = true, want false from config")
	}
	if cfg.MailWatcherPollMS != 2500 || cfg.MailWatcherFetchLimit != 6 || cfg.MailWatcherInitialFetchLimit != 16 || cfg.MailWatcherLookbackHours != 12 {
		t.Fatalf("mail watcher settings = poll:%d fetch:%d initial:%d lookback:%d, want 2500/6/16/12", cfg.MailWatcherPollMS, cfg.MailWatcherFetchLimit, cfg.MailWatcherInitialFetchLimit, cfg.MailWatcherLookbackHours)
	}
	if cfg.PublicFastSyncWaitMS != 250 || cfg.PublicSyncMinIntervalMS != 1500 {
		t.Fatalf("public sync settings = fast:%d min:%d, want 250/1500", cfg.PublicFastSyncWaitMS, cfg.PublicSyncMinIntervalMS)
	}
	if !cfg.AppleAccountKeepAliveEnabled || cfg.AppleAccountKeepAliveMS != 123000 {
		t.Fatalf("apple account keepalive settings = enabled:%t ms:%d, want true/123000", cfg.AppleAccountKeepAliveEnabled, cfg.AppleAccountKeepAliveMS)
	}
}

func TestAppleAccountOperationGateSerializesSameAccount(t *testing.T) {
	release, err := acquireAppleAccountOperationGate(context.Background(), "test-owner:test-account")
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = acquireAppleAccountOperationGate(ctx, "test-owner:test-account")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second gate error = %v, want context deadline", err)
	}
}

func TestICloudEndpointAddsProtocolQuery(t *testing.T) {
	client := NewICloudClient()
	got, err := client.endpoint(ICloudSession{
		PremiumMailBaseURL: "https://p213-maildomainws.icloud.com.cn:443",
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
	}, "/v1/hme/generate")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"https://p213-maildomainws.icloud.com.cn:443/v1/hme/generate?",
		"clientBuildNumber=build",
		"clientMasteringNumber=master",
		"clientId=cid",
		"dsid=123",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("endpoint %q missing %q", got, want)
		}
	}
}

func TestMailGatewayBaseURLFallback(t *testing.T) {
	got, err := mailGatewayBaseURL(ICloudSession{MailBaseURL: "https://p213-mailws.icloud.com.cn:443"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://p213-mccgateway.icloud.com.cn:443" {
		t.Fatalf("mailGatewayBaseURL() = %q", got)
	}

	got, err = mailGatewayBaseURL(ICloudSession{PremiumMailBaseURL: "https://p213-maildomainws.icloud.com.cn:443"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://p213-mccgateway.icloud.com.cn:443" {
		t.Fatalf("mailGatewayBaseURL() from premium = %q", got)
	}
}

func TestICloudClientMoveRemoteMessagesToTrashAndEmptyTrash(t *testing.T) {
	var sawMove bool
	var sawDestroy bool
	client := &ICloudClient{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		response := `{}`
		switch r.URL.Path {
		case "/mailws2/v1/geqs/query":
			response = `{"domainObjects":[{"identifier":"31","name":"INBOX","messageCount":1},{"identifier":"53","name":"Deleted Messages","messageCount":1}]}`
		case "/mailws2/v1/message/list":
			if strings.Contains(string(body), `"value":"31"`) {
				response = `{"domainObjects":[{"uid":7,"identifier":"msg-inbox","mboxRef":{"id":"31"}}]}`
			} else if strings.Contains(string(body), `"value":"53"`) {
				response = `{"domainObjects":[{"uid":7,"identifier":"msg-trash","mboxRef":{"id":"53"}}]}`
			}
		case "/mailws2/v1/email/set":
			if strings.Contains(string(body), `"batchUpdate"`) {
				sawMove = true
				response = `{"updated":{"msg-inbox":{"modseq":4}}}`
			} else if strings.Contains(string(body), `"destroy"`) {
				sawDestroy = true
				response = `{"destroyed":["msg-trash"]}`
			}
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(response)),
			Request:    r,
		}, nil
	})}}
	session := ICloudSession{
		MailGatewayBaseURL: "https://p39-mccgateway.icloud.com",
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com", Path: "/"}},
	}
	moved, err := client.MoveRemoteMessagesToTrash(t.Context(), session, []string{"icloud:INBOX:7", "local:bad"})
	if err != nil {
		t.Fatal(err)
	}
	if moved.MovedToTrash != 1 || moved.Skipped != 1 || !sawMove {
		t.Fatalf("moved = %+v sawMove=%v, want moved=1 skipped=1", moved, sawMove)
	}
	destroyed, err := client.EmptyTrash(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	if destroyed != 1 || !sawDestroy {
		t.Fatalf("destroyed=%d sawDestroy=%v, want 1", destroyed, sawDestroy)
	}
}

func TestPublicSessionIncludesLastCheckStatus(t *testing.T) {
	checkedAt := time.Date(2026, 6, 21, 23, 0, 0, 0, time.UTC)
	session := ICloudSession{
		SavedAt:           checkedAt.Add(-time.Hour),
		AppleID:           "user@example.com",
		DSID:              "1234567890",
		IsICloudPlus:      true,
		CanCreateHME:      true,
		Cookies:           []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com.cn", Path: "/"}},
		LastCheckedAt:     checkedAt,
		LastCheckOK:       false,
		LastStatusMessage: "最近检测失败：请重新登录",
	}
	got := publicSession(&session)
	if got.LastCheckedAt != formatTime(checkedAt) {
		t.Fatalf("LastCheckedAt = %q, want %q", got.LastCheckedAt, formatTime(checkedAt))
	}
	if got.LastCheckOK {
		t.Fatalf("LastCheckOK = true, want false")
	}
	if got.LastStatusMessage != session.LastStatusMessage {
		t.Fatalf("LastStatusMessage = %q, want %q", got.LastStatusMessage, session.LastStatusMessage)
	}
}

func TestPublicSessionSeparatesLoginStateKinds(t *testing.T) {
	appleOnly := publicSession(&ICloudSession{
		SavedAt: time.Now(),
		AppleID: "apple@example.com",
		DSID:    "123456",
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Scnt:   "scnt",
			APIKey: "api-key",
		}},
	})
	if !appleOnly.AppleAccountLoginSaved || !appleOnly.AppleAccountManageReady {
		t.Fatalf("apple account state not exposed: %+v", appleOnly)
	}
	if !appleOnly.ProviderConfigured {
		t.Fatalf("apple account manage state should expose provider as configured: %+v", appleOnly)
	}
	if appleOnly.ICloudWebLoginSaved || appleOnly.NeedsManualLogin {
		t.Fatalf("apple-only state mixed with iCloud web: %+v", appleOnly)
	}

	icloudOnly := publicSession(&ICloudSession{
		SavedAt:      time.Now(),
		AppleID:      "icloud@example.com",
		DSID:         "654321",
		IsICloudPlus: true,
		CanCreateHME: true,
		Cookies:      []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com", Path: "/"}},
	})
	if !icloudOnly.ICloudWebLoginSaved || !icloudOnly.ProviderConfigured {
		t.Fatalf("icloud web state not exposed: %+v", icloudOnly)
	}
	if icloudOnly.AppleAccountLoginSaved || icloudOnly.AppleAccountManageReady {
		t.Fatalf("icloud-only state mixed with apple account: %+v", icloudOnly)
	}
	if icloudOnly.AppleAccountNextRefreshAt != "" || icloudOnly.AppleAccountManageExpiresAt != "" {
		t.Fatalf("icloud-only state should not expose apple account refresh time: %+v", icloudOnly)
	}
}

func TestPublicSessionCountsNestedICloudWebCookies(t *testing.T) {
	got := publicSession(&ICloudSession{
		LoginStates: []LoginState{{
			Kind: LoginStateICloudWeb,
			Cookies: []SessionCookie{
				{Name: "session", Value: "cookie-value"},
				{Name: "x-apple-id-session-id", Value: "session-id"},
			},
		}},
	})
	if got.CookieCount != 2 {
		t.Fatalf("nested iCloud web CookieCount = %d, want 2", got.CookieCount)
	}
}

func TestPublicSessionExposesPerLoginStateCheckStatus(t *testing.T) {
	checkedAt := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	expiresAt := checkedAt.Add(15 * time.Minute)
	session := ICloudSession{
		SavedAt: time.Now(),
		AppleID: "state@example.com",
		LoginStates: []LoginState{
			{
				Kind:              LoginStateAppleAccount,
				Scnt:              "scnt",
				APIKey:            "api-key",
				LastCheckedAt:     checkedAt,
				LastCheckOK:       true,
				LastStatusMessage: "新接口登录态正常",
				ManageExpiresAt:   expiresAt,
			},
			{
				Kind:              LoginStateICloudWeb,
				Cookies:           []SessionCookie{{Name: "icloud", Value: "ok"}},
				LastCheckedAt:     checkedAt,
				LastCheckOK:       false,
				LastStatusMessage: "旧接口登录态异常",
			},
		},
	}
	got := publicSession(&session)
	if !got.AppleAccountLoginChecked || !got.AppleAccountLoginOK || got.AppleAccountLoginStatus != "登录态正常" {
		t.Fatalf("apple account status = checked:%t ok:%t text:%q", got.AppleAccountLoginChecked, got.AppleAccountLoginOK, got.AppleAccountLoginStatus)
	}
	wantNext := checkedAt.Add(appleAccountKeepAliveIntervalForSession(session, appleAccountKeepAliveDefaultInterval))
	if got.AppleAccountManageExpiresAt != formatTime(expiresAt) || got.AppleAccountNextRefreshAt != formatTime(wantNext) {
		t.Fatalf("apple account refresh times = next:%q expires:%q", got.AppleAccountNextRefreshAt, got.AppleAccountManageExpiresAt)
	}
	if !got.ICloudWebLoginChecked || got.ICloudWebLoginOK || got.ICloudWebLoginStatus != "登录态异常" {
		t.Fatalf("icloud web status = checked:%t ok:%t text:%q", got.ICloudWebLoginChecked, got.ICloudWebLoginOK, got.ICloudWebLoginStatus)
	}
}

func TestPublicSessionHidesAppleKeepAliveTimeWhenLoginStateFailed(t *testing.T) {
	checkedAt := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	got := publicSession(&ICloudSession{
		SavedAt: time.Now(),
		AppleID: "failed@example.com",
		LoginStates: []LoginState{{
			Kind:              LoginStateAppleAccount,
			Scnt:              "scnt",
			APIKey:            "api-key",
			LastCheckedAt:     checkedAt,
			LastCheckOK:       false,
			KeepAliveStopped:  true,
			LastStatusMessage: "新接口登录态异常",
		}},
	})
	if !got.AppleAccountLoginSaved || !got.AppleAccountLoginChecked || got.AppleAccountLoginOK {
		t.Fatalf("apple account failed state not exposed correctly: %+v", got)
	}
	if !got.AppleAccountKeepAliveStopped || got.AppleAccountKeepAliveRetrying {
		t.Fatalf("stopped keepalive flags = stopped:%t retrying:%t", got.AppleAccountKeepAliveStopped, got.AppleAccountKeepAliveRetrying)
	}
	if got.AppleAccountNextRefreshAt != "" {
		t.Fatalf("failed apple account state should not expose keepalive time: %+v", got)
	}
}

func TestPublicSessionExposesAppleKeepAliveRetrying(t *testing.T) {
	checkedAt := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	session := ICloudSession{
		SavedAt: time.Now(),
		AppleID: "retry@example.com",
		LoginStates: []LoginState{{
			Kind:               LoginStateAppleAccount,
			Scnt:               "scnt",
			APIKey:             "api-key",
			LastCheckedAt:      checkedAt,
			LastCheckOK:        false,
			KeepAliveFailCount: 1,
			LastStatusMessage:  "新接口保活：重试中",
		}},
	}
	got := publicSession(&session)
	if got.AppleAccountLoginOK || !got.AppleAccountKeepAliveRetrying || got.AppleAccountKeepAliveStopped {
		t.Fatalf("retrying keepalive flags = ok:%t retrying:%t stopped:%t", got.AppleAccountLoginOK, got.AppleAccountKeepAliveRetrying, got.AppleAccountKeepAliveStopped)
	}
	wantNext := checkedAt.Add(appleAccountKeepAliveIntervalForSession(session, appleAccountKeepAliveDefaultInterval))
	if got.AppleAccountNextRefreshAt != formatTime(wantNext) {
		t.Fatalf("retrying keepalive next refresh = %q, want %q", got.AppleAccountNextRefreshAt, formatTime(wantNext))
	}
}

func TestAppleAccountKeepAliveRoundSavesUpdatedState(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-keepalive"
	account, err := store.AddAccountForOwner(ownerID, "KeepAlive", "keepalive@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   "keepalive@example.com",
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:          LoginStateAppleAccount,
			Scnt:          "old-scnt",
			APIKey:        "old-key",
			LastCheckedAt: time.Now().Add(-time.Hour),
			LastCheckOK:   true,
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{AppleAccountKeepAliveEnabled: true, AppleAccountKeepAliveMS: 1000}, store, discardLogger())
	server, ok := handler.(*Server)
	if !ok {
		t.Fatalf("handler type = %T, want *Server", handler)
	}
	var calls int
	server.keepAliveAppleAccountState = func(ctx context.Context, state LoginState) (LoginState, error) {
		calls++
		state.Scnt = "kept-scnt"
		state.APIKey = "kept-key"
		markAppleAccountManageOK(&state)
		return state, nil
	}

	server.keepAliveAppleAccountRound(context.Background())

	if calls != 1 {
		t.Fatalf("keepalive calls = %d, want 1", calls)
	}
	got, ok := store.ICloudSessionForOwnerAccount(ownerID, account.ID)
	if !ok {
		t.Fatal("updated session not found")
	}
	state, ok := appleAccountLoginState(got)
	if !ok || state.Scnt != "kept-scnt" || state.APIKey != "kept-key" || !state.LastCheckOK {
		t.Fatalf("saved apple account state = %+v ok=%v, want updated keepalive state", state, ok)
	}
}

func TestAppleAccountKeepAliveWaitsForMailboxAccountOperation(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-keepalive-gate"
	account, err := store.AddAccountForOwner(ownerID, "KeepAlive gate", "keepalive-gate@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   "keepalive-gate@example.com",
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:          LoginStateAppleAccount,
			Scnt:          "old-scnt",
			APIKey:        "old-key",
			LastCheckedAt: time.Now().Add(-time.Hour),
			LastCheckOK:   true,
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{AppleAccountKeepAliveEnabled: true, AppleAccountKeepAliveMS: 1000}, store, discardLogger()).(*Server)
	entered := make(chan struct{})
	handler.keepAliveAppleAccountState = func(ctx context.Context, state LoginState) (LoginState, error) {
		close(entered)
		return state, nil
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(context.Background(), mailboxAccountOperationKey(ownerID, account.ID))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		handler.keepAliveAppleAccountRound(context.Background())
		close(done)
	}()

	select {
	case <-entered:
		releaseAccountOperation()
		t.Fatal("Apple Account keepalive ran while the mailbox account operation was held")
	case <-time.After(100 * time.Millisecond):
	}
	releaseAccountOperation()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Apple Account keepalive did not resume after the mailbox account operation was released")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Apple Account keepalive round did not finish")
	}
}

func TestAppleAccountKeepAliveUsesSessionStateAfterGateWait(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-keepalive-fresh"
	account, err := store.AddAccountForOwner(ownerID, "KeepAlive fresh", "keepalive-fresh@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	initial := ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   account.AppleID,
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:          LoginStateAppleAccount,
			Scnt:          "stale-scnt",
			APIKey:        "stale-key",
			LastCheckedAt: time.Now().Add(-time.Hour),
			LastCheckOK:   true,
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, initial); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{AppleAccountKeepAliveEnabled: true, AppleAccountKeepAliveMS: 1000}, store, discardLogger()).(*Server)
	seen := make(chan string, 1)
	handler.keepAliveAppleAccountState = func(ctx context.Context, state LoginState) (LoginState, error) {
		seen <- state.APIKey
		return state, nil
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(ownerID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		handler.keepAliveAppleAccountRound(context.Background())
		close(done)
	}()

	select {
	case <-seen:
		releaseAccountOperation()
		t.Fatal("keepalive provider ran before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}

	fresh := cloneICloudSession(initial)
	fresh.LoginStates[0].Scnt = "fresh-scnt"
	fresh.LoginStates[0].APIKey = "fresh-key"
	if err := store.SaveICloudSessionForOwner(ownerID, fresh); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case got := <-seen:
		if got != "fresh-key" {
			t.Fatalf("keepalive provider API key = %q, want fresh-key", got)
		}
	case <-time.After(time.Second):
		t.Fatal("keepalive provider was not called")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("keepalive round did not finish")
	}
}

func TestICloudSessionCheckWaitsForMailboxAccountOperation(t *testing.T) {
	store := newTestStore(t)
	ownerID := ""
	account, err := store.AddAccountForOwner(ownerID, "Session check gate", "session-check-gate@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   "session-check-gate@example.com",
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:              LoginStateICloudIMAP,
			IMAPEmail:         "session-check-gate@example.com",
			IMAPAppPassword:   "app-password",
			IMAPHost:          defaultICloudIMAPHost,
			IMAPPort:          defaultICloudIMAPPort,
			LastCheckedAt:     time.Now().Add(-time.Hour),
			LastCheckOK:       true,
			LastStatusMessage: "取码登录正常",
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	entered := make(chan struct{})
	check := func(ctx context.Context, email, appPassword string) error {
		close(entered)
		return nil
	}
	handler.checkIMAPLogin = check
	handler.checkIMAPLoginWithProxy = func(ctx context.Context, email, appPassword, proxyURL string) error {
		return check(ctx, email, appPassword)
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(context.Background(), mailboxAccountOperationKey(ownerID, account.ID))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/session/check", strings.NewReader(`{"account_id":"`+account.ID+`"}`))
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.handleCheckICloudSession(rr, req)
		close(done)
	}()

	select {
	case <-entered:
		releaseAccountOperation()
		t.Fatal("iCloud session check ran while the mailbox account operation was held")
	case <-time.After(100 * time.Millisecond):
	}
	releaseAccountOperation()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("iCloud session check did not resume after the mailbox account operation was released")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("iCloud session check did not finish")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("iCloud session check status = %d body=%s, want 200", rr.Code, rr.Body.String())
	}
}

func TestICloudSessionCheckUsesSessionAfterGateWait(t *testing.T) {
	store := newTestStore(t)
	ownerID := ""
	account, err := store.AddAccountForOwnerWithProxy(ownerID, "Session check fresh", "session-check-fresh@example.com", "", "http://proxy-old:8080")
	if err != nil {
		t.Fatal(err)
	}
	session := testIMAPSession(ownerID, account.ID, account.AppleID)
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	seenProxy := make(chan string, 1)
	handler.checkIMAPLoginWithProxy = func(ctx context.Context, email, appPassword, proxyURL string) error {
		seenProxy <- proxyURL
		return nil
	}
	handler.checkIMAPLogin = func(ctx context.Context, email, appPassword string) error {
		t.Fatal("proxy-aware IMAP checker should be used")
		return nil
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(ownerID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/session/check", strings.NewReader(
		fmt.Sprintf(`{"account_id":%q}`, account.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.handleCheckICloudSession(rr, req)
		close(done)
	}()

	select {
	case <-seenProxy:
		releaseAccountOperation()
		t.Fatal("iCloud session check ran before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := store.UpdateAccountProxyForOwner(ownerID, account.ID, "http://proxy-fresh:8080"); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case got := <-seenProxy:
		if got != "http://proxy-fresh:8080" {
			t.Fatalf("session check proxy = %q, want fresh proxy", got)
		}
	case <-time.After(time.Second):
		t.Fatal("session check did not call the IMAP checker")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session check did not finish")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("session check status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestICloudIMAPLoginCheckWaitsForMailboxAccountOperation(t *testing.T) {
	store := newTestStore(t)
	ownerID := ""
	account, err := store.AddAccountForOwner(ownerID, "IMAP check gate", "imap-check-gate@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	session := ICloudSession{
		AccountID: account.ID,
		AppleID:   "imap-check-gate@example.com",
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:              LoginStateICloudIMAP,
			IMAPEmail:         "imap-check-gate@example.com",
			IMAPAppPassword:   "app-password",
			IMAPHost:          defaultICloudIMAPHost,
			IMAPPort:          defaultICloudIMAPPort,
			LastCheckedAt:     time.Now().Add(-time.Hour),
			LastCheckOK:       true,
			LastStatusMessage: "取码登录正常",
		}},
	}
	if err := store.SaveICloudSession(session); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	entered := make(chan struct{})
	check := func(ctx context.Context, email, appPassword string) error {
		close(entered)
		return nil
	}
	handler.checkIMAPLogin = check
	handler.checkIMAPLoginWithProxy = func(ctx context.Context, email, appPassword, proxyURL string) error {
		return check(ctx, email, appPassword)
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(context.Background(), mailboxAccountOperationKey(ownerID, account.ID))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/check", strings.NewReader(`{"account_id":"`+account.ID+`"}`))
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.handleCheckICloudIMAPLogin(rr, req)
		close(done)
	}()

	select {
	case <-entered:
		releaseAccountOperation()
		t.Fatal("iCloud IMAP login check ran while the mailbox account operation was held")
	case <-time.After(100 * time.Millisecond):
	}
	releaseAccountOperation()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("iCloud IMAP login check did not resume after the mailbox account operation was released")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("iCloud IMAP login check did not finish")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("iCloud IMAP login check status = %d body=%s, want 200", rr.Code, rr.Body.String())
	}
}

func TestICloudIMAPLoginCheckUsesSessionAfterGateWait(t *testing.T) {
	store := newTestStore(t)
	ownerID := ""
	account, err := store.AddAccountForOwnerWithProxy(ownerID, "IMAP check fresh", "imap-check-fresh@example.com", "", "http://proxy-old:8080")
	if err != nil {
		t.Fatal(err)
	}
	session := testIMAPSession(ownerID, account.ID, account.AppleID)
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	seenProxy := make(chan string, 1)
	handler.checkIMAPLoginWithProxy = func(ctx context.Context, email, appPassword, proxyURL string) error {
		seenProxy <- proxyURL
		return nil
	}
	handler.checkIMAPLogin = func(ctx context.Context, email, appPassword string) error {
		t.Fatal("proxy-aware IMAP checker should be used")
		return nil
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(ownerID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/check", strings.NewReader(
		fmt.Sprintf(`{"account_id":%q}`, account.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.handleCheckICloudIMAPLogin(rr, req)
		close(done)
	}()

	select {
	case <-seenProxy:
		releaseAccountOperation()
		t.Fatal("IMAP login check ran before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := store.UpdateAccountProxyForOwner(ownerID, account.ID, "http://proxy-fresh:8080"); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case got := <-seenProxy:
		if got != "http://proxy-fresh:8080" {
			t.Fatalf("IMAP login check proxy = %q, want fresh proxy", got)
		}
	case <-time.After(time.Second):
		t.Fatal("IMAP login check did not call the checker")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("IMAP login check did not finish")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("IMAP login check status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSaveICloudIMAPLoginWaitsForMailboxAccountOperation(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-imap-save-gate"
	account, err := store.AddAccountForOwner(ownerID, "IMAP save gate", "imap-save-gate@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	entered := make(chan struct{})
	handler.checkIMAPLogin = func(ctx context.Context, email, appPassword string) error {
		close(entered)
		return nil
	}
	handler.checkIMAPLoginWithProxy = func(ctx context.Context, email, appPassword, proxyURL string) error {
		return handler.checkIMAPLogin(ctx, email, appPassword)
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(context.Background(), mailboxAccountOperationKey(ownerID, account.ID))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/save", strings.NewReader(
		`{"account_id":"`+account.ID+`","email":"imap-save-gate@example.com","app_password":"app-password"}`,
	))
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.handleSaveICloudIMAPLogin(rr, req)
		close(done)
	}()

	select {
	case <-entered:
		releaseAccountOperation()
		t.Fatal("iCloud IMAP login save ran while the mailbox account operation was held")
	case <-time.After(100 * time.Millisecond):
	}
	releaseAccountOperation()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("iCloud IMAP login save did not resume after the mailbox account operation was released")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("iCloud IMAP login save did not finish")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("iCloud IMAP login save status = %d body=%s, want 200", rr.Code, rr.Body.String())
	}
}

func TestSaveICloudIMAPLoginUsesAccountProxyAfterGateWait(t *testing.T) {
	store := newTestStore(t)
	ownerID := ""
	account, err := store.AddAccountForOwnerWithProxy(ownerID, "IMAP save fresh", "imap-save-fresh@example.com", "", "http://proxy-old:8080")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	seenProxy := make(chan string, 1)
	handler.checkIMAPLoginWithProxy = func(ctx context.Context, email, appPassword, proxyURL string) error {
		seenProxy <- proxyURL
		return nil
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(ownerID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/save", strings.NewReader(
		fmt.Sprintf(`{"account_id":%q,"email":%q,"app_password":"app-password"}`, account.ID, account.AppleID),
	))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.handleSaveICloudIMAPLogin(rr, req)
		close(done)
	}()

	select {
	case <-seenProxy:
		releaseAccountOperation()
		t.Fatal("IMAP login save ran before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := store.UpdateAccountProxyForOwner(ownerID, account.ID, "http://proxy-fresh:8080"); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case got := <-seenProxy:
		if got != "http://proxy-fresh:8080" {
			t.Fatalf("IMAP login save proxy = %q, want fresh proxy", got)
		}
	case <-time.After(time.Second):
		t.Fatal("IMAP login save did not call the checker")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("IMAP login save did not finish")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("IMAP login save status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAppleAccountKeepAliveRoundSkipsFailedLoginState(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-keepalive-failed"
	account, err := store.AddAccountForOwner(ownerID, "KeepAliveFailed", "failed@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   "failed@example.com",
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:              LoginStateAppleAccount,
			Scnt:              "scnt",
			APIKey:            "api-key",
			LastCheckedAt:     time.Now().Add(-time.Hour),
			LastCheckOK:       false,
			KeepAliveStopped:  true,
			LastStatusMessage: "新接口登录态异常",
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{AppleAccountKeepAliveEnabled: true, AppleAccountKeepAliveMS: 1000}, store, discardLogger())
	server, ok := handler.(*Server)
	if !ok {
		t.Fatalf("handler type = %T, want *Server", handler)
	}
	server.keepAliveAppleAccountState = func(ctx context.Context, state LoginState) (LoginState, error) {
		t.Fatal("stopped login state should not be kept alive")
		return state, nil
	}

	server.keepAliveAppleAccountRound(context.Background())
}

func TestAppleAccountKeepAliveRoundSkipsLegacyFailedLoginStateWithoutRetryStreak(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-keepalive-legacy"
	account, err := store.AddAccountForOwner(ownerID, "KeepAliveLegacy", "legacy@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   "legacy@example.com",
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:              LoginStateAppleAccount,
			Scnt:              "scnt",
			APIKey:            "api-key",
			LastCheckedAt:     time.Now().Add(-time.Hour),
			LastCheckOK:       false,
			LastStatusMessage: "新接口登录态异常",
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{AppleAccountKeepAliveEnabled: true, AppleAccountKeepAliveMS: 1000}, store, discardLogger())
	server, ok := handler.(*Server)
	if !ok {
		t.Fatalf("handler type = %T, want *Server", handler)
	}
	server.keepAliveAppleAccountState = func(ctx context.Context, state LoginState) (LoginState, error) {
		t.Fatal("legacy failed login state without retry streak should not be kept alive")
		return state, nil
	}

	server.keepAliveAppleAccountRound(context.Background())
}

func TestAppleAccountKeepAliveRoundRetriesFailedButNotStoppedState(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-keepalive-retry"
	account, err := store.AddAccountForOwner(ownerID, "KeepAliveRetry", "retry@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   "retry@example.com",
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:               LoginStateAppleAccount,
			Scnt:               "old-scnt",
			APIKey:             "old-key",
			LastCheckedAt:      time.Now().Add(-time.Hour),
			LastCheckOK:        false,
			KeepAliveFailCount: 1,
			LastStatusMessage:  "新接口保活：重试中",
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{AppleAccountKeepAliveEnabled: true, AppleAccountKeepAliveMS: 1000}, store, discardLogger())
	server, ok := handler.(*Server)
	if !ok {
		t.Fatalf("handler type = %T, want *Server", handler)
	}
	var calls int
	server.keepAliveAppleAccountState = func(ctx context.Context, state LoginState) (LoginState, error) {
		calls++
		state.Scnt = "retry-scnt"
		state.APIKey = "retry-key"
		state.LastCheckOK = false
		state.KeepAliveFailCount = 2
		state.LastStatusMessage = "新接口保活：重试中"
		return state, errCode("apple_account_keepalive_retrying", "新接口保活重试中", true)
	}

	server.keepAliveAppleAccountRound(context.Background())

	if calls != 1 {
		t.Fatalf("keepalive calls = %d, want 1", calls)
	}
	got, ok := store.ICloudSessionForOwnerAccount(ownerID, account.ID)
	if !ok {
		t.Fatal("updated session not found")
	}
	state, ok := appleAccountLoginState(got)
	if !ok || state.Scnt != "retry-scnt" || state.APIKey != "retry-key" || state.KeepAliveFailCount != 2 || state.KeepAliveStopped || state.LastCheckOK {
		t.Fatalf("saved retrying apple account state = %+v ok=%v", state, ok)
	}
}

func TestAppleAccountKeepAliveRoundStopsAfterMaxAuthFails(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-keepalive-stop"
	account, err := store.AddAccountForOwner(ownerID, "KeepAliveStop", "stop@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   "stop@example.com",
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:               LoginStateAppleAccount,
			Scnt:               "old-scnt",
			APIKey:             "old-key",
			LastCheckedAt:      time.Now().Add(-time.Hour),
			LastCheckOK:        false,
			KeepAliveFailCount: 2,
			LastStatusMessage:  "新接口保活：重试中",
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{AppleAccountKeepAliveEnabled: true, AppleAccountKeepAliveMS: 1000}, store, discardLogger())
	server, ok := handler.(*Server)
	if !ok {
		t.Fatalf("handler type = %T, want *Server", handler)
	}
	server.keepAliveAppleAccountState = func(ctx context.Context, state LoginState) (LoginState, error) {
		state.Scnt = "dead-scnt"
		state.LastCheckOK = false
		state.KeepAliveFailCount = 3
		state.KeepAliveStopped = true
		state.LastStatusMessage = "新接口登录态异常：管理态已失效"
		return state, errCode("apple_account_auth_failed", "Apple Account 管理态已失效，请重新协议登录", true)
	}

	server.keepAliveAppleAccountRound(context.Background())

	got, ok := store.ICloudSessionForOwnerAccount(ownerID, account.ID)
	if !ok {
		t.Fatal("updated session not found")
	}
	state, ok := appleAccountLoginState(got)
	if !ok || state.Scnt != "dead-scnt" || !state.KeepAliveStopped || state.KeepAliveFailCount != 3 || state.LastCheckOK {
		t.Fatalf("saved stopped apple account state = %+v ok=%v", state, ok)
	}
	if appleAccountKeepAliveEligible(got) {
		t.Fatal("stopped login state should leave the keepalive queue")
	}
}

func TestAppleAccountKeepAliveRoundIgnoresNetworkError(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-keepalive-net"
	account, err := store.AddAccountForOwner(ownerID, "KeepAliveNet", "net@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   "net@example.com",
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:          LoginStateAppleAccount,
			Scnt:          "live-scnt",
			APIKey:        "live-key",
			LastCheckedAt: time.Now().Add(-time.Hour),
			LastCheckOK:   true,
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{AppleAccountKeepAliveEnabled: true, AppleAccountKeepAliveMS: 1000}, store, discardLogger())
	server, ok := handler.(*Server)
	if !ok {
		t.Fatalf("handler type = %T, want *Server", handler)
	}
	server.keepAliveAppleAccountState = func(ctx context.Context, state LoginState) (LoginState, error) {
		return state, context.DeadlineExceeded
	}

	server.keepAliveAppleAccountRound(context.Background())

	got, ok := store.ICloudSessionForOwnerAccount(ownerID, account.ID)
	if !ok {
		t.Fatal("session not found")
	}
	state, ok := appleAccountLoginState(got)
	if !ok || state.Scnt != "live-scnt" || !state.LastCheckOK || state.KeepAliveFailCount != 0 || state.KeepAliveStopped {
		t.Fatalf("network error should not mark apple account dead: %+v ok=%v", state, ok)
	}
	if !state.LastCheckedAt.After(session.LoginStates[0].LastCheckedAt) {
		t.Fatalf("network error should still postpone the next keepalive: last=%v previous=%v", state.LastCheckedAt, session.LoginStates[0].LastCheckedAt)
	}
}

func TestAppleAccountKeepAliveRoundSavesRefreshedCookiesOnTransientError(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-keepalive-transient"
	account, err := store.AddAccountForOwner(ownerID, "KeepAliveTransient", "transient@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	previousCheck := time.Now().Add(-time.Hour)
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   "transient@example.com",
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:          LoginStateAppleAccount,
			Scnt:          "live-scnt",
			APIKey:        "live-key",
			LastCheckedAt: previousCheck,
			LastCheckOK:   true,
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{AppleAccountKeepAliveEnabled: true, AppleAccountKeepAliveMS: 1000}, store, discardLogger())
	server, ok := handler.(*Server)
	if !ok {
		t.Fatalf("handler type = %T, want *Server", handler)
	}
	server.keepAliveAppleAccountState = func(ctx context.Context, state LoginState) (LoginState, error) {
		state.Scnt = "refreshed-scnt"
		state.APIKey = "refreshed-key"
		return state, errCode("apple_account_api_failed", "Apple Account 接口失败；阶段：读取转发邮箱；HTTP 500", true)
	}

	server.keepAliveAppleAccountRound(context.Background())

	got, ok := store.ICloudSessionForOwnerAccount(ownerID, account.ID)
	if !ok {
		t.Fatal("session not found")
	}
	state, ok := appleAccountLoginState(got)
	if !ok || state.Scnt != "refreshed-scnt" || state.APIKey != "refreshed-key" || !state.LastCheckOK || state.KeepAliveFailCount != 0 || state.KeepAliveStopped {
		t.Fatalf("transient keepalive should keep health flags and write refreshed credentials: %+v ok=%v", state, ok)
	}
	if !state.LastCheckedAt.After(previousCheck) {
		t.Fatalf("transient keepalive should postpone the next round: last=%v previous=%v", state.LastCheckedAt, previousCheck)
	}
}

func TestAppleAccountKeepAliveTimeoutAllowsRescuePath(t *testing.T) {
	if appleAccountKeepAliveTimeout != 60*time.Second {
		t.Fatalf("keepalive timeout = %s, want 60s", appleAccountKeepAliveTimeout)
	}
}

func TestNewICloudKeepAliveClientDefersTimeoutToContext(t *testing.T) {
	general := NewICloudClient()
	if general.client == nil || general.client.Timeout != 30*time.Second {
		t.Fatalf("general iCloud client timeout = %v, want 30s", general.client)
	}
	keepAlive := newICloudKeepAliveClient()
	if keepAlive.client == nil || keepAlive.client.Timeout != 0 {
		t.Fatalf("keepalive client timeout = %v, want 0 so the 60s context bounds the whole rescue round", keepAlive.client)
	}
}

func TestLoginCheckTimeoutsAreIndependent(t *testing.T) {
	if appleAccountKeepAliveTimeout != 60*time.Second {
		t.Fatalf("apple check timeout = %s, want 60s", appleAccountKeepAliveTimeout)
	}
	if icloudWebCheckTimeout != 30*time.Second {
		t.Fatalf("old-interface check timeout = %s, want 30s", icloudWebCheckTimeout)
	}
	if icloudIMAPCheckTimeout != 25*time.Second {
		t.Fatalf("IMAP check timeout = %s, want 25s", icloudIMAPCheckTimeout)
	}
	if appleAccountManageOperationTimeout != 2*appleAccountKeepAliveTimeout {
		t.Fatalf("manage operation timeout = %s, want 2x keepalive", appleAccountManageOperationTimeout)
	}
}

func TestAppleAccountListClientUsesKeepAliveHTTPTimeout(t *testing.T) {
	client, _, cancel := appleAccountListClientAndContext(t.Context(), string(mailboxCreateChannelAppleAccount))
	defer cancel()
	if client == nil || client.client == nil || client.client.Timeout != 0 {
		t.Fatalf("apple account list client timeout = %v, want 0", client)
	}
	webClient, _, webCancel := appleAccountListClientAndContext(t.Context(), string(mailboxCreateChannelICloudWeb))
	defer webCancel()
	if webClient == nil || webClient.client == nil || webClient.client.Timeout != 30*time.Second {
		t.Fatalf("icloud web list client timeout = %v, want 30s", webClient)
	}
}

func TestAppleAccountKeepAliveScanIntervalPollsBeforeBaseInterval(t *testing.T) {
	if got := appleAccountKeepAliveScanInterval(4 * time.Minute); got != 30*time.Second {
		t.Fatalf("scan interval for 4m = %s, want 30s", got)
	}
	if got := appleAccountKeepAliveScanInterval(12 * time.Second); got != 5*time.Second {
		t.Fatalf("scan interval for 12s = %s, want 5s floor", got)
	}
}

func TestPublicViewsExposeFullAppleID(t *testing.T) {
	store := newTestStore(t)
	server := &Server{cfg: Config{PublicBaseURL: "https://mail.example"}, store: store, logger: discardLogger()}
	account, err := store.AddAccountForOwner("owner-full", "Main", "full.user@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner("owner-full", account.ID, "Alias", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	gotAccount := server.publicAccount(account)
	if gotAccount.AppleID != "full.user@example.com" {
		t.Fatalf("public account AppleID = %q, want full email", gotAccount.AppleID)
	}

	gotMailbox := server.publicMailbox(httptest.NewRequest(http.MethodGet, "https://panel.example/", nil), mailbox)
	if gotMailbox.AccountAppleID != "full.user@example.com" {
		t.Fatalf("public mailbox account AppleID = %q, want full email", gotMailbox.AccountAppleID)
	}

	gotSession := publicSession(&ICloudSession{
		SavedAt:   time.Now(),
		AccountID: account.ID,
		AppleID:   "session.user@example.com",
	})
	if gotSession.AppleID != "session.user@example.com" {
		t.Fatalf("public session AppleID = %q, want full email", gotSession.AppleID)
	}

	matched := publicSessionForAppleID([]publicICloudSession{gotSession}, "session.user@example.com")
	if matched.AppleID != gotSession.AppleID {
		t.Fatalf("publicSessionForAppleID did not match full email: %+v", matched)
	}
}

func TestPublicAccountExposesFullProxyAndApplePassword(t *testing.T) {
	store := newTestStore(t)
	server := &Server{cfg: Config{PublicBaseURL: "https://mail.example"}, store: store, logger: discardLogger()}
	account, err := store.AddAccountForOwnerWithProxy("owner-full-proxy", "Main", "proxy.user@example.com", "", "http://user:pass@127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAccountApplePasswordForOwner("owner-full-proxy", account.ID, account.AppleID, "apple-secret"); err != nil {
		t.Fatal(err)
	}
	account, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account missing after password save")
	}

	gotAccount := server.publicAccount(account)
	if gotAccount.ProxyURL != "http://user:pass@127.0.0.1:7890" {
		t.Fatalf("public account proxy = %q, want full proxy with credentials", gotAccount.ProxyURL)
	}
	if gotAccount.ApplePassword != "" {
		t.Fatalf("default public account password = %q, want omitted", gotAccount.ApplePassword)
	}
	gotSecret := server.publicAccountWithSecrets(account)
	if gotSecret.ApplePassword != "apple-secret" {
		t.Fatalf("secret public account password = %q, want stored Apple password", gotSecret.ApplePassword)
	}
	if gotSecret.ProxyURL != "http://user:pass@127.0.0.1:7890" {
		t.Fatalf("secret public account proxy = %q, want full proxy with credentials", gotSecret.ProxyURL)
	}

	gotSession := publicSession(&ICloudSession{
		SavedAt:   time.Now(),
		AccountID: account.ID,
		AppleID:   account.AppleID,
		ProxyURL:  "socks5://user:pass@127.0.0.1:1080",
	})
	if gotSession.ProxyURL != "socks5://user:pass@127.0.0.1:1080" {
		t.Fatalf("public session proxy = %q, want full proxy with credentials", gotSession.ProxyURL)
	}
}

func TestSaveAccountApplePasswordForOwner(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwner("owner-password", "Main", "password.user@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAccountApplePasswordForOwner("owner-password", "", account.AppleID, "first-secret"); err != nil {
		t.Fatal(err)
	}
	got, ok := store.FindAccountByID(account.ID)
	if !ok || got.ApplePassword != "first-secret" {
		t.Fatalf("password by apple id = %+v ok=%t", got, ok)
	}
	if err := store.SaveAccountApplePasswordForOwner("owner-password", account.ID, "", "second-secret"); err != nil {
		t.Fatal(err)
	}
	got, ok = store.FindAccountByID(account.ID)
	if !ok || got.ApplePassword != "second-secret" {
		t.Fatalf("password by account id = %+v ok=%t", got, ok)
	}
	if err := store.SaveAccountApplePasswordForOwner("other-owner", account.ID, "", "third-secret"); !isCodedError(err, "account_forbidden") {
		t.Fatalf("other owner error = %#v, want account_forbidden", err)
	}
}

func TestAppleAccountLoginStartPersistsApplePassword(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "login-save-password", "panel-pass")
	account, err := store.AddAccountForOwnerWithProxy(user.ID, "Save password", "save-pass@example.com", "", "http://user:pass@10.0.0.8:1080")
	if err != nil {
		t.Fatal(err)
	}
	handler.startAppleAccountLogin = func(
		ctx context.Context,
		appleID, password string,
		pendingStore *appleAuthPendingStore,
		twoFactorMethod, proxyURL, ownerID string,
	) (appleAuthStartResult, error) {
		return appleAuthStartResult{
			Needs2FA:  true,
			PendingID: "pending-save-password",
			AppleID:   account.AppleID,
			ExpiresAt: time.Now().Add(time.Minute),
			Message:   "need 2fa",
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/apple-account/login/start", strings.NewReader(fmt.Sprintf(
		`{"apple_id":%q,"password":"apple-login-secret","account_id":%q,"proxy_url":"http://user:pass@10.0.0.8:1080"}`,
		account.AppleID,
		account.ID,
	)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login start status = %d body=%s", rr.Code, rr.Body.String())
	}
	updated, ok := store.FindAccountByID(account.ID)
	if !ok || updated.ApplePassword != "apple-login-secret" {
		t.Fatalf("account after login start = %+v ok=%t", updated, ok)
	}
	got := handler.publicAccount(updated)
	if got.ProxyURL != "http://user:pass@10.0.0.8:1080" {
		t.Fatalf("public proxy after login start = %q", got.ProxyURL)
	}
	if got.ApplePassword != "" {
		t.Fatalf("manage-style public account leaked password = %q", got.ApplePassword)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/accounts", nil)
	listReq.AddCookie(cookie)
	listRR := httptest.NewRecorder()
	handler.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list accounts status = %d body=%s", listRR.Code, listRR.Body.String())
	}
	var listed struct {
		Success  bool            `json:"success"`
		Accounts []publicAccount `json:"accounts"`
	}
	if err := json.NewDecoder(listRR.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if !listed.Success || len(listed.Accounts) != 1 {
		t.Fatalf("list accounts = %+v", listed)
	}
	if listed.Accounts[0].ApplePassword != "apple-login-secret" {
		t.Fatalf("GET /api/accounts password = %q", listed.Accounts[0].ApplePassword)
	}
	if listed.Accounts[0].ProxyURL != "http://user:pass@10.0.0.8:1080" {
		t.Fatalf("GET /api/accounts proxy = %q", listed.Accounts[0].ProxyURL)
	}

	manageReq := httptest.NewRequest(http.MethodGet, "/api/manage/data", nil)
	manageReq.AddCookie(cookie)
	manageRR := httptest.NewRecorder()
	handler.ServeHTTP(manageRR, manageReq)
	if manageRR.Code != http.StatusOK {
		t.Fatalf("manage data status = %d body=%s", manageRR.Code, manageRR.Body.String())
	}
	var manage struct {
		Success  bool            `json:"success"`
		Accounts []publicAccount `json:"accounts"`
	}
	if err := json.NewDecoder(manageRR.Body).Decode(&manage); err != nil {
		t.Fatal(err)
	}
	if !manage.Success || len(manage.Accounts) != 1 {
		t.Fatalf("manage data = %+v", manage)
	}
	if manage.Accounts[0].ApplePassword != "" {
		t.Fatalf("manage data leaked apple password = %q", manage.Accounts[0].ApplePassword)
	}
	if manage.Accounts[0].ProxyURL != "http://user:pass@10.0.0.8:1080" {
		t.Fatalf("manage data proxy = %q", manage.Accounts[0].ProxyURL)
	}
}

func TestICloudProtocolLoginStartPersistsApplePassword(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "protocol-save-password", "panel-pass")
	account, err := store.AddAccountForOwnerWithProxy(user.ID, "Protocol password", "protocol-pass@example.com", "", "socks5://user:pass@127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	handler.startICloudProtocolLogin = func(
		ctx context.Context,
		appleID, password, defaultHost, clientID string,
		pendingStore *appleAuthPendingStore,
		twoFactorMethod, proxyURL, ownerID string,
	) (appleAuthStartResult, error) {
		return appleAuthStartResult{
			Session: ICloudSession{
				AppleID:  account.AppleID,
				ProxyURL: "socks5://user:pass@127.0.0.1:1080",
			},
			AppleID: account.AppleID,
			Message: "login started",
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/start", strings.NewReader(fmt.Sprintf(
		`{"apple_id":%q,"password":"protocol-login-secret","account_id":%q}`,
		account.AppleID,
		account.ID,
	)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("protocol login start status = %d body=%s", rr.Code, rr.Body.String())
	}
	updated, ok := store.FindAccountByID(account.ID)
	if !ok || updated.ApplePassword != "protocol-login-secret" {
		t.Fatalf("account after protocol login start = %+v ok=%t", updated, ok)
	}
}

func TestSavePendingICloudSessionPersistsApplePassword(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	_, user := registerTestUser(t, handler, "pending-save-password", "user123")
	account, err := store.AddAccountForOwner(user.ID, "Apple", "pending-pass@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	err = handler.savePendingICloudSession(appleAuthPending{
		OwnerID:       user.ID,
		TargetOwnerID: user.ID,
		AccountID:     account.ID,
		Password:      "pending-apple-secret",
		ProxyExplicit: false,
	}, ICloudSession{AppleID: account.AppleID})
	if err != nil {
		t.Fatal(err)
	}
	updated, ok := store.FindAccountByID(account.ID)
	if !ok || updated.ApplePassword != "pending-apple-secret" {
		t.Fatalf("account after pending session save = %+v ok=%t", updated, ok)
	}
}

func TestSavePendingICloudSessionPersistsApplePasswordForNewAccount(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	_, user := registerTestUser(t, handler, "pending-new-password", "user123")

	err := handler.savePendingICloudSession(appleAuthPending{
		OwnerID:        user.ID,
		TargetOwnerID:  user.ID,
		TargetOwnerSet: true,
		Password:       "brand-new-secret",
		ProxyExplicit:  false,
	}, ICloudSession{AppleID: "brand-new@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	created, ok := store.FindAccountForOwnerAppleID(user.ID, "brand-new@example.com")
	if !ok || created.ApplePassword != "brand-new-secret" {
		t.Fatalf("new account after pending session save = %+v ok=%t", created, ok)
	}
}

func TestAppleAccountLoginStartKeepsPendingWhenPasswordPersistFails(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "login-password-persist-fail", "panel-pass")
	account, err := store.AddAccountForOwner(user.ID, "Persist fail", "persist-fail@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	handler.startAppleAccountLogin = func(
		ctx context.Context,
		appleID, password string,
		pendingStore *appleAuthPendingStore,
		twoFactorMethod, proxyURL, ownerID string,
	) (appleAuthStartResult, error) {
		pending, err := pendingStore.putForOwnerWithProxy(&appleAuthSession{AppleID: appleID, ProxyURL: proxyURL}, ownerID, strings.TrimSpace(proxyURL) != "")
		if err != nil {
			return appleAuthStartResult{}, err
		}
		return appleAuthStartResult{
			Needs2FA:  true,
			PendingID: pending.ID,
			AppleID:   appleID,
			ExpiresAt: pending.ExpiresAt,
			Message:   "need 2fa",
		}, nil
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	req := httptest.NewRequest(http.MethodPost, "/api/apple-account/login/start", strings.NewReader(fmt.Sprintf(
		`{"apple_id":%q,"password":"persist-fail-secret","account_id":%q}`,
		account.AppleID,
		account.ID,
	)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login start status = %d body=%s, want 200 when password persist fails", rr.Code, rr.Body.String())
	}
	var payload struct {
		Success   bool   `json:"success"`
		Needs2FA  bool   `json:"needs_2fa"`
		PendingID string `json:"pending_id"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Success || !payload.Needs2FA || strings.TrimSpace(payload.PendingID) == "" {
		t.Fatalf("login start payload = %+v, want pending_id after password persist failure", payload)
	}
}

func TestAppleAccount2FAHTTPPersistsPasswordAndExplicitProxy(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "login-2fa-http", "panel-pass")
	account, err := store.AddAccountForOwnerWithProxy(user.ID, "HTTP 2FA", "http-2fa@example.com", "", "http://old-user:old-pass@10.0.0.8:1080")
	if err != nil {
		t.Fatal(err)
	}
	handler.startAppleAccountLogin = func(
		ctx context.Context,
		appleID, password string,
		pendingStore *appleAuthPendingStore,
		twoFactorMethod, proxyURL, ownerID string,
	) (appleAuthStartResult, error) {
		pending, err := pendingStore.putForOwnerWithProxy(&appleAuthSession{AppleID: appleID, ProxyURL: proxyURL}, ownerID, strings.TrimSpace(proxyURL) != "")
		if err != nil {
			return appleAuthStartResult{}, err
		}
		return appleAuthStartResult{
			Needs2FA:  true,
			PendingID: pending.ID,
			AppleID:   appleID,
			ExpiresAt: pending.ExpiresAt,
			Message:   "need 2fa",
		}, nil
	}
	handler.submitAppleAccount2FA = func(ctx context.Context, pending appleAuthPending, code string, phoneNumber json.RawMessage) (ICloudSession, error) {
		if pending.Password != "http-2fa-secret" {
			t.Fatalf("pending password = %q, want http-2fa-secret", pending.Password)
		}
		if code != "123456" {
			t.Fatalf("2fa code = %q", code)
		}
		proxyURL := ""
		if pending.Session != nil {
			proxyURL = pending.Session.ProxyURL
		}
		return ICloudSession{AppleID: account.AppleID, ProxyURL: proxyURL}, nil
	}

	startReq := httptest.NewRequest(http.MethodPost, "/api/apple-account/login/start", strings.NewReader(fmt.Sprintf(
		`{"apple_id":%q,"password":"http-2fa-secret","account_id":%q,"proxy_url":"socks5://user:pass@127.0.0.1:1080"}`,
		account.AppleID,
		account.ID,
	)))
	startReq.Header.Set("Content-Type", "application/json")
	startReq.AddCookie(cookie)
	addClosureTestCSRF(startReq, cookie)
	startRR := httptest.NewRecorder()
	handler.ServeHTTP(startRR, startReq)
	if startRR.Code != http.StatusOK {
		t.Fatalf("login start status = %d body=%s", startRR.Code, startRR.Body.String())
	}
	var startPayload struct {
		Success   bool   `json:"success"`
		Needs2FA  bool   `json:"needs_2fa"`
		PendingID string `json:"pending_id"`
	}
	if err := json.NewDecoder(startRR.Body).Decode(&startPayload); err != nil {
		t.Fatal(err)
	}
	if !startPayload.Success || !startPayload.Needs2FA || startPayload.PendingID == "" {
		t.Fatalf("login start payload = %+v", startPayload)
	}
	afterStart, ok := store.FindAccountByID(account.ID)
	if !ok || afterStart.ApplePassword != "http-2fa-secret" {
		t.Fatalf("account after 2FA start = %+v ok=%t", afterStart, ok)
	}
	if afterStart.ProxyURL != "socks5://user:pass@127.0.0.1:1080" {
		t.Fatalf("account proxy after 2FA start = %q", afterStart.ProxyURL)
	}

	twoFAReq := httptest.NewRequest(http.MethodPost, "/api/apple-account/login/2fa", strings.NewReader(fmt.Sprintf(
		`{"pending_id":%q,"code":"123456"}`,
		startPayload.PendingID,
	)))
	twoFAReq.Header.Set("Content-Type", "application/json")
	twoFAReq.AddCookie(cookie)
	addClosureTestCSRF(twoFAReq, cookie)
	twoFARR := httptest.NewRecorder()
	handler.ServeHTTP(twoFARR, twoFAReq)
	if twoFARR.Code != http.StatusOK {
		t.Fatalf("2FA status = %d body=%s", twoFARR.Code, twoFARR.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/accounts", nil)
	listReq.AddCookie(cookie)
	listRR := httptest.NewRecorder()
	handler.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list accounts status = %d body=%s", listRR.Code, listRR.Body.String())
	}
	var listed struct {
		Success  bool            `json:"success"`
		Accounts []publicAccount `json:"accounts"`
	}
	if err := json.NewDecoder(listRR.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if !listed.Success || len(listed.Accounts) != 1 {
		t.Fatalf("list accounts = %+v", listed)
	}
	if listed.Accounts[0].ApplePassword != "http-2fa-secret" {
		t.Fatalf("GET /api/accounts password = %q", listed.Accounts[0].ApplePassword)
	}
	if listed.Accounts[0].ProxyURL != "socks5://user:pass@127.0.0.1:1080" {
		t.Fatalf("GET /api/accounts proxy = %q", listed.Accounts[0].ProxyURL)
	}
}

func TestPublicMailboxClearsAPIActiveAfterRemoteDeleteSucceeded(t *testing.T) {
	server := &Server{cfg: Config{PublicBaseURL: "https://mail.example"}, logger: discardLogger()}
	got := server.publicMailbox(httptest.NewRequest(http.MethodGet, "https://panel.example/", nil), Mailbox{
		ID:                 "mailbox-1",
		Email:              "alias@icloud.com",
		APIToken:           "secret-token",
		APIActive:          true,
		ICloudActive:       false,
		Status:             StatusDisabled,
		RemoteDeleteStatus: "succeeded",
	})
	if got.APIActive {
		t.Fatalf("public mailbox APIActive = true after remote delete succeeded, want false")
	}
	if got.RemoteDeleteStatus != "succeeded" {
		t.Fatalf("public mailbox remote delete status = %q, want succeeded", got.RemoteDeleteStatus)
	}
}

func TestStatusReturnsOwnerICloudSessionForAdminUser(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, adminUser := registerTestUser(t, handler, "admin", "admin123")
	if err := store.SaveICloudSessionForOwner(adminUser.ID, ICloudSession{
		SavedAt:       time.Now(),
		AppleID:       "admin@example.com",
		DSID:          "12345678908382",
		IsICloudPlus:  true,
		CanCreateHME:  true,
		Cookies:       []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com.cn", Path: "/"}},
		LastCheckOK:   true,
		LastCheckedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	_, peerUser := registerTestUser(t, handler, "status-peer", "user123")
	peerAccount, err := store.AddAccountForOwner(peerUser.ID, "Peer account", "peer@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(peerUser.ID, ICloudSession{
		SavedAt:       time.Now(),
		AppleID:       peerAccount.AppleID,
		AccountID:     peerAccount.ID,
		IsICloudPlus:  true,
		CanCreateHME:  true,
		Cookies:       []SessionCookie{{Name: "session", Value: "peer", Domain: ".icloud.com.cn", Path: "/"}},
		LastCheckOK:   true,
		LastCheckedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		ICloudSession  publicICloudSession   `json:"icloud_session"`
		ICloudSessions []publicICloudSession `json:"icloud_sessions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.ICloudSession.Saved || body.ICloudSession.CookieCount != 1 || !body.ICloudSession.ProviderConfigured {
		t.Fatalf("icloud session = %+v, want saved owner session", body.ICloudSession)
	}
	adminSessionID := body.ICloudSession.AccountID
	if strings.TrimSpace(adminSessionID) == "" {
		t.Fatalf("admin status session has no account id: %+v", body.ICloudSession)
	}
	if len(body.ICloudSessions) != 1 || body.ICloudSessions[0].AccountID != adminSessionID {
		t.Fatalf("home status sessions = %+v, want only admin session", body.ICloudSessions)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/status?owner_id=all", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("all-owner status = %d body=%s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.ICloudSessions) != 2 {
		t.Fatalf("all-owner status sessions = %+v, want both admin and peer sessions", body.ICloudSessions)
	}
	seen := map[string]struct{}{}
	for _, session := range body.ICloudSessions {
		seen[session.AccountID] = struct{}{}
	}
	for _, want := range []string{adminSessionID, peerAccount.ID} {
		if _, ok := seen[want]; !ok {
			t.Fatalf("all-owner status sessions = %+v, missing %q", body.ICloudSessions, want)
		}
	}
}

func TestICloudCreateLimitErrorIsClassified(t *testing.T) {
	err := iCloudAPIError("You have reached the limit of addresses you can create right now. Please try again later.")
	coded, ok := err.(codedError)
	if !ok {
		t.Fatalf("error type = %T, want codedError", err)
	}
	if coded.code != "icloud_hme_limit" || !coded.retryable {
		t.Fatalf("coded error = %+v, want icloud_hme_limit retryable", coded)
	}
	if !strings.Contains(err.Error(), "已达到当前隐私邮箱创建上限") {
		t.Fatalf("error = %q, want sanitized limit message", err.Error())
	}
	if strings.Contains(err.Error(), "You have reached the limit") {
		t.Fatalf("error leaked provider response: %q", err.Error())
	}
}

func TestAppleAccountAPIErrorIncludesStageHTTPWithoutRawBody(t *testing.T) {
	err := appleAccountAPIError(http.StatusNotFound, []byte("<html><body>not found</body></html>"), "生成候选隐私邮箱")
	coded, ok := err.(codedError)
	if !ok {
		t.Fatalf("error type = %T, want codedError", err)
	}
	if coded.code != "apple_account_api_failed" || !coded.retryable {
		t.Fatalf("coded error = %+v, want apple_account_api_failed retryable", coded)
	}
	message := err.Error()
	for _, want := range []string{"阶段：生成候选隐私邮箱", "HTTP 404"} {
		if !strings.Contains(message, want) {
			t.Fatalf("error = %q, want %q", message, want)
		}
	}
	if strings.Contains(message, "<html><body>not found</body></html>") {
		t.Fatalf("error leaked provider response: %q", message)
	}
}

func TestICloudClientAppleAccountGenerateEmptyOmitsRawBody(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			_, _ = w.Write([]byte(`{"unexpected":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	_, _, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt-current",
			APIKey:          "fresh-key",
			LastCheckedAt:   time.Now(),
			ManageExpiresAt: time.Now().Add(15 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "LAB", "")
	if err == nil {
		t.Fatal("expected error")
	}
	coded, ok := err.(codedError)
	if !ok || coded.code != "apple_account_generate_empty" {
		t.Fatalf("error = %#v, want apple_account_generate_empty", err)
	}
	message := err.Error()
	if !strings.Contains(message, "阶段：生成候选隐私邮箱") {
		t.Fatalf("error = %q, want stage", message)
	}
	if strings.Contains(message, `{"unexpected":true}`) {
		t.Fatalf("error leaked provider response: %q", message)
	}
	for _, want := range []string{"阶段：生成候选隐私邮箱"} {
		if !strings.Contains(message, want) {
			t.Fatalf("error = %q, want %q", message, want)
		}
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRetriesNetworkErrors(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	appleAccountManageBaseURL = "https://appleid.test"

	addAttempts := 0
	completeAttempts := 0
	client := &ICloudClient{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			addAttempts++
			if addAttempts < 3 {
				return nil, &url.Error{Op: "Post", URL: r.URL.String(), Err: context.DeadlineExceeded}
			}
			return appleAccountTestResponse(r, http.StatusOK, `{"emailAddress":"Retry.Alias@icloud.com"}`), nil
		case "PUT /account/manage/email/private/add/complete":
			completeAttempts++
			return appleAccountTestResponse(r, http.StatusOK, `{"emailAddress":"Retry.Alias@icloud.com","label":"LAB","note":"note","active":true}`), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})}}

	remote, _, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), appleAccountFreshSessionForTest(), "", "LAB", "note")
	if err != nil {
		t.Fatal(err)
	}
	if addAttempts != 3 {
		t.Fatalf("add attempts = %d, want 3", addAttempts)
	}
	if completeAttempts != 1 {
		t.Fatalf("complete attempts = %d, want 1", completeAttempts)
	}
	if remote.Email != "retry.alias@icloud.com" || remote.Origin != "APPLE_ACCOUNT" {
		t.Fatalf("remote = %+v, want retry alias from Apple Account", remote)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountDoesNotRetryHTTPError(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	appleAccountManageBaseURL = "https://appleid.test"

	addAttempts := 0
	client := &ICloudClient{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			addAttempts++
			return appleAccountTestResponse(r, http.StatusInternalServerError, `<html><body>temporary</body></html>`), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})}}

	_, _, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), appleAccountFreshSessionForTest(), "", "LAB", "note")
	if err == nil {
		t.Fatal("expected error")
	}
	if addAttempts != 1 {
		t.Fatalf("add attempts = %d, want 1", addAttempts)
	}
	if !isCodedError(err, "apple_account_api_failed") {
		t.Fatalf("error = %#v, want apple_account_api_failed", err)
	}
}

func appleAccountFreshSessionForTest() ICloudSession {
	now := time.Now()
	return ICloudSession{
		OwnerID:   "owner-test",
		AccountID: "account-test",
		AppleID:   "apple-test@example.com",
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt-current",
			APIKey:          "fresh-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(15 * time.Minute),
			LastCheckOK:     true,
			Origin:          appleAccountManageOrigin,
		}},
	}
}

func appleAccountTestResponse(r *http.Request, status int, body string) *http.Response {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    r,
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccount(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	tokenCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-Apple-I-Request-Context") != "ca" {
			t.Fatalf("request context = %q, want ca", r.Header.Get("X-Apple-I-Request-Context"))
		}
		if r.Header.Get("Origin") != "https://account.apple.com" {
			t.Fatalf("origin = %q, want account.apple.com", r.Header.Get("Origin"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			tokenCalls++
			if tokenCalls != 1 {
				t.Fatalf("unexpected token call %d", tokenCalls)
			}
			if r.Header.Get("X-Apple-Api-Key") != "" {
				t.Fatalf("token api key header = %q, want empty", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-token" {
				t.Fatalf("token scnt header = %q, want scnt-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-token")
			http.SetCookie(w, &http.Cookie{Name: "token-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("X-Apple-Api-Key") != "" {
				t.Fatalf("manage api key header = %q, want empty", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "token-cookie=ok") {
				t.Fatalf("manage cookie header = %q, want token response cookie", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("add api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("add scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			body, _ := io.ReadAll(r.Body)
			if strings.TrimSpace(string(body)) != "{}" {
				t.Fatalf("add body = %s, want {}", body)
			}
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","newToPrivateEmail":false,"exists":false,"type":"settings","active":false}`))
		case "PUT /account/manage/email/private/add/complete":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("complete api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-add" {
				t.Fatalf("complete scnt header = %q, want scnt-after-add", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-complete")
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["emailAddress"] != "Candidate.Alias@icloud.com" || body["label"] != "LAB" || body["note"] != "note" {
				t.Fatalf("complete body = %+v", body)
			}
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","label":"LAB","note":"note","id":"abc123","type":"settings","active":false}`))
		case "GET /account/manage/email/private/abc123.em":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("confirm api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-complete" {
				t.Fatalf("confirm scnt header = %q, want scnt-after-complete", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-confirm")
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","label":"LAB","note":"note","id":"abc123","forwardToEmail":"main@example.com","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Scnt:   "scnt-token",
			APIKey: "stale-key",
		}},
	}, "", "LAB", "note")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "candidate.alias@icloud.com" || remote.Label != "LAB" || remote.AnonymousID != "abc123" || !remote.IsActive || remote.ForwardToEmail != "main@example.com" || remote.Origin != "APPLE_ACCOUNT" {
		t.Fatalf("remote = %+v", remote)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/abc123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.Scnt != "scnt-after-confirm" || updatedState.APIKey != "account-key" {
		t.Fatalf("updated apple account state = %+v ok=%v, want refreshed scnt/api key", updatedState, ok)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountReusesFreshState(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token", "GET /account/manage":
			t.Fatalf("unexpected refresh request %s %s", r.Method, r.URL.Path)
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("add api key header = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-current" {
				t.Fatalf("add scnt header = %q, want scnt-current", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			_, _ = w.Write([]byte(`{"emailAddress":"Fresh.Alias@icloud.com","active":false}`))
		case "PUT /account/manage/email/private/add/complete":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("complete api key header = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-add" {
				t.Fatalf("complete scnt header = %q, want scnt-after-add", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-complete")
			_, _ = w.Write([]byte(`{"emailAddress":"Fresh.Alias@icloud.com","id":"fresh123","active":true}`))
		case "GET /account/manage/email/private/fresh123.em":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("confirm api key header = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-complete" {
				t.Fatalf("confirm scnt header = %q, want scnt-after-complete", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-confirm")
			_, _ = w.Write([]byte(`{"emailAddress":"Fresh.Alias@icloud.com","id":"fresh123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	checkedAt := time.Now()
	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt-current",
			APIKey:          "fresh-key",
			LastCheckedAt:   checkedAt,
			ManageExpiresAt: checkedAt.Add(15 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "fresh.alias@icloud.com" {
		t.Fatalf("remote email = %q, want fresh.alias@icloud.com", remote.Email)
	}
	wantPaths := []string{
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/fresh123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.Scnt != "scnt-after-confirm" || updatedState.APIKey != "fresh-key" || !updatedState.LastCheckOK || updatedState.LastCheckedAt.IsZero() || updatedState.LastCheckedAt.Before(checkedAt) {
		t.Fatalf("updated apple account state = %+v ok=%v, want reused fresh state marked ok", updatedState, ok)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRefreshesExpiredManageState(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("scnt") != "stale-scnt" {
				t.Fatalf("token scnt header = %q, want stale-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-token")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("add api key header = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("add scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			_, _ = w.Write([]byte(`{"emailAddress":"TTL.Alias@icloud.com","active":false}`))
		case "PUT /account/manage/email/private/add/complete":
			w.Header().Set("scnt", "scnt-after-complete")
			_, _ = w.Write([]byte(`{"emailAddress":"TTL.Alias@icloud.com","id":"ttl123","active":true}`))
		case "GET /account/manage/email/private/ttl123.em":
			w.Header().Set("scnt", "scnt-after-confirm")
			_, _ = w.Write([]byte(`{"emailAddress":"TTL.Alias@icloud.com","id":"ttl123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "stale-scnt",
			APIKey:          "stale-key",
			LastCheckedAt:   now.Add(-2 * time.Minute),
			ManageExpiresAt: now.Add(-30 * time.Second),
			LastCheckOK:     true,
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "ttl.alias@icloud.com" {
		t.Fatalf("remote email = %q, want ttl.alias@icloud.com", remote.Email)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/ttl123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.APIKey != "fresh-key" || updatedState.Scnt != "scnt-after-confirm" || !updatedState.LastCheckOK || !updatedState.ManageExpiresAt.After(now) {
		t.Fatalf("updated apple account state = %+v ok=%v, want refreshed TTL state", updatedState, ok)
	}
}

func TestICloudClientRefreshAppleAccountManageStateUsesBootstrapTTLWhenInitialTokenIsEmpty(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	tokenCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			tokenCalls++
			if tokenCalls == 1 {
				if r.Header.Get("scnt") != "start-scnt" {
					t.Fatalf("first token scnt header = %q, want start-scnt", r.Header.Get("scnt"))
				}
				w.Header().Set("scnt", "token-empty-scnt")
				_, _ = w.Write([]byte(`{}`))
				return
			}
			if r.Header.Get("scnt") != "" {
				t.Fatalf("second token scnt header = %q, want empty like browser refresh", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "token-refreshed-scnt")
			_, _ = w.Write([]byte(`{}`))
		case "GET /account/manage/section/privacy":
			if r.Header.Get("scnt") != "" {
				t.Fatalf("privacy page scnt header = %q, want empty", r.Header.Get("scnt"))
			}
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("scnt", "page-scnt")
			_, _ = w.Write([]byte(`<html></html>`))
		case "GET /bootstrap/portal":
			if r.Header.Get("scnt") != "" {
				t.Fatalf("bootstrap scnt header = %q, want empty", r.Header.Get("scnt"))
			}
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "token-refreshed-scnt" {
				t.Fatalf("manage scnt header = %q, want token-refreshed-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	state, err := client.RefreshAppleAccountManageState(t.Context(), LoginState{
		Kind:   LoginStateAppleAccount,
		Origin: ts.URL,
		Scnt:   "start-scnt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.APIKey != "account-key" || state.Scnt != "manage-scnt" || !state.ManageExpiresAt.After(now) {
		t.Fatalf("state = %+v, want api key, updated scnt and bootstrap TTL", state)
	}
	if state.LastCheckOK || state.KeepAliveFailCount != 0 {
		t.Fatalf("token refresh must not mark manage state healthy: %+v", state)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage/section/privacy",
		"GET /bootstrap/portal",
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestICloudClientKeepAliveAppleAccountManageStateTouchesRealManageAPI(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("scnt") != "start-scnt" {
				t.Fatalf("token scnt header = %q, want start-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "token-scnt" {
				t.Fatalf("manage scnt header = %q, want token-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "GET /account/manage/forwardemail":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("forwardemail api key = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "manage-scnt" {
				t.Fatalf("forwardemail scnt header = %q, want manage-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "touch-scnt")
			_, _ = w.Write([]byte(`{"forwardToEmail":"receiver@icloud.com"}`))
		case "POST /v2/jslogs":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("jslogs api key = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "touch-scnt" {
				t.Fatalf("jslogs scnt header = %q, want touch-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("X-Apple-ID-Session-Id", "jslog-session")
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	state, err := client.KeepAliveAppleAccountManageState(t.Context(), LoginState{
		Kind:      LoginStateAppleAccount,
		Origin:    ts.URL,
		Scnt:      "start-scnt",
		APIKey:    "old-key",
		SessionID: "old-session",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"GET /account/manage/forwardemail",
		"POST /v2/jslogs",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	if state.APIKey != "fresh-key" || state.Scnt != "touch-scnt" || state.SessionID != "jslog-session" || !state.LastCheckOK || state.LastCheckedAt.Before(now) {
		t.Fatalf("state = %+v, want touched real manage API state", state)
	}
	if state.KeepAliveFailCount != 0 || state.KeepAliveStopped {
		t.Fatalf("successful keepalive should clear retry flags: %+v", state)
	}
}

func TestICloudClientKeepAliveRecoversAfterForwardemailAuthFailure(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	forwardCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("scnt") == "start-scnt" {
				w.Header().Set("scnt", "token-scnt")
			} else if r.Header.Get("scnt") == "" {
				w.Header().Set("scnt", "recover-token-scnt")
			} else {
				t.Fatalf("unexpected token scnt header = %q", r.Header.Get("scnt"))
			}
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") == "token-scnt" {
				w.Header().Set("scnt", "manage-scnt")
				_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
				return
			}
			if r.Header.Get("scnt") == "recover-token-scnt" {
				w.Header().Set("scnt", "recover-manage-scnt")
				_, _ = w.Write([]byte(`{"apiKey":"recover-key"}`))
				return
			}
			t.Fatalf("unexpected manage scnt header = %q", r.Header.Get("scnt"))
		case "GET /account/manage/forwardemail":
			forwardCalls++
			if forwardCalls == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"service_errors":[{"message":"authentication_failed"}]}`))
				return
			}
			if r.Header.Get("X-Apple-Api-Key") != "recover-key" {
				t.Fatalf("recovered forwardemail api key = %q, want recover-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "recover-manage-scnt" {
				t.Fatalf("recovered forwardemail scnt = %q, want recover-manage-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "recover-touch-scnt")
			_, _ = w.Write([]byte(`{"forwardToEmail":"receiver@icloud.com"}`))
		case "GET /account/manage/section/privacy":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html></html>`))
		case "GET /bootstrap/portal":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "POST /v2/jslogs":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	state, err := client.KeepAliveAppleAccountManageState(t.Context(), LoginState{
		Kind:   LoginStateAppleAccount,
		Origin: ts.URL,
		Scnt:   "start-scnt",
		APIKey: "old-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"GET /account/manage/forwardemail",
		"GET /account/manage/section/privacy",
		"GET /bootstrap/portal",
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"GET /account/manage/forwardemail",
		"POST /v2/jslogs",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	if state.APIKey != "recover-key" || state.Scnt != "recover-touch-scnt" || !state.LastCheckOK || state.KeepAliveFailCount != 0 || state.KeepAliveStopped {
		t.Fatalf("recovered keepalive state = %+v", state)
	}
}

func TestICloudClientKeepAliveMarksRetryingAfterRescueStillFails(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/section/privacy":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html></html>`))
		case "GET /bootstrap/portal":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"service_errors":[{"message":"authentication_failed"}]}`))
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	state, err := client.keepAliveAppleAccountManageStateUnlocked(t.Context(), LoginState{
		Kind:   LoginStateAppleAccount,
		Origin: ts.URL,
		Scnt:   "start-scnt",
		APIKey: "old-key",
	})
	if !isCodedError(err, "apple_account_keepalive_retrying") {
		t.Fatalf("err = %v, want apple_account_keepalive_retrying", err)
	}
	if state.LastCheckOK || state.KeepAliveFailCount != 1 || state.KeepAliveStopped || state.LastStatusMessage != "新接口保活：重试中" {
		t.Fatalf("retrying keepalive state = %+v", state)
	}

	state, err = client.keepAliveAppleAccountManageStateUnlocked(t.Context(), state)
	if !isCodedError(err, "apple_account_keepalive_retrying") {
		t.Fatalf("second err = %v, want apple_account_keepalive_retrying", err)
	}
	if state.KeepAliveFailCount != 2 || state.KeepAliveStopped {
		t.Fatalf("second retrying state = %+v", state)
	}

	state, err = client.keepAliveAppleAccountManageStateUnlocked(t.Context(), state)
	if !isCodedError(err, "apple_account_auth_failed") {
		t.Fatalf("third err = %v, want apple_account_auth_failed", err)
	}
	if !state.KeepAliveStopped || state.KeepAliveFailCount != 3 || state.LastCheckOK {
		t.Fatalf("stopped keepalive state = %+v", state)
	}
}

func TestICloudClientKeepAliveCountsForwardemailAuthFailuresAcrossRounds(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("scnt", "token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "GET /account/manage/section/privacy":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html></html>`))
		case "GET /bootstrap/portal":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage/forwardemail":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"service_errors":[{"message":"authentication_failed"}]}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	state := LoginState{
		Kind:               LoginStateAppleAccount,
		Origin:             ts.URL,
		Scnt:               "start-scnt",
		APIKey:             "old-key",
		KeepAliveFailCount: 1,
		LastCheckOK:        false,
		LastStatusMessage:  "新接口保活：重试中",
	}
	state, err := client.keepAliveAppleAccountManageStateUnlocked(t.Context(), state)
	if !isCodedError(err, "apple_account_keepalive_retrying") {
		t.Fatalf("err = %v, want apple_account_keepalive_retrying", err)
	}
	if state.KeepAliveFailCount != 2 || state.KeepAliveStopped || state.LastCheckOK {
		t.Fatalf("token-ok forwardemail-401 should accumulate fail count, got %+v", state)
	}

	state, err = client.keepAliveAppleAccountManageStateUnlocked(t.Context(), state)
	if !isCodedError(err, "apple_account_auth_failed") {
		t.Fatalf("second err = %v, want apple_account_auth_failed", err)
	}
	if !state.KeepAliveStopped || state.KeepAliveFailCount != 3 || state.LastCheckOK {
		t.Fatalf("third consecutive manage-api auth failure should stop keepalive, got %+v", state)
	}
}

func TestICloudClientKeepAliveCountsHTMLUnauthorizedAfterRescue(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("scnt", "token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "GET /account/manage/section/privacy":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html></html>`))
		case "GET /bootstrap/portal":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage/forwardemail":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`<html><body>401 Unauthorized</body></html>`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	state, err := client.keepAliveAppleAccountManageStateUnlocked(t.Context(), LoginState{
		Kind:   LoginStateAppleAccount,
		Origin: ts.URL,
		Scnt:   "start-scnt",
		APIKey: "old-key",
	})
	if !isCodedError(err, "apple_account_keepalive_retrying") {
		t.Fatalf("err = %v, want apple_account_keepalive_retrying", err)
	}
	if state.LastCheckOK || state.KeepAliveFailCount != 1 || state.KeepAliveStopped {
		t.Fatalf("HTML 401 after rescue should count as keepalive failure, got %+v", state)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountReusesFreshStateAfterFailedCheck(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token", "GET /account/manage":
			t.Fatalf("unexpected refresh request %s %s", r.Method, r.URL.Path)
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "recent-key" {
				t.Fatalf("add api key header = %q, want recent-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "recent-scnt" {
				t.Fatalf("add scnt header = %q, want recent-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			_, _ = w.Write([]byte(`{"emailAddress":"Recovered.Alias@icloud.com","active":false}`))
		case "PUT /account/manage/email/private/add/complete":
			if r.Header.Get("X-Apple-Api-Key") != "recent-key" {
				t.Fatalf("complete api key header = %q, want recent-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-add" {
				t.Fatalf("complete scnt header = %q, want scnt-after-add", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-complete")
			_, _ = w.Write([]byte(`{"emailAddress":"Recovered.Alias@icloud.com","id":"recovered123","active":true}`))
		case "GET /account/manage/email/private/recovered123.em":
			if r.Header.Get("X-Apple-Api-Key") != "recent-key" {
				t.Fatalf("confirm api key header = %q, want recent-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-complete" {
				t.Fatalf("confirm scnt header = %q, want scnt-after-complete", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-confirm")
			_, _ = w.Write([]byte(`{"emailAddress":"Recovered.Alias@icloud.com","id":"recovered123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	checkedAt := time.Now()
	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:              LoginStateAppleAccount,
			Scnt:              "recent-scnt",
			APIKey:            "recent-key",
			LastCheckedAt:     checkedAt,
			ManageExpiresAt:   checkedAt.Add(15 * time.Minute),
			LastCheckOK:       false,
			LastStatusMessage: "新接口登录态异常：HTTP 404",
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "recovered.alias@icloud.com" {
		t.Fatalf("remote email = %q, want recovered.alias@icloud.com", remote.Email)
	}
	wantPaths := []string{
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/recovered123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.Scnt != "scnt-after-confirm" || updatedState.APIKey != "recent-key" || !updatedState.LastCheckOK || updatedState.LastCheckedAt.IsZero() || updatedState.LastCheckedAt.Before(checkedAt) {
		t.Fatalf("updated apple account state = %+v ok=%v, want reused state marked ok", updatedState, ok)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRetriesHTMLUnauthorized(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	addCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			addCalls++
			if addCalls == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`<html><body>401 Unauthorized</body></html>`))
				return
			}
			w.Header().Set("scnt", "scnt-after-add")
			_, _ = w.Write([]byte(`{"emailAddress":"Html.Retry@icloud.com","active":false}`))
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("scnt", "token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "PUT /account/manage/email/private/add/complete":
			w.Header().Set("scnt", "scnt-after-complete")
			_, _ = w.Write([]byte(`{"emailAddress":"Html.Retry@icloud.com","id":"htmlretry1","active":true}`))
		case "GET /account/manage/email/private/htmlretry1.em":
			w.Header().Set("scnt", "scnt-after-confirm")
			_, _ = w.Write([]byte(`{"emailAddress":"Html.Retry@icloud.com","id":"htmlretry1","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	remote, _, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Origin:          ts.URL,
			Scnt:            "fresh-scnt",
			APIKey:          "fresh-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(15 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	if addCalls != 2 {
		t.Fatalf("add calls = %d, want 2 after HTML 401 retry", addCalls)
	}
	if remote.Email != "html.retry@icloud.com" {
		t.Fatalf("remote email = %q, want html.retry@icloud.com", remote.Email)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRefreshesWhenKeepAliveRetrying(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("scnt", "token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("add api key header = %q, want fresh-key after keepalive retry refresh", r.Header.Get("X-Apple-Api-Key"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			_, _ = w.Write([]byte(`{"emailAddress":"Retry.Keepalive@icloud.com","active":false}`))
		case "PUT /account/manage/email/private/add/complete":
			w.Header().Set("scnt", "scnt-after-complete")
			_, _ = w.Write([]byte(`{"emailAddress":"Retry.Keepalive@icloud.com","id":"retryka123","active":true}`))
		case "GET /account/manage/email/private/retryka123.em":
			w.Header().Set("scnt", "scnt-after-confirm")
			_, _ = w.Write([]byte(`{"emailAddress":"Retry.Keepalive@icloud.com","id":"retryka123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	remote, _, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:               LoginStateAppleAccount,
			Origin:             ts.URL,
			Scnt:               "stale-scnt",
			APIKey:             "stale-key",
			LastCheckedAt:      now,
			ManageExpiresAt:    now.Add(15 * time.Minute),
			LastCheckOK:        false,
			KeepAliveFailCount: 1,
			LastStatusMessage:  "新接口保活：重试中",
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "retry.keepalive@icloud.com" {
		t.Fatalf("remote email = %q, want retry.keepalive@icloud.com", remote.Email)
	}
	if paths[0] != "GET /account/manage/gs/ws/token" {
		t.Fatalf("create during keepalive retry must refresh first, paths=%#v", paths)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountKeepsKeepAliveFailureAfterAddAuthError(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("scnt", "token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "POST /account/manage/email/private/add":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"service_errors":[{"message":"authentication_failed"}]}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	_, updated, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:               LoginStateAppleAccount,
			Origin:             ts.URL,
			Scnt:               "stale-scnt",
			APIKey:             "stale-key",
			LastCheckedAt:      now,
			ManageExpiresAt:    now.Add(15 * time.Minute),
			LastCheckOK:        false,
			KeepAliveFailCount: 2,
			LastStatusMessage:  "新接口保活：重试中",
		}},
	}, "", "LAB", "")
	if !isCodedError(err, "apple_account_auth_failed") {
		t.Fatalf("err = %v, want apple_account_auth_failed", err)
	}
	state, ok := appleAccountLoginState(updated)
	if !ok || state.LastCheckOK || state.KeepAliveFailCount != 2 || state.KeepAliveStopped {
		t.Fatalf("failed create must not clear keepalive failure streak: %+v ok=%v", state, ok)
	}
	if state.Scnt != "manage-scnt" || state.APIKey != "fresh-key" {
		t.Fatalf("failed create should still keep refreshed credentials: %+v", state)
	}
}

func TestICloudClientDeletePrivacyMailboxWithAppleAccountKeepsKeepAliveFailureAfterAuthError(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("scnt", "token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "DELETE /account/manage/email/private/anon-1/remove":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"service_errors":[{"message":"authentication_failed"}]}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	updated, err := client.DeletePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:               LoginStateAppleAccount,
			Origin:             ts.URL,
			Scnt:               "stale-scnt",
			APIKey:             "stale-key",
			LastCheckedAt:      now,
			ManageExpiresAt:    now.Add(15 * time.Minute),
			LastCheckOK:        false,
			KeepAliveFailCount: 1,
			LastStatusMessage:  "新接口保活：重试中",
		}},
	}, "", "anon-1")
	if !isCodedError(err, "apple_account_auth_failed") {
		t.Fatalf("err = %v, want apple_account_auth_failed", err)
	}
	state, ok := appleAccountLoginState(updated)
	if !ok || state.LastCheckOK || state.KeepAliveFailCount != 1 || state.KeepAliveStopped {
		t.Fatalf("failed delete must not clear keepalive failure streak: %+v ok=%v", state, ok)
	}
}

func TestICloudClientListAppleAccountMailboxesDoesNotClearKeepAliveFailure(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account/manage/email/private" {
			t.Fatalf("list path = %q, want /account/manage/email/private", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("scnt", "list-scnt")
		_, _ = w.Write([]byte(`{"success":true,"result":{"hmeEmails":[{"anonymousId":"list-1","hme":"list-keep@icloud.com","isActive":true}]}}`))
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	remotes, updated, err := (&ICloudClient{client: ts.Client()}).ListPrivacyMailboxesForOriginWithSession(
		t.Context(),
		ICloudSession{LoginStates: []LoginState{{
			Kind:               LoginStateAppleAccount,
			Origin:             ts.URL,
			Scnt:               "retry-scnt",
			APIKey:             "retry-key",
			LastCheckOK:        false,
			KeepAliveFailCount: 2,
			LastStatusMessage:  "新接口保活：重试中",
		}}},
		mailboxRemoteOriginAppleAccount,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(remotes) != 1 || remotes[0].Email != "list-keep@icloud.com" {
		t.Fatalf("remotes = %+v, want one listed mailbox", remotes)
	}
	state, ok := appleAccountLoginState(updated)
	if !ok || state.LastCheckOK || state.KeepAliveFailCount != 2 || state.KeepAliveStopped {
		t.Fatalf("successful list must not clear keepalive failure streak: %+v ok=%v", state, ok)
	}
	if state.Scnt != "list-scnt" {
		t.Fatalf("list should still keep refreshed scnt, got %+v", state)
	}
}

func TestICloudClientListAppleAccountMailboxesRetriesHTMLUnauthorized(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	listCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			listCalls++
			if listCalls == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`<html><body>401 Unauthorized</body></html>`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("scnt", "list-retry-scnt")
			_, _ = w.Write([]byte(`{"success":true,"result":{"hmeEmails":[{"anonymousId":"list-2","hme":"list-retry@icloud.com","isActive":true}]}}`))
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("scnt", "token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	remotes, _, err := (&ICloudClient{client: ts.Client()}).ListPrivacyMailboxesForOriginWithSession(
		t.Context(),
		ICloudSession{LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Origin:          ts.URL,
			Scnt:            "fresh-scnt",
			APIKey:          "fresh-key",
			LastCheckOK:     true,
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(15 * time.Minute),
		}}},
		mailboxRemoteOriginAppleAccount,
	)
	if err != nil {
		t.Fatal(err)
	}
	if listCalls != 2 {
		t.Fatalf("list calls = %d, want 2 after HTML 401 retry", listCalls)
	}
	if len(remotes) != 1 || remotes[0].Email != "list-retry@icloud.com" {
		t.Fatalf("remotes = %+v, want retried mailbox", remotes)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRefreshesAfterAuthFailure(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	addCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			addCalls++
			if addCalls == 1 {
				if r.Header.Get("X-Apple-Api-Key") != "old-key" {
					t.Fatalf("first add api key header = %q, want old-key", r.Header.Get("X-Apple-Api-Key"))
				}
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"service_errors":[{"message":"authentication_failed"}]}`))
				return
			}
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("retry add api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("retry add scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			_, _ = w.Write([]byte(`{"emailAddress":"Retry.Alias@icloud.com","active":false}`))
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("X-Apple-Api-Key") != "" {
				t.Fatalf("token api key header = %q, want empty", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-old" {
				t.Fatalf("token scnt header = %q, want scnt-old", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-token")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		case "PUT /account/manage/email/private/add/complete":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("complete api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			_, _ = w.Write([]byte(`{"emailAddress":"Retry.Alias@icloud.com","id":"retry123","active":true}`))
		case "GET /account/manage/email/private/retry123.em":
			_, _ = w.Write([]byte(`{"emailAddress":"Retry.Alias@icloud.com","id":"retry123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt-old",
			APIKey:          "old-key",
			LastCheckedAt:   time.Now(),
			ManageExpiresAt: time.Now().Add(15 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "retry.alias@icloud.com" {
		t.Fatalf("remote email = %q, want retry.alias@icloud.com", remote.Email)
	}
	wantPaths := []string{
		"POST /account/manage/email/private/add",
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/retry123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.APIKey != "account-key" || updatedState.Scnt != "scnt-after-add" || !updatedState.LastCheckOK {
		t.Fatalf("updated apple account state = %+v ok=%v, want refreshed state", updatedState, ok)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRefreshesAfterSessionTimeout(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	addCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			addCalls++
			if addCalls == 1 {
				w.WriteHeader(appleAccountHTTPStatusSessionTimeout)
				_, _ = w.Write([]byte(`{"service_errors":[{"message":"session timeout"}]}`))
				return
			}
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("retry add api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("retry add scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			_, _ = w.Write([]byte(`{"emailAddress":"Timeout.Alias@icloud.com","active":false}`))
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("scnt", "scnt-after-token")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		case "PUT /account/manage/email/private/add/complete":
			_, _ = w.Write([]byte(`{"emailAddress":"Timeout.Alias@icloud.com","id":"timeout123","active":true}`))
		case "GET /account/manage/email/private/timeout123.em":
			_, _ = w.Write([]byte(`{"emailAddress":"Timeout.Alias@icloud.com","id":"timeout123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt-old",
			APIKey:          "old-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(15 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "timeout.alias@icloud.com" {
		t.Fatalf("remote email = %q, want timeout.alias@icloud.com", remote.Email)
	}
	wantPaths := []string{
		"POST /account/manage/email/private/add",
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/timeout123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.APIKey != "account-key" || updatedState.Scnt != "scnt-after-add" || !updatedState.LastCheckOK || !updatedState.ManageExpiresAt.After(now) {
		t.Fatalf("updated apple account state = %+v ok=%v, want refreshed state", updatedState, ok)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRequiresManageSession(t *testing.T) {
	client := NewICloudClient()
	_, _, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{}, "account-key", "LAB", "")
	coded, ok := err.(codedError)
	if !ok {
		t.Fatalf("error type = %T, want codedError", err)
	}
	if coded.code != "apple_account_session_missing" {
		t.Fatalf("code = %q, want apple_account_session_missing", coded.code)
	}
}

func TestCheckSavedLoginStatesChecksAppleAccountState(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("scnt") != "scnt-token" {
				t.Fatalf("token scnt header = %q, want scnt-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-token")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		case "GET /account/manage/forwardemail":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("forwardemail api key = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("forwardemail scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-touch")
			_, _ = w.Write([]byte(`{"forwardToEmail":"receiver@icloud.com"}`))
		case "POST /v2/jslogs":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("jslogs api key = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	checkedAt := time.Date(2026, 6, 30, 13, 0, 0, 0, time.UTC)
	client := &ICloudClient{client: ts.Client()}
	session, ok, err := checkSavedLoginStates(context.Background(), client, ICloudSession{
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Origin: appleAccountManageOrigin,
			Scnt:   "scnt-token",
		}},
	}, checkedAt)
	if err != nil || !ok {
		t.Fatalf("checkSavedLoginStates err=%v ok=%t", err, ok)
	}
	state, found := appleAccountLoginState(session)
	if !found {
		t.Fatalf("apple account state missing: %+v", session.LoginStates)
	}
	if state.APIKey != "account-key" || state.Scnt != "scnt-after-touch" || !state.LastCheckOK || !state.LastCheckedAt.Equal(checkedAt) || state.LastStatusMessage != "新接口登录态正常" {
		t.Fatalf("updated state = %+v", state)
	}
	if !session.LastCheckOK || !strings.Contains(session.LastStatusMessage, "新接口正常") {
		t.Fatalf("session check status = ok:%t message:%q", session.LastCheckOK, session.LastStatusMessage)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"GET /account/manage/forwardemail",
		"POST /v2/jslogs",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestCheckSavedLoginStatesKeepsRecentlyHealthyAppleAccountState(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "should not refresh recently healthy state", http.StatusTeapot)
	}))
	defer ts.Close()

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	session, ok, err := checkSavedLoginStates(context.Background(), client, ICloudSession{
		LoginStates: []LoginState{{
			Kind:              LoginStateAppleAccount,
			Host:              "appleid.apple.com",
			Origin:            ts.URL,
			Scnt:              "fresh-scnt",
			APIKey:            "fresh-key",
			LastCheckOK:       true,
			LastCheckedAt:     now.Add(-time.Minute),
			ManageExpiresAt:   now.Add(14 * time.Minute),
			LastStatusMessage: "新接口登录态正常",
		}},
	}, now)
	if err != nil || !ok {
		t.Fatalf("checkSavedLoginStates err=%v ok=%t", err, ok)
	}
	if called {
		t.Fatal("recently healthy Apple Account state should not be refreshed")
	}
	state, found := appleAccountLoginState(session)
	if !found || !state.LastCheckOK || state.LastStatusMessage != "新接口登录态正常" || !state.LastCheckedAt.Equal(now) {
		t.Fatalf("state = %+v found=%t, want healthy state updated at check time", state, found)
	}
}

func TestCheckSavedLoginStatesTreatsKeepAliveRetryingAsCompletedCheck(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/section/privacy":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html></html>`))
		case "GET /bootstrap/portal":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"service_errors":[{"message":"authentication_failed"}]}`))
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	checkedAt := time.Now()
	client := &ICloudClient{client: ts.Client()}
	session, ok, err := checkSavedLoginStates(context.Background(), client, ICloudSession{
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Origin: ts.URL,
			Scnt:   "start-scnt",
			APIKey: "old-key",
		}},
	}, checkedAt)
	if err != nil || !ok {
		t.Fatalf("retrying-only check should complete without hard error, err=%v ok=%t", err, ok)
	}
	if session.LastCheckOK || !strings.Contains(session.LastStatusMessage, "新接口重试中") {
		t.Fatalf("session check status = ok:%t message:%q", session.LastCheckOK, session.LastStatusMessage)
	}
	state, found := appleAccountLoginState(session)
	if !found || state.LastCheckOK || state.KeepAliveFailCount != 1 || state.KeepAliveStopped {
		t.Fatalf("apple account retrying state = %+v found=%t", state, found)
	}
}

func TestICloudSessionCheckOKMessageReportsKeepAliveRetrying(t *testing.T) {
	got := icloudSessionCheckOKMessage(0, 1, []publicICloudSession{{
		AppleAccountKeepAliveRetrying: true,
		AppleAccountLoginOK:           false,
	}})
	if got != "新接口保活重试中" {
		t.Fatalf("message = %q, want 新接口保活重试中", got)
	}
	if got := icloudSessionCheckOKMessage(0, 1, []publicICloudSession{{LastCheckOK: true}}); got != "登录态检测正常" {
		t.Fatalf("healthy message = %q, want 登录态检测正常", got)
	}
	if got := icloudSessionCheckOKMessage(1, 2, []publicICloudSession{{}, {}}); got != "登录态部分检测成功：成功 1，失败 1" {
		t.Fatalf("partial message = %q", got)
	}
	mixed := icloudSessionCheckOKMessage(0, 2, []publicICloudSession{
		{AppleAccountLoginOK: true, LastCheckOK: true},
		{AppleAccountKeepAliveRetrying: true, AppleAccountLoginOK: false},
	})
	if mixed != "登录态部分正常：新接口保活重试中 1 个" {
		t.Fatalf("mixed message = %q, want partial retrying summary", mixed)
	}
	failedAndRetrying := icloudSessionCheckOKMessage(1, 2, []publicICloudSession{
		{},
		{AppleAccountKeepAliveRetrying: true, AppleAccountLoginOK: false},
	})
	if failedAndRetrying != "登录态部分检测成功：成功 1，失败 1，新接口保活重试中 1 个" {
		t.Fatalf("failed+retrying message = %q", failedAndRetrying)
	}
	failedAndDeferred := icloudSessionCheckOKMessage(1, 2, []publicICloudSession{
		{},
		{LastStatusMessage: "登录态异常：新接口暂时失败"},
	})
	if failedAndDeferred != "登录态部分检测成功：成功 1，失败 1，检测暂时失败 1 个" {
		t.Fatalf("failed+deferred message = %q", failedAndDeferred)
	}
	deferredAndRetrying := icloudSessionCheckOKMessage(0, 2, []publicICloudSession{
		{LastStatusMessage: "登录态异常：新接口暂时失败"},
		{AppleAccountKeepAliveRetrying: true, AppleAccountLoginOK: false},
	})
	if deferredAndRetrying != "登录态部分正常：新接口保活重试中 1 个，检测暂时失败 1 个" {
		t.Fatalf("deferred+retrying message = %q", deferredAndRetrying)
	}
	partialDeferred := icloudSessionCheckOKMessage(0, 1, []publicICloudSession{{
		LastStatusMessage: "登录态部分正常：新接口暂时失败；取码登录正常",
		ICloudIMAPLoginOK: true,
	}})
	if partialDeferred != "登录态部分正常：新接口检测暂时失败，已推迟保活" {
		t.Fatalf("partial deferred message = %q", partialDeferred)
	}
}

func TestCheckSavedLoginStatesUsesConfiguredKeepAliveInterval(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "probe", http.StatusTeapot)
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	_, _, _ = checkSavedLoginStatesWithKeepAliveInterval(context.Background(), client, ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Host:            "appleid.apple.com",
			Origin:          ts.URL,
			Scnt:            "fresh-scnt",
			APIKey:          "fresh-key",
			LastCheckOK:     true,
			LastCheckedAt:   now.Add(-time.Minute),
			ManageExpiresAt: now.Add(14 * time.Minute),
		}},
	}, now, CheckICloudIMAPLoginWithProxy, 30*time.Second)
	if !called {
		t.Fatal("configured 30s keepalive interval must probe a session last checked 1 minute ago")
	}
}

func TestCheckSavedLoginStatesKeepsHealthyAppleAccountOnTransientError(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`<html><body>bad gateway</body></html>`))
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	session, ok, err := checkSavedLoginStates(context.Background(), client, ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Origin:          ts.URL,
			Scnt:            "live-scnt",
			APIKey:          "live-key",
			LastCheckOK:     true,
			LastCheckedAt:   now.Add(-time.Hour),
			ManageExpiresAt: now.Add(10 * time.Minute),
		}},
	}, now)
	if err != nil || !ok {
		t.Fatalf("transient check should complete without kicking keepalive, err=%v ok=%t", err, ok)
	}
	state, found := appleAccountLoginState(session)
	if !found || !state.LastCheckOK || state.KeepAliveFailCount != 0 || state.KeepAliveStopped {
		t.Fatalf("transient check must keep healthy keepalive flags: %+v found=%t", state, found)
	}
	if !appleAccountKeepAliveEligible(session) {
		t.Fatal("transient check must not remove a healthy session from the keepalive queue")
	}
	if !strings.Contains(session.LastStatusMessage, "暂时失败") {
		t.Fatalf("session message = %q, want 暂时失败", session.LastStatusMessage)
	}
	pub := publicSession(&session)
	if pub.AppleAccountLoginOK {
		t.Fatal("transient check must not show the new-interface chip as healthy")
	}
	if !strings.Contains(pub.AppleAccountLoginStatus, "暂时失败") {
		t.Fatalf("public apple status = %q, want 暂时失败", pub.AppleAccountLoginStatus)
	}
}

func TestCheckSavedLoginStatesProbesDeferredAppleAccountEvenIfRecentlyChecked(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`<html><body>bad gateway</body></html>`))
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	_, _, err := checkSavedLoginStates(context.Background(), client, ICloudSession{
		LoginStates: []LoginState{{
			Kind:              LoginStateAppleAccount,
			Origin:            ts.URL,
			Scnt:              "live-scnt",
			APIKey:            "live-key",
			LastCheckOK:       true,
			LastCheckedAt:     now.Add(-time.Minute),
			ManageExpiresAt:   now.Add(10 * time.Minute),
			LastStatusMessage: "新接口检测暂时失败，已推迟保活",
		}},
	}, now)
	if err != nil {
		t.Fatalf("deferred recheck err=%v", err)
	}
	if !called {
		t.Fatal("deferred keepalive state must not skip a real Apple probe")
	}
}

func TestAppleAuthClientPrimeAppleAccountManageStateKeepsChallengeScnt(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/section/privacy":
			w.Header().Set("scnt", "page-scnt")
			_, _ = w.Write([]byte(`<html></html>`))
		case "GET /bootstrap/portal":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("scnt") != "" {
				t.Fatalf("pre-login token scnt header = %q, want empty", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "manage-scnt")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	session := &appleAuthSession{
		Endpoints: appleAccountManageAuthEndpoints(),
		UserAgent: appleAccountManageUserAgent,
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.primeAppleAccountManageState(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if session.ManageScnt != "manage-scnt" {
		t.Fatalf("ManageScnt = %q, want manage-scnt", session.ManageScnt)
	}
	wantPaths := []string{
		"GET /account/manage/section/privacy",
		"GET /bootstrap/portal",
		"GET /account/manage/gs/ws/token",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestAppleAuthClientAuthStartPreservesAppleAccountCompleteHashcashChallenge(t *testing.T) {
	var gotPath string
	var gotAuthVersion string
	var gotSecFetchDest string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuthVersion = r.URL.Query().Get("authVersion")
		gotSecFetchDest = r.Header.Get("Sec-Fetch-Dest")
		if r.Header.Get("Accept") == "" || !strings.Contains(r.Header.Get("Accept"), "text/html") {
			t.Fatalf("Accept = %q, want browser navigation accept", r.Header.Get("Accept"))
		}
		w.Header().Set("X-Apple-HC-Bits", "8")
		w.Header().Set("X-Apple-HC-Challenge", "initial-challenge")
		_, _ = w.Write([]byte(`<html></html>`))
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		ClientID:  appleAccountManageOAuthClientID,
		FrameID:   "unit",
		UserAgent: appleAccountManageUserAgent,
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.authStart(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/authorize/signin" {
		t.Fatalf("path = %q, want /authorize/signin", gotPath)
	}
	if gotAuthVersion != "8.0.2" {
		t.Fatalf("authVersion = %q, want 8.0.2", gotAuthVersion)
	}
	if gotSecFetchDest != "iframe" {
		t.Fatalf("Sec-Fetch-Dest = %q, want iframe", gotSecFetchDest)
	}
	if session.CompleteHCBits != 8 || session.CompleteHCChallenge != "initial-challenge" {
		t.Fatalf("complete hashcash = %d/%q, want 8/initial-challenge", session.CompleteHCBits, session.CompleteHCChallenge)
	}

	session.HCBits = 12
	session.HCChallenge = "later-challenge"
	bits, challenge := session.completeHashcashChallenge()
	if bits != 8 || challenge != "initial-challenge" {
		t.Fatalf("completeHashcashChallenge() = %d/%q, want preserved initial challenge", bits, challenge)
	}
}

func TestAppleAuthClientAuthFederateEnablesRememberMeForAppleAccountManage(t *testing.T) {
	var body map[string]any
	var rememberQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/federate" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		rememberQuery = r.URL.Query().Get("isRememberMeEnabled")
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		AppleID:   "user@example.com",
		ClientID:  appleAccountManageOAuthClientID,
		UserAgent: appleAccountManageUserAgent,
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.authFederate(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if rememberQuery != "true" {
		t.Fatalf("isRememberMeEnabled = %q, want true", rememberQuery)
	}
	if body["rememberMe"] != true {
		t.Fatalf("rememberMe = %#v, want true", body["rememberMe"])
	}
	if body["accountName"] != "user@example.com" {
		t.Fatalf("accountName = %#v, want user@example.com", body["accountName"])
	}
}

func TestAppleAuthClientAuthSRPUsesPreservedAppleAccountHashcashAndBrowserBody(t *testing.T) {
	var completeHashcash string
	var completeBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /signin/init":
			w.Header().Set("X-Apple-HC-Bits", "12")
			w.Header().Set("X-Apple-HC-Challenge", "later-challenge")
			_, _ = w.Write([]byte(`{"iteration":1,"salt":"c2FsdA==","protocol":"s2k","b":"Ag==","c":"proof-context"}`))
		case "POST /signin/complete":
			completeHashcash = r.Header.Get("X-Apple-HC")
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &completeBody); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		AppleID:        "user@example.com",
		ClientID:       appleAccountManageOAuthClientID,
		HCBits:         8,
		HCChallenge:    "initial-challenge",
		UserAgent:      appleAccountManageUserAgent,
		Scnt:           "scnt",
		SessionID:      "session-id",
		AuthAttributes: "attributes",
	}
	session.rememberCompleteHashcashChallenge()

	client := &AppleAuthClient{httpClient: ts.Client()}
	needs2FA, err := client.authSRP(t.Context(), session, "password")
	if err != nil {
		t.Fatal(err)
	}
	if !needs2FA {
		t.Fatalf("needs2FA = false, want true")
	}
	if !strings.Contains(completeHashcash, ":8:") || !strings.Contains(completeHashcash, ":initial-challenge::") {
		t.Fatalf("X-Apple-HC = %q, want preserved initial challenge", completeHashcash)
	}
	if completeBody["rememberMe"] != true {
		t.Fatalf("rememberMe = %#v, want true", completeBody["rememberMe"])
	}
	if _, ok := completeBody["trustTokens"]; ok {
		t.Fatalf("trustTokens present in Apple Account manage complete body: %#v", completeBody["trustTokens"])
	}
	if completeBody["accountName"] != "user@example.com" {
		t.Fatalf("accountName = %#v, want user@example.com", completeBody["accountName"])
	}
}

func TestAppleAccountFallbackPhoneNumber(t *testing.T) {
	if got := appleAccountFallbackPhoneNumber(nil); len(got) != 0 {
		t.Fatalf("nil fallback = %s, want empty", got)
	}
	if got := appleAccountFallbackPhoneNumber(json.RawMessage(`null`)); len(got) != 0 {
		t.Fatalf("null fallback = %s, want empty", got)
	}
	if got := string(appleAccountFallbackPhoneNumber(nil, json.RawMessage(`{"id":3}`))); got != `{"id":3}` {
		t.Fatalf("stored fallback = %s", got)
	}
	if got := string(appleAccountFallbackPhoneNumber(json.RawMessage(`{"id":2}`))); got != `{"id":2}` {
		t.Fatalf("explicit phone = %s", got)
	}
}

func TestAppleAuthClientRejectsSMS2FAWithoutPhoneIdentity(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		ClientID:  appleAccountManageOAuthClientID,
		FrameID:   "unit",
		UserAgent: appleAccountManageUserAgent,
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	err := client.requestPhoneSecurityCode(t.Context(), session, nil)
	if !isCodedError(err, "invalid_phone_number_payload") {
		t.Fatalf("requestPhoneSecurityCode error = %#v, want invalid_phone_number_payload", err)
	}
	if called {
		t.Fatal("requestPhoneSecurityCode sent a request without a trusted phone identity")
	}
}

func TestAppleAuthClientRequestsBrowser2FACodeEndpoints(t *testing.T) {
	var paths []string
	var phoneBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "PUT /verify/trusteddevice/securitycode":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{}`))
		case "PUT /verify/phone":
			if err := json.NewDecoder(r.Body).Decode(&phoneBody); err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		ClientID:       appleAccountManageOAuthClientID,
		FrameID:        "unit",
		UserAgent:      appleAccountManageUserAgent,
		Scnt:           "scnt-token",
		SessionID:      "session-id",
		TwoFactorPhone: json.RawMessage(`{"id":2,"nonFTEU":true}`),
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.requestTrustedDeviceCode(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if err := client.requestPhoneSecurityCode(t.Context(), session, nil); err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"PUT /verify/trusteddevice/securitycode",
		"PUT /verify/phone",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	phone, ok := phoneBody["phoneNumber"].(map[string]any)
	if !ok {
		t.Fatalf("phoneNumber = %#v, want object", phoneBody["phoneNumber"])
	}
	if phone["id"] != float64(2) {
		t.Fatalf("phone id = %#v, want 2", phone["id"])
	}
	if _, ok := phone["nonFTEU"]; ok {
		t.Fatalf("send phoneNumber should not include nonFTEU: %#v", phone)
	}
	if phoneBody["mode"] != "sms" {
		t.Fatalf("mode = %#v, want sms", phoneBody["mode"])
	}
}

func TestSubmitAppleAccountManage2FADefaultsTrustedDeviceAndUsesFreshScnt(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var authPaths []string
	var submittedCode string
	authTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authPaths = append(authPaths, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "POST /verify/trusteddevice/securitycode":
			var body struct {
				SecurityCode struct {
					Code string `json:"code"`
				} `json:"securityCode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			submittedCode = body.SecurityCode.Code
			w.Header().Set("scnt", "fresh-scnt")
			w.Header().Set("X-Apple-ID-Session-Id", "fresh-session")
			w.WriteHeader(http.StatusNoContent)
		case "GET /2sv/trust":
			if r.Header.Get("scnt") != "fresh-scnt" {
				t.Fatalf("trust scnt header = %q, want fresh-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "trusted-scnt")
			w.Header().Set("X-Apple-ID-Session-Id", "trusted-session")
			http.SetCookie(w, &http.Cookie{Name: "trust-cookie", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected auth request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer authTS.Close()

	var managePaths []string
	tokenCalls := 0
	manageTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		managePaths = append(managePaths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			tokenCalls++
			if tokenCalls != 1 {
				t.Fatalf("unexpected token call %d", tokenCalls)
			}
			if r.Header.Get("scnt") != "trusted-scnt" {
				t.Fatalf("token scnt header = %q, want trusted-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "token-scnt")
			http.SetCookie(w, &http.Cookie{Name: "manage-token", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "token-scnt" {
				t.Fatalf("manage scnt header = %q, want token-scnt", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "manage-token=ok") {
				t.Fatalf("manage cookie header = %q, want token response cookie", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		default:
			t.Fatalf("unexpected manage request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer manageTS.Close()
	appleAccountManageBaseURL = manageTS.URL

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: authTS.URL,
			Host: "appleid.apple.com",
		},
		AppleID:    "user@example.com",
		ClientID:   appleAccountManageOAuthClientID,
		FrameID:    "unit",
		UserAgent:  appleAccountManageUserAgent,
		Scnt:       "old-scnt",
		ManageScnt: "stale-manage-scnt",
		SessionID:  "old-session",
	}
	client := &AppleAuthClient{httpClient: authTS.Client()}
	icloudSession, err := client.SubmitAppleAccountManage2FA(t.Context(), appleAuthPending{Session: session}, "123456", nil)
	if err != nil {
		t.Fatal(err)
	}
	if submittedCode != "123456" {
		t.Fatalf("submitted code = %q, want 123456", submittedCode)
	}
	wantAuthPaths := []string{
		"POST /verify/trusteddevice/securitycode",
		"GET /2sv/trust",
	}
	if strings.Join(authPaths, "\n") != strings.Join(wantAuthPaths, "\n") {
		t.Fatalf("auth paths = %#v, want %#v", authPaths, wantAuthPaths)
	}
	wantManagePaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
	}
	if strings.Join(managePaths, "\n") != strings.Join(wantManagePaths, "\n") {
		t.Fatalf("manage paths = %#v, want %#v", managePaths, wantManagePaths)
	}
	state, ok := appleAccountLoginState(icloudSession)
	if !ok || state.Scnt != "manage-scnt" || state.APIKey != "account-key" || state.SessionID != "trusted-session" {
		t.Fatalf("apple account state = %+v ok=%v, want fresh session/scnt/api key", state, ok)
	}
	if !strings.Contains(cookieHeader(state.Cookies, authTS.URL+"/2sv/trust"), "trust-cookie=ok") {
		t.Fatalf("apple account state cookies = %+v, want trust cookie saved", state.Cookies)
	}
}

func TestSubmitAppleAccountManage2FAUsesPhoneMethod(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var authPaths []string
	var submittedCode string
	var submittedPhoneID float64
	authTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authPaths = append(authPaths, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "POST /verify/phone/securitycode":
			var body struct {
				PhoneNumber struct {
					ID float64 `json:"id"`
				} `json:"phoneNumber"`
				SecurityCode struct {
					Code string `json:"code"`
				} `json:"securityCode"`
				Mode string `json:"mode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			submittedCode = body.SecurityCode.Code
			submittedPhoneID = body.PhoneNumber.ID
			if body.Mode != "sms" {
				t.Fatalf("mode = %q, want sms", body.Mode)
			}
			w.Header().Set("scnt", "fresh-scnt")
			w.Header().Set("X-Apple-ID-Session-Id", "fresh-session")
			w.WriteHeader(http.StatusNoContent)
		case "GET /2sv/trust":
			w.Header().Set("scnt", "trusted-scnt")
			w.Header().Set("X-Apple-ID-Session-Id", "trusted-session")
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected auth request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer authTS.Close()

	manageTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("scnt", "token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		default:
			t.Fatalf("unexpected manage request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer manageTS.Close()
	appleAccountManageBaseURL = manageTS.URL

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: authTS.URL,
			Host: "appleid.apple.com",
		},
		AppleID:         "user@example.com",
		ClientID:        appleAccountManageOAuthClientID,
		FrameID:         "unit",
		UserAgent:       appleAccountManageUserAgent,
		Scnt:            "old-scnt",
		SessionID:       "old-session",
		TwoFactorMethod: appleTwoFactorMethodPhone,
		TwoFactorPhone:  json.RawMessage(`{"id":9,"nonFTEU":true}`),
	}
	client := &AppleAuthClient{httpClient: authTS.Client()}
	icloudSession, err := client.SubmitAppleAccountManage2FA(t.Context(), appleAuthPending{Session: session}, "654321", nil)
	if err != nil {
		t.Fatal(err)
	}
	if submittedCode != "654321" || submittedPhoneID != 9 {
		t.Fatalf("submitted code/id = %q/%v, want 654321/9", submittedCode, submittedPhoneID)
	}
	wantAuthPaths := []string{
		"POST /verify/phone/securitycode",
		"GET /2sv/trust",
	}
	if strings.Join(authPaths, "\n") != strings.Join(wantAuthPaths, "\n") {
		t.Fatalf("auth paths = %#v, want %#v", authPaths, wantAuthPaths)
	}
	state, ok := appleAccountLoginState(icloudSession)
	if !ok || state.Scnt != "manage-scnt" || state.APIKey != "account-key" || state.SessionID != "trusted-session" {
		t.Fatalf("apple account state = %+v ok=%v, want fresh session/scnt/api key", state, ok)
	}
}

func TestSubmitAppleAccountManage2FARejectsTrustFailure(t *testing.T) {
	var trustCalls int
	authTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /verify/trusteddevice/securitycode":
			w.WriteHeader(http.StatusNoContent)
		case "GET /2sv/trust":
			trustCalls++
			http.Error(w, "trust failed", http.StatusForbidden)
		default:
			t.Fatalf("unexpected auth request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer authTS.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: authTS.URL,
			Host: "appleid.apple.com",
		},
		AppleID:   "trust-failure@example.com",
		ClientID:  appleAccountManageOAuthClientID,
		FrameID:   "unit",
		UserAgent: appleAccountManageUserAgent,
		Scnt:      "scnt",
		SessionID: "session",
	}
	client := &AppleAuthClient{httpClient: authTS.Client()}
	_, err := client.SubmitAppleAccountManage2FA(t.Context(), appleAuthPending{Session: session}, "123456", nil)
	if err == nil {
		t.Fatal("SubmitAppleAccountManage2FA succeeded after trust failure")
	}
	if trustCalls == 0 {
		t.Fatal("trust endpoint was not called")
	}
}

func TestAppleAuthClientValidatePhoneCodeUsesStoredPhoneNumber(t *testing.T) {
	var body map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/verify/phone/securitycode" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		ClientID:       appleAccountManageOAuthClientID,
		FrameID:        "unit",
		UserAgent:      appleAccountManageUserAgent,
		TwoFactorPhone: json.RawMessage(`{"id":4,"nonFTEU":true}`),
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.validatePhoneSecurityCode(t.Context(), session, "123456", nil); err != nil {
		t.Fatal(err)
	}
	phone, ok := body["phoneNumber"].(map[string]any)
	if !ok {
		t.Fatalf("phoneNumber = %#v, want object", body["phoneNumber"])
	}
	if phone["id"] != float64(4) || phone["nonFTEU"] != true {
		t.Fatalf("phoneNumber = %#v, want stored id and nonFTEU", phone)
	}
	securityCode := body["securityCode"].(map[string]any)
	if securityCode["code"] != "123456" || body["mode"] != "sms" {
		t.Fatalf("body = %#v, want code and sms mode", body)
	}
}

func TestAppleAuthSessionRememberTwoFactorPhoneNumberFromAuthHTML(t *testing.T) {
	session := &appleAuthSession{}
	session.rememberTwoFactorPhoneNumber([]byte(`<html><script id="app_config" type="application/json">{"bootData":{"twoSV":{"trustedDeviceVerification":{"phoneNumberVerification":{"trustedPhoneNumbers":[{"id":7,"numberWithDialCode":"+1 ***"}]}}}}}</script></html>`))
	if string(session.TwoFactorPhone) != `{"id":7}` {
		t.Fatalf("TwoFactorPhone = %s, want id 7", session.TwoFactorPhone)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRefreshesAPIKey(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	tokenCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			tokenCalls++
			if tokenCalls != 1 {
				t.Fatalf("unexpected token call %d", tokenCalls)
			}
			if r.Header.Get("scnt") != "scnt-token" {
				t.Fatalf("token scnt header = %q, want scnt-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-token")
			http.SetCookie(w, &http.Cookie{Name: "token-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "token-cookie=ok") {
				t.Fatalf("manage cookie header = %q, want token response cookie", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			http.SetCookie(w, &http.Cookie{Name: "manage-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("add scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "manage-cookie=ok") {
				t.Fatalf("add cookie header = %q, want manage response cookie", r.Header.Get("Cookie"))
			}
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","active":false}`))
		case "PUT /account/manage/email/private/add/complete":
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","id":"abc123","active":true}`))
		case "GET /account/manage/email/private/abc123.em":
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","id":"abc123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	_, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind: LoginStateAppleAccount,
			Scnt: "scnt-token",
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.APIKey != "account-key" {
		t.Fatalf("updated apple account state = %+v ok=%v, want api key", updatedState, ok)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/abc123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestICloudClientListPrivacyMailboxes(t *testing.T) {
	var sawRequest bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRequest = true
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("path = %s, want /v2/hme/list", r.URL.Path)
		}
		if r.URL.Query().Get("dsid") != "123" {
			t.Fatalf("dsid query = %q, want 123", r.URL.Query().Get("dsid"))
		}
		if r.Header.Get("Origin") != "https://www.icloud.com.cn" {
			t.Fatalf("Origin = %q, want https://www.icloud.com.cn", r.Header.Get("Origin"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"timestamp": 1,
			"result": {
				"forwardToEmails": ["main@example.com"],
				"hmeEmails": [
					{"anonymousId":"a1","hme":"Phone.Created@iCloud.com","label":"PHONE","isActive":true,"forwardToEmail":"main@example.com","origin":"ON_DEMAND"},
					{"id":"a2","hme":"old@icloud.com","isActive":false,"origin":"MAIL"}
				]
			}
		}`))
	}))
	defer ts.Close()

	client := &ICloudClient{client: ts.Client()}
	remotes, err := client.ListPrivacyMailboxes(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com.cn",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sawRequest {
		t.Fatal("server did not receive request")
	}
	if len(remotes) != 2 {
		t.Fatalf("remotes len = %d, want 2", len(remotes))
	}
	if remotes[0].Email != "phone.created@icloud.com" || remotes[0].Label != "PHONE" || !remotes[0].IsActive || remotes[0].Origin != "ICLOUD_WEB" {
		t.Fatalf("first remote = %+v", remotes[0])
	}
	if remotes[1].Email != "old@icloud.com" || remotes[1].AnonymousID != "a2" || remotes[1].IsActive || remotes[1].Origin != "ICLOUD_WEB" {
		t.Fatalf("second remote = %+v", remotes[1])
	}
}

func TestICloudClientListPrivacyMailboxesPaginatesICloudWeb(t *testing.T) {
	var cursors []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/hme/list" {
			t.Fatalf("request = %s %s, want GET /v2/hme/list", r.Method, r.URL.Path)
		}
		cursors = append(cursors, r.URL.Query().Get("cursor"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("cursor") {
		case "":
			_, _ = w.Write([]byte(`{
				"success": true,
				"result": {
					"hmeEmails": [{"anonymousId":"web-page-1","hme":"web-page-1@icloud.com"}],
					"hasMore": true,
					"nextCursor": "web-cursor-2"
				}
			}`))
		case "web-cursor-2":
			_, _ = w.Write([]byte(`{
				"success": true,
				"result": {
					"hmeEmails": [{"anonymousId":"web-page-2","hme":"web-page-2@icloud.com"}]
				}
			}`))
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer ts.Close()

	remotes, err := (&ICloudClient{client: ts.Client()}).ListPrivacyMailboxes(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "web-dsid",
		ClientID:           "web-client",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie", Domain: "127.0.0.1", Path: "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cursors, []string{"", "web-cursor-2"}) {
		t.Fatalf("cursor sequence = %#v, want initial and next cursor", cursors)
	}
	if len(remotes) != 2 || remotes[0].AnonymousID != "web-page-1" || remotes[1].AnonymousID != "web-page-2" {
		t.Fatalf("remotes = %+v, want both pages", remotes)
	}
}

func TestICloudClientListPrivacyMailboxesPaginatesAppleAccount(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var cursors []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/account/manage/email/private" {
			t.Fatalf("request = %s %s, want GET /account/manage/email/private", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-Apple-Api-Key") != "apple-api-key" {
			t.Fatalf("api key = %q, want apple-api-key", r.Header.Get("X-Apple-Api-Key"))
		}
		cursors = append(cursors, r.URL.Query().Get("cursor"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("cursor") {
		case "":
			_, _ = w.Write([]byte(`{
				"result": {
					"hmeEmails": [{"id":"apple-page-1","emailAddress":"apple-page-1@icloud.com"}],
					"hasMore": true,
					"nextCursor": "apple-cursor-2"
				}
			}`))
		case "apple-cursor-2":
			_, _ = w.Write([]byte(`{
				"result": {
					"hmeEmails": [{"id":"apple-page-2","emailAddress":"apple-page-2@icloud.com"}]
				}
			}`))
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	remotes, err := (&ICloudClient{client: ts.Client()}).ListPrivacyMailboxes(t.Context(), ICloudSession{
		AppleID: "apple-pagination@example.com",
		LoginStates: []LoginState{{
			Kind:    LoginStateAppleAccount,
			Host:    "appleid.apple.com",
			Scnt:    "scnt",
			APIKey:  "apple-api-key",
			Cookies: []SessionCookie{{Name: "session", Value: "cookie", Domain: "127.0.0.1", Path: "/"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cursors, []string{"", "apple-cursor-2"}) {
		t.Fatalf("cursor sequence = %#v, want initial and next cursor", cursors)
	}
	if len(remotes) != 2 || remotes[0].AnonymousID != "apple-page-1" || remotes[1].AnonymousID != "apple-page-2" {
		t.Fatalf("remotes = %+v, want both pages", remotes)
	}
}

func TestICloudClientListPrivacyMailboxesRetriesEOF(t *testing.T) {
	attempts := 0
	client := &ICloudClient{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return nil, io.EOF
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{
				"success": true,
				"timestamp": 1,
				"result": {"hmeEmails": [{"anonymousId":"a1","hme":"Retry.OK@icloud.com","label":"retry","isActive":true}]}
			}`)),
			Request: r,
		}, nil
	})}}
	remotes, err := client.ListPrivacyMailboxes(t.Context(), ICloudSession{
		PremiumMailBaseURL: "https://p39-maildomainws.icloud.com:443",
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com", Path: "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if len(remotes) != 1 || remotes[0].Email != "retry.ok@icloud.com" {
		t.Fatalf("remotes = %+v", remotes)
	}
}

func TestICloudClientListPrivacyMailboxesDefaultsMissingActiveToTrue(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": {
				"hmeEmails": [
					{"anonymousId":"a1","hme":"missing-active@icloud.com"}
				]
			}
		}`))
	}))
	defer ts.Close()

	client := &ICloudClient{client: ts.Client()}
	remotes, err := client.ListPrivacyMailboxes(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(remotes) != 1 || !remotes[0].IsActive {
		t.Fatalf("remotes = %+v, want one active mailbox when isActive is omitted", remotes)
	}
}

func TestICloudClientListPrivacyMailboxesAcceptsActiveField(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": {
				"hmeEmails": [
					{"anonymousId":"a1","hme":"inactive-active-field@icloud.com","active":false}
				]
			}
		}`))
	}))
	defer ts.Close()

	client := &ICloudClient{client: ts.Client()}
	remotes, err := client.ListPrivacyMailboxes(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(remotes) != 1 || remotes[0].IsActive {
		t.Fatalf("remotes = %+v, want one inactive mailbox when active is false", remotes)
	}
}

func TestICloudClientListPrivacyMailboxesRejectsIncompletePayload(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing hmeEmails",
			body: `{
				"success": true,
				"result": {"forwardToEmails": ["main@example.com"]}
			}`,
		},
		{
			name: "has more pages",
			body: `{
				"success": true,
				"result": {
					"hmeEmails": [{"anonymousId":"a1","hme":"partial@icloud.com"}],
					"hasMore": true,
					"nextCursor": "cursor-2"
				}
			}`,
		},
		{
			name: "item missing email",
			body: `{
				"success": true,
				"result": {
					"hmeEmails": [{"anonymousId":"a1","label":"broken"}]
				}
			}`,
		},
		{
			name: "item missing remote id",
			body: `{
				"success": true,
				"result": {
					"hmeEmails": [{"hme":"missing-id@icloud.com","label":"broken"}]
				}
			}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.body))
			}))
			defer ts.Close()

			client := &ICloudClient{client: ts.Client()}
			_, err := client.ListPrivacyMailboxes(t.Context(), ICloudSession{
				PremiumMailBaseURL: ts.URL,
				DSID:               "123",
				ClientID:           "cid",
				ClientBuildNumber:  "build",
				MasteringNumber:    "master",
				Host:               "www.icloud.com",
				Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
			})
			if !isCodedError(err, "icloud_mailbox_list_incomplete") {
				t.Fatalf("ListPrivacyMailboxes error = %#v, want icloud_mailbox_list_incomplete", err)
			}
		})
	}
}

func TestICloudClientListPrivacyMailboxesRejectsDuplicateRemoteIdentity(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": {
				"hmeEmails": [
					{"anonymousId":"duplicate-id","hme":"first-duplicate@icloud.com","isActive":true},
					{"anonymousId":"duplicate-id","hme":"second-duplicate@icloud.com","isActive":true}
				]
			}
		}`))
	}))
	defer ts.Close()

	client := &ICloudClient{client: ts.Client()}
	_, err := client.ListPrivacyMailboxes(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
	})
	if !isCodedError(err, "icloud_mailbox_list_incomplete") {
		t.Fatalf("duplicate remote identity error = %#v, want icloud_mailbox_list_incomplete", err)
	}
}

func TestICloudClientCreatePrivacyMailboxDefaultsMissingActiveToTrue(t *testing.T) {
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/hme/generate":
			_, _ = w.Write([]byte(`{"success":true,"timestamp":1,"result":{"hme":"candidate@icloud.com"}}`))
		case "POST /v1/hme/reserve":
			_, _ = w.Write([]byte(`{"success":true,"timestamp":1,"result":{"hme":{"anonymousId":"a1","hme":"created@icloud.com","label":"LAB","note":"note","forwardToEmail":"main@example.com"}}}`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	client := &ICloudClient{client: ts.Client()}
	remote, err := client.CreatePrivacyMailbox(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com", Path: "/"}},
		IsICloudPlus:       true,
		CanCreateHME:       true,
	}, "LAB", "note")
	if err != nil {
		t.Fatal(err)
	}
	if !remote.IsActive || remote.Email != "created@icloud.com" || remote.AnonymousID != "a1" {
		t.Fatalf("remote = %+v", remote)
	}
	if got := strings.Join(paths, "\n"); got != "POST /v1/hme/generate\nPOST /v1/hme/reserve" {
		t.Fatalf("paths = %q", got)
	}
}

func TestICloudClientCreatePrivacyMailboxAcceptsActiveField(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/hme/generate":
			_, _ = w.Write([]byte(`{"success":true,"timestamp":1,"result":{"hme":"candidate@icloud.com"}}`))
		case "POST /v1/hme/reserve":
			_, _ = w.Write([]byte(`{"success":true,"timestamp":1,"result":{"hme":{"anonymousId":"a1","hme":"created-inactive@icloud.com","label":"LAB","note":"note","forwardToEmail":"main@example.com","active":false}}}`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	client := &ICloudClient{client: ts.Client()}
	remote, err := client.CreatePrivacyMailbox(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
		IsICloudPlus:       true,
		CanCreateHME:       true,
	}, "LAB", "note")
	if err != nil {
		t.Fatal(err)
	}
	if remote.IsActive {
		t.Fatalf("remote = %+v, want inactive mailbox when active is false", remote)
	}
}

func TestICloudClientCreatePrivacyMailboxDefaultsMissingReserveActiveToTrue(t *testing.T) {
	var seenReserve bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/hme/generate":
			_, _ = w.Write([]byte(`{"success":true,"timestamp":1,"result":{"hme":"candidate@icloud.com"}}`))
		case "POST /v1/hme/reserve":
			seenReserve = true
			_, _ = w.Write([]byte(`{"success":true,"timestamp":1,"result":{"hme":{"anonymousId":"a1","hme":"created@icloud.com","label":"LAB","note":"note","forwardToEmail":"main@example.com"}}}`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	client := &ICloudClient{client: ts.Client()}
	remote, err := client.CreatePrivacyMailbox(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com", Path: "/"}},
		IsICloudPlus:       true,
		CanCreateHME:       true,
	}, "LAB", "note")
	if err != nil {
		t.Fatal(err)
	}
	if !seenReserve {
		t.Fatal("reserve request was not sent")
	}
	if !remote.IsActive || remote.Email != "created@icloud.com" {
		t.Fatalf("remote = %+v", remote)
	}
}

func TestICloudClientDeactivateAndDeletePrivacyMailbox(t *testing.T) {
	var paths []string
	var bodies []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, string(data))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"timestamp":1,"result":{}}`))
	}))
	defer ts.Close()

	client := &ICloudClient{client: ts.Client()}
	err := client.DeletePrivacyMailbox(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com", Path: "/"}},
	}, "anon-123")
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"POST /v1/hme/deactivate",
		"POST /v1/hme/delete",
	}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	for _, body := range bodies {
		if !strings.Contains(body, `"anonymousId":"anon-123"`) {
			t.Fatalf("body = %q, want anonymousId", body)
		}
	}
}

func TestUpsertMailboxFromRemoteCreatesAndUpdates(t *testing.T) {
	store := newTestStore(t)
	remote := ICloudRemoteMailbox{
		AnonymousID:    "a1",
		Email:          "Phone.Created@iCloud.com",
		Label:          "PHONE",
		ForwardToEmail: "main@example.com",
		IsActive:       true,
	}
	mailbox, created, err := store.UpsertMailboxFromRemote("usr_1", "acc_1", remote, "synced from iCloud")
	if err != nil {
		t.Fatal(err)
	}
	if !created || mailbox.OwnerID != "usr_1" || mailbox.AccountID != "acc_1" || mailbox.Email != "phone.created@icloud.com" || mailbox.Status != StatusAvailable {
		t.Fatalf("created mailbox = %+v created=%v", mailbox, created)
	}
	token := mailbox.APIToken

	remote.Label = "PHONE-UPDATED"
	remote.IsActive = false
	updated, created, err := store.UpsertMailboxFromRemote("usr_1", "", remote, "ignored")
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatalf("second upsert created=true, want update")
	}
	if updated.ID != mailbox.ID || updated.APIToken != token || updated.Label != "PHONE-UPDATED" || updated.ICloudActive {
		t.Fatalf("updated mailbox = %+v", updated)
	}
	if len(store.Snapshot().Mailboxes) != 1 {
		t.Fatalf("mailboxes len = %d, want 1", len(store.Snapshot().Mailboxes))
	}

	_, _, err = store.UpsertMailboxFromRemote("usr_2", "", remote, "")
	coded, ok := err.(codedError)
	if !ok || coded.code != "mailbox_exists_other_owner" {
		t.Fatalf("cross owner err = %T %+v, want mailbox_exists_other_owner", err, err)
	}
}

func TestUpsertMailboxFromRemoteUsesRemoteIdentityWhenEmailChanges(t *testing.T) {
	store := newTestStore(t)
	existing, err := store.AddMailboxForOwnerWithRemote("owner-identity-change", "account-identity-change", ICloudRemoteMailbox{
		AnonymousID: "stable-remote-id",
		Origin:      "ICLOUD_WEB",
		Email:       "old-address@icloud.com",
		Label:       "old",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	updated, created, err := store.UpsertMailboxFromRemote("owner-identity-change", "account-identity-change", ICloudRemoteMailbox{
		AnonymousID: "stable-remote-id",
		Origin:      "ICLOUD_WEB",
		Email:       "new-address@icloud.com",
		Label:       "new",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if created || updated.ID != existing.ID || updated.Email != "new-address@icloud.com" || updated.Label != "new" {
		t.Fatalf("remote identity update = %+v created=%v, want same mailbox with new email", updated, created)
	}
	if got := len(store.Snapshot().Mailboxes); got != 1 {
		t.Fatalf("mailbox count after remote identity update = %d, want 1", got)
	}
}

func TestUpsertMailboxFromRemoteRejectsAccountCollision(t *testing.T) {
	store := newTestStore(t)
	existing, err := store.AddMailboxForOwnerWithRemote("owner-account-collision", "account-old", ICloudRemoteMailbox{
		AnonymousID: "account-collision-id",
		Origin:      "ICLOUD_WEB",
		Email:       "account-collision@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = store.UpsertMailboxFromRemote("owner-account-collision", "account-new", ICloudRemoteMailbox{
		Email:    existing.Email,
		IsActive: true,
	}, "")
	if !isCodedError(err, "mailbox_remote_identity_conflict") {
		t.Fatalf("account collision error = %#v, want mailbox_remote_identity_conflict", err)
	}
	unchanged, _ := store.FindMailboxByID(existing.ID)
	if unchanged.AccountID != "account-old" || unchanged.RemoteAnonymousID != "account-collision-id" {
		t.Fatalf("existing mailbox changed after account collision: %+v", unchanged)
	}
}
func TestMailboxSyncAfterUsesCursorOverlap(t *testing.T) {
	now := time.Date(2026, 6, 22, 11, 0, 0, 0, time.UTC)
	mailbox := Mailbox{LastSyncAt: now.Add(-time.Minute)}
	got := mailboxSyncAfter(mailbox, now.Add(-5*time.Minute), now)
	want := now.Add(-time.Minute).Add(-mailboxSyncCursorOverlap)
	if !got.Equal(want) {
		t.Fatalf("mailboxSyncAfter() = %s, want %s", got, want)
	}

	got = mailboxSyncAfter(Mailbox{}, now.Add(-5*time.Minute), now)
	if !got.Equal(now.Add(-5 * time.Minute)) {
		t.Fatalf("mailboxSyncAfter(no cursor) = %s", got)
	}
}

func TestLooksLikeVerificationText(t *testing.T) {
	tests := []struct {
		text string
		want bool
	}{
		{text: "Your ChatGPT code is ready", want: true},
		{text: "验证码 123456", want: true},
		{text: "Ordinary newsletter", want: false},
	}
	for _, tt := range tests {
		if got := looksLikeVerificationText(tt.text, "OpenAI"); got != tt.want {
			t.Fatalf("looksLikeVerificationText(%q) = %v, want %v", tt.text, got, tt.want)
		}
	}
}

func TestIMAPQuoteEscapesUnsafeCharacters(t *testing.T) {
	got := imapQuote("a\"b\\c\r\n")
	if got != `"a\"b\\c"` {
		t.Fatalf("imapQuote() = %q", got)
	}
}

func TestSaveICloudIMAPLoginStoresStateWithoutReturningPassword(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	var checkedEmail, checkedPassword string
	server.checkIMAPLogin = func(ctx context.Context, email, appPassword string) error {
		checkedEmail = email
		checkedPassword = appPassword
		return nil
	}
	cookie, user := registerTestUser(t, handler, "imap-user", "imap123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/save", strings.NewReader(`{"email":"IMAP.User@iCloud.com","app_password":"app-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("save imap login status = %d body=%s", rr.Code, rr.Body.String())
	}
	if checkedEmail != "imap.user@icloud.com" || checkedPassword != "app-secret" {
		t.Fatalf("checked credentials = %q/%q", checkedEmail, checkedPassword)
	}
	if strings.Contains(rr.Body.String(), "app-secret") {
		t.Fatalf("response leaked app password: %s", rr.Body.String())
	}
	var body struct {
		Session publicICloudSession `json:"session"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Session.ICloudIMAPLoginSaved || !body.Session.ICloudIMAPLoginOK || body.Session.ICloudIMAPEmail != "imap.user@icloud.com" {
		t.Fatalf("public session missing imap state: %+v", body.Session)
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 1 {
		t.Fatalf("sessions len = %d, want 1", len(sessions))
	}
	state, ok := iCloudIMAPLoginState(sessions[0])
	if !ok || state.IMAPEmail != "imap.user@icloud.com" || state.IMAPAppPassword != "app-secret" || !state.LastCheckOK {
		t.Fatalf("saved imap state = %+v ok=%v", state, ok)
	}
}

func TestSaveICloudIMAPLoginCanAttachICloudMailAliasToDifferentAppleID(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	var checkedEmail, checkedPassword string
	server.checkIMAPLogin = func(ctx context.Context, email, appPassword string) error {
		checkedEmail = email
		checkedPassword = appPassword
		return nil
	}
	cookie, user := registerTestUser(t, handler, "imap-alias-user", "imap123")

	primaryAppleID := "primary.owner@example.com"
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID: user.ID,
		AppleID: primaryAppleID,
		LoginStates: []LoginState{{
			Kind:    LoginStateAppleAccount,
			Host:    "appleid.apple.com",
			Origin:  "https://account.apple.com",
			APIKey:  "api-key",
			Scnt:    "scnt",
			SavedAt: time.Now(),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 1 || strings.TrimSpace(sessions[0].AccountID) == "" {
		t.Fatalf("seed sessions = %+v", sessions)
	}
	accountID := sessions[0].AccountID
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID: user.ID,
		AppleID: "alias.one@icloud.com",
		LoginStates: []LoginState{{
			Kind:            LoginStateICloudIMAP,
			IMAPEmail:       "alias.one@icloud.com",
			IMAPAppPassword: "old-secret",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if sessions := store.ICloudSessionsForOwner(user.ID); len(sessions) != 2 {
		t.Fatalf("seed sessions len = %d, want 2", len(sessions))
	}

	rr := httptest.NewRecorder()
	payload := fmt.Sprintf(`{"account_id":%q,"email":"Alias.One@iCloud.com","app_password":"app-secret"}`, accountID)
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/save", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("save imap alias status = %d body=%s", rr.Code, rr.Body.String())
	}
	if checkedEmail != "alias.one@icloud.com" || checkedPassword != "app-secret" {
		t.Fatalf("checked credentials = %q/%q", checkedEmail, checkedPassword)
	}
	var body struct {
		Session publicICloudSession `json:"session"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Session.AccountID != accountID || body.Session.AppleID != primaryAppleID {
		t.Fatalf("response session = %+v, want account %s apple id %s", body.Session, accountID, primaryAppleID)
	}
	if !body.Session.ICloudIMAPLoginSaved || body.Session.ICloudIMAPEmail != "alias.one@icloud.com" {
		t.Fatalf("response imap state = %+v", body.Session)
	}
	sessions = store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 1 {
		t.Fatalf("sessions len = %d, want 1: %+v", len(sessions), sessions)
	}
	if accounts := store.SnapshotForOwner(user.ID).Accounts; len(accounts) != 1 {
		t.Fatalf("accounts len = %d, want 1: %+v", len(accounts), accounts)
	}
	if sessions[0].AppleID != primaryAppleID || sessions[0].AccountID != accountID {
		t.Fatalf("stored session identity = %+v", sessions[0])
	}
	state, ok := iCloudIMAPLoginState(sessions[0])
	if !ok || state.IMAPEmail != "alias.one@icloud.com" || state.IMAPAppPassword != "app-secret" {
		t.Fatalf("stored imap state = %+v ok=%v", state, ok)
	}
}

func TestSaveICloudIMAPLoginMatchesCreateAccountByEmailLocalPart(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.checkIMAPLogin = func(ctx context.Context, email, appPassword string) error {
		return nil
	}
	cookie, user := registerTestUser(t, handler, "imap-localpart-user", "imap123")

	primaryAppleID := "secondary.owner@example.com"
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID: user.ID,
		AppleID: primaryAppleID,
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Host:   "appleid.apple.com",
			Origin: "https://account.apple.com",
			APIKey: "api-key",
			Scnt:   "scnt",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	accountID := store.ICloudSessionsForOwner(user.ID)[0].AccountID

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/save", strings.NewReader(`{"email":"secondary.owner@icloud.com","app_password":"app-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("save imap alias status = %d body=%s", rr.Code, rr.Body.String())
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 1 {
		t.Fatalf("sessions len = %d, want 1: %+v", len(sessions), sessions)
	}
	if sessions[0].AccountID != accountID || sessions[0].AppleID != primaryAppleID {
		t.Fatalf("stored session identity = %+v", sessions[0])
	}
	state, ok := iCloudIMAPLoginState(sessions[0])
	if !ok || state.IMAPEmail != "secondary.owner@icloud.com" {
		t.Fatalf("stored imap state = %+v ok=%v", state, ok)
	}
}

func TestSaveICloudIMAPLoginMatchesAppleSecondaryEmailPrefix(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.checkIMAPLogin = func(ctx context.Context, email, appPassword string) error {
		return nil
	}
	cookie, user := registerTestUser(t, handler, "imap-prefix-user", "imap123")

	primaryAppleID := "primary.owner@example.com"
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID: user.ID,
		AppleID: primaryAppleID,
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	accountID := store.ICloudSessionsForOwner(user.ID)[0].AccountID
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID: user.ID,
		AppleID: "secondary.owner@example.com",
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Host:   "appleid.apple.com",
			Origin: "https://account.apple.com",
			APIKey: "api-key",
			Scnt:   "scnt",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/save", strings.NewReader(`{"email":"primary.owner@icloud.com","app_password":"app-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("save imap prefix alias status = %d body=%s", rr.Code, rr.Body.String())
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 2 {
		t.Fatalf("sessions len = %d, want 2: %+v", len(sessions), sessions)
	}
	var matched ICloudSession
	for _, session := range sessions {
		if session.AccountID == accountID {
			matched = session
			break
		}
	}
	if matched.AccountID != accountID || matched.AppleID != primaryAppleID {
		t.Fatalf("stored session identity = %+v", matched)
	}
	state, ok := iCloudIMAPLoginState(matched)
	if !ok || state.IMAPEmail != "primary.owner@icloud.com" {
		t.Fatalf("stored imap state = %+v ok=%v", state, ok)
	}
}

func TestSaveICloudIMAPLoginFailureDoesNotStorePassword(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.checkIMAPLogin = func(ctx context.Context, email, appPassword string) error {
		return errCode("imap_login_failed", "IMAP 登录失败", false)
	}
	cookie, user := registerTestUser(t, handler, "imap-fail", "imap123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/save", strings.NewReader(`{"email":"fail@icloud.com","app_password":"bad-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("save imap login failure status = %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "bad-secret") {
		t.Fatalf("error response leaked app password: %s", rr.Body.String())
	}
	if sessions := store.ICloudSessionsForOwner(user.ID); len(sessions) != 0 {
		t.Fatalf("sessions len = %d, want 0", len(sessions))
	}
}

func TestSetMailboxSyncCursor(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	syncedAt := time.Date(2026, 6, 22, 11, 1, 0, 0, time.UTC)
	updated, err := store.SetMailboxSyncCursor(mailbox.ID, syncedAt, "12345")
	if err != nil {
		t.Fatal(err)
	}
	if !updated.LastSyncAt.Equal(syncedAt) || updated.LastSyncUID != "12345" {
		t.Fatalf("updated cursor = %+v", updated)
	}
	stored, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || !stored.LastSyncAt.Equal(syncedAt) || stored.LastSyncUID != "12345" {
		t.Fatalf("stored cursor = %+v ok=%v", stored, ok)
	}
}

func TestUpsertMessageDeduplicatesRemoteID(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := store.UpsertMessage(mailbox.ID, "remote-1", "icloud", "code 123456", "noreply", "first", zeroTime()); err != nil || !created {
		t.Fatalf("first upsert created=%v err=%v", created, err)
	}
	if _, created, err := store.UpsertMessage(mailbox.ID, "remote-1", "icloud", "code 654321", "noreply", "updated", zeroTime()); err != nil || created {
		t.Fatalf("second upsert created=%v err=%v", created, err)
	}
	state := store.Snapshot()
	if len(state.Messages) != 1 {
		t.Fatalf("messages len = %d, want 1", len(state.Messages))
	}
	if state.Messages[0].Body != "updated" {
		t.Fatalf("message body = %q", state.Messages[0].Body)
	}
	if state.Mailboxes[0].ReceiveCount != 1 {
		t.Fatalf("receive_count = %d, want 1", state.Mailboxes[0].ReceiveCount)
	}
}

func TestFileStoreSetPathMigratesAndLoadsState(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.AddAccount("UPI-1", "user@example.com", ""); err != nil {
		t.Fatal(err)
	}
	nextPath := filepath.Join(t.TempDir(), "custom-data", "state.json")
	state, err := store.SetPath(nextPath)
	if err != nil {
		t.Fatal(err)
	}
	if store.Path() != nextPath {
		t.Fatalf("Path() = %q, want %q", store.Path(), nextPath)
	}
	if len(state.Accounts) != 1 {
		t.Fatalf("migrated accounts = %d, want 1", len(state.Accounts))
	}

	other := newTestStore(t)
	if _, err := other.AddMailbox("", "UPI-2", "alias@icloud.com"); err != nil {
		t.Fatal(err)
	}
	otherPath := other.Path()
	loaded, err := store.SetPath(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Mailboxes) != 1 || loaded.Mailboxes[0].Email != "alias@icloud.com" {
		t.Fatalf("loaded state = %+v", loaded)
	}
}

func TestRuntimeExportIncludesAccountsMailboxesAndSession(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.AddAccount("UPI-1", "user@example.com", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailbox("", "UPI-2", "alias@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSession(ICloudSession{DSID: "123", Cookies: []SessionCookie{{Name: "session", Value: "x"}}}); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export?owner_id=all", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Accounts      []Account      `json:"accounts"`
		Mailboxes     []Mailbox      `json:"mailboxes"`
		ICloudSession *ICloudSession `json:"icloud_session"`
		Messages      []Message      `json:"messages"`
		MessageCount  int            `json:"message_count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Accounts) != 1 || len(body.Mailboxes) != 1 || body.ICloudSession == nil {
		t.Fatalf("export body = %+v", body)
	}
	if len(body.Messages) != 0 || body.MessageCount != 0 {
		t.Fatalf("messages exported by default = %d count=%d", len(body.Messages), body.MessageCount)
	}
}

func TestMailboxAPITextExportIsScoped(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	userCookie, _ := registerTestUser(t, handler, "alice", "alice123")

	adminBox := createTestMailboxWithCookie(t, handler, adminCookie, "ADMIN", "admin-alias@icloud.com")
	userBox := createTestMailboxWithCookie(t, handler, userCookie, "USER", "user-alias@icloud.com")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(userCookie)
	addClosureTestCSRF(req, userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("user mailbox api export status = %d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type = %q, want text/plain", ct)
	}
	userBody := rr.Body.String()
	if !strings.Contains(userBody, userBox.Email+"----"+userBox.APIURL) {
		t.Fatalf("user export missing own mailbox api: %q", userBody)
	}
	if strings.Contains(userBody, userBox.APIURL+"----") {
		t.Fatalf("user export still has token column: %q", userBody)
	}
	if strings.Contains(userBody, adminBox.Email) {
		t.Fatalf("user export leaked admin mailbox: %q", userBody)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis?owner_id=all", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin mailbox api export status = %d body=%s", rr.Code, rr.Body.String())
	}
	adminBody := rr.Body.String()
	for _, row := range []string{adminBox.Email + "----" + adminBox.APIURL, userBox.Email + "----" + userBox.APIURL} {
		if !strings.Contains(adminBody, row) {
			t.Fatalf("admin export missing row %q in %q", row, adminBody)
		}
		if strings.Contains(adminBody, strings.SplitN(row, "----", 2)[1]+"----") {
			t.Fatalf("admin export still has token column for %q in %q", row, adminBody)
		}
	}
}

func TestMailboxEmailExportFormatsAreScoped(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	userCookie, _ := registerTestUser(t, handler, "alice", "alice123")

	adminBox := createTestMailboxWithCookie(t, handler, adminCookie, "ADMIN", "admin-alias@icloud.com")
	userBox := createTestMailboxWithCookie(t, handler, userCookie, "USER", "user-alias@icloud.com")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-emails?format=csv", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(userCookie)
	addClosureTestCSRF(req, userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("user mailbox email export status = %d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type = %q, want text/csv", ct)
	}
	userBody := rr.Body.String()
	if !strings.Contains(userBody, userBox.Email+"\n") {
		t.Fatalf("user export missing own email: %q", userBody)
	}
	if strings.Contains(userBody, adminBox.Email) || strings.Contains(userBody, "----") {
		t.Fatalf("user email export leaked admin/API data: %q", userBody)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-emails?format=tsv&owner_id=all", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin mailbox email export status = %d body=%s", rr.Code, rr.Body.String())
	}
	adminBody := rr.Body.String()
	for _, email := range []string{adminBox.Email + "\n", userBox.Email + "\n"} {
		if !strings.Contains(adminBody, email) {
			t.Fatalf("admin export missing email %q in %q", email, adminBody)
		}
	}
}

func TestMailboxAPIExportMarksMailboxesAsExported(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")

	mailbox := createTestMailboxWithCookie(t, handler, adminCookie, "ADMIN", "export-mark@icloud.com")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis", strings.NewReader(`{"format":"txt"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("api export status = %d body=%s", rr.Code, rr.Body.String())
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing after export")
	}
	if updated.APIExportedAt.IsZero() {
		t.Fatalf("APIExportedAt = zero, want exported mark")
	}
	req = httptest.NewRequest(http.MethodGet, "/api/mailboxes?api_exported=1", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("filtered list status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Mailboxes) != 1 || body.Mailboxes[0].ID != mailbox.ID || !body.Mailboxes[0].APIExported {
		t.Fatalf("filtered exported mailboxes = %+v", body.Mailboxes)
	}
}

func TestMailboxGETAPIExportRequiresPost(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "get-export-no-mark", "admin123")

	mailbox := createTestMailboxWithCookie(t, handler, adminCookie, "ADMIN", "get-export-no-mark@icloud.com")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-apis", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET api export status = %d body=%s, want 405", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("GET api export Allow = %q, want %q", got, http.MethodPost)
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "mailbox_api_export_requires_post" {
		t.Fatalf("GET API export code = %q", body.Code)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing after GET export")
	}
	if !updated.APIExportedAt.IsZero() {
		t.Fatalf("GET API export marked mailbox as exported: %+v", updated)
	}
}

func TestMailboxAPIExportRejectsNonJSONPost(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "export-non-json", "admin123")
	mailbox := createTestMailboxWithCookie(t, handler, adminCookie, "ADMIN", "export-non-json@icloud.com")

	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis", strings.NewReader("format=txt"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-JSON API export status = %d body=%s, want 415", rr.Code, rr.Body.String())
	}
	var response struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Code != "mailbox_api_export_requires_json" {
		t.Fatalf("non-JSON API export code = %q", response.Code)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing after non-JSON API export")
	}
	if !updated.APIExportedAt.IsZero() {
		t.Fatalf("non-JSON API export marked mailbox as exported: %+v", updated)
	}
}

func TestMailboxExportRejectsEmptySelectedIDs(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "empty-export", "admin123")
	_ = createTestMailboxWithCookie(t, handler, adminCookie, "ONE", "empty-export@icloud.com")

	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis?ids=", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty selected export status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "mailbox_ids_missing" {
		t.Fatalf("empty selected export code = %q", body.Code)
	}
}

func TestMailboxExportRejectsEmptyRenderedResult(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "api", method: http.MethodPost, path: "/api/runtime/export-mailbox-apis"},
		{name: "email", method: http.MethodPost, path: "/api/runtime/export-mailbox-emails"},
	}
	formats := []string{"txt", "csv", "tsv", "jsonl"}
	for _, test := range tests {
		for _, format := range formats {
			t.Run(test.name+"-"+format, func(t *testing.T) {
				store := newTestStore(t)
				handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
				adminCookie, _ := registerTestUser(t, handler, "empty-result-"+test.name+"-"+format, "admin123")
				mailbox := createTestMailboxWithCookie(t, handler, adminCookie, "EMPTY", "empty-result-"+test.name+"-"+format+"@icloud.com")

				path := test.path + "?format=" + url.QueryEscape(format) + "&search=does-not-exist"
				var body io.Reader = strings.NewReader(`{}`)
				req := httptest.NewRequest(test.method, path, body)
				req.Header.Set("Content-Type", "application/json")
				req.AddCookie(adminCookie)
				addClosureTestCSRF(req, adminCookie)
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)
				if rr.Code != http.StatusNotFound {
					t.Fatalf("empty %s export status = %d body=%s, want 404", test.name, rr.Code, rr.Body.String())
				}
				if got := rr.Header().Get("Content-Disposition"); got != "" {
					t.Fatalf("empty %s export Content-Disposition = %q, want empty", test.name, got)
				}
				var response struct {
					Code string `json:"code"`
				}
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Fatalf("decode empty %s export response: %v; body=%s", test.name, err, rr.Body.String())
				}
				if response.Code != "mailbox_export_empty" {
					t.Fatalf("empty %s export code = %q, want mailbox_export_empty", test.name, response.Code)
				}
				updated, ok := store.FindMailboxByID(mailbox.ID)
				if !ok {
					t.Fatal("mailbox disappeared after empty export")
				}
				if !updated.APIExportedAt.IsZero() {
					t.Fatalf("empty export marked mailbox as exported: %+v", updated)
				}
			})
		}
	}
}

func TestMailboxExportRejectsNullSelectedIDs(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "null-export", "admin123")
	_ = createTestMailboxWithCookie(t, handler, adminCookie, "ONE", "null-export@icloud.com")

	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis", strings.NewReader(`{"format":"txt","ids":null}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("null selected export status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "mailbox_ids_missing" {
		t.Fatalf("null selected export code = %q", body.Code)
	}
}

func TestMailboxExportRejectsSelectedIDsWithoutAccessibleMatches(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "missing-selected-export", "admin123")
	_ = createTestMailboxWithCookie(t, handler, adminCookie, "ONE", "selected-present@icloud.com")

	body, err := json.Marshal(map[string]any{
		"format": "txt",
		"ids":    []string{"missing-mailbox-id"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing selected export status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != "mailbox_not_found" {
		t.Fatalf("missing selected export code = %q", resp.Code)
	}
}

func TestMailboxExportRejectsPartiallyMissingSelectedIDs(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "partial-selected-export", "admin123")
	mailbox := createTestMailboxWithCookie(t, handler, adminCookie, "ONE", "partial-selected@icloud.com")

	body, err := json.Marshal(map[string]any{
		"format": "txt",
		"ids":    []string{mailbox.ID, "missing-mailbox-id"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("partial selected export status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != "mailbox_selection_changed" {
		t.Fatalf("partial selected export code = %q", resp.Code)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing after rejected partial export")
	}
	if !updated.APIExportedAt.IsZero() {
		t.Fatalf("partially rejected export marked mailbox: %+v", updated)
	}
}

func TestMailboxListRejectsInvalidExportedFilter(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "invalid-export-filter-list", "admin123")

	req := httptest.NewRequest(http.MethodGet, "/api/mailboxes?api_exported=maybe", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid exported list filter status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != "invalid_export_filter" {
		t.Fatalf("invalid exported list filter code = %q", resp.Code)
	}
}

func TestMailboxExportRejectsInvalidExportedFilter(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "invalid-export-filter-export", "admin123")

	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-emails?api_exported=maybe", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid exported export filter status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != "invalid_export_filter" {
		t.Fatalf("invalid exported export filter code = %q", resp.Code)
	}
}

func TestMailboxListSearchRespectsAccountFilter(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "search-filter", "admin123")
	accOne, err := store.AddAccountForOwner("", "Apple One", "one@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	accTwo, err := store.AddAccountForOwner("", "Apple Two", "two@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", accOne.ID, "Shared Alpha", "shared-alpha@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", accTwo.ID, "Shared Beta", "shared-beta@icloud.com"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/mailboxes?owner_id=all&account_key="+url.QueryEscape(accOne.ID)+"&search=shared", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Mailboxes) != 1 {
		t.Fatalf("mailboxes len = %d, want 1", len(body.Mailboxes))
	}
	if body.Mailboxes[0].AccountID != accOne.ID {
		t.Fatalf("mailbox account = %q, want %q", body.Mailboxes[0].AccountID, accOne.ID)
	}
}

func TestDeleteMailboxCanDeleteRemoteMailbox(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger()).(*Server)
	adminCookie, admin := registerTestUser(t, handler, "admin", "admin123")
	mailbox, err := store.AddMailboxForOwnerWithRemote(admin.ID, "account-remote-delete", ICloudRemoteMailbox{
		AnonymousID: "remote-delete-hook",
		Origin:      "APPLE_ACCOUNT",
		Email:       "remote-delete@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	saveTestAppleAccountSession(t, store, admin.ID, "account-remote-delete", "remote-delete@example.com")
	called := false
	handler.deleteRemoteMailbox = func(ctx context.Context, remote Mailbox) error {
		called = true
		if remote.ID != mailbox.ID {
			t.Fatalf("remote mailbox = %+v, want %s", remote, mailbox.ID)
		}
		return nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/mailboxes/"+mailbox.ID+"?delete_remote=1", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !called {
		t.Fatal("remote delete hook not called")
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("mailbox still exists after delete")
	}
}

func TestBulkDeleteMailboxesCanDeleteRemoteMailbox(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger()).(*Server)
	adminCookie, admin := registerTestUser(t, handler, "admin", "admin123")
	first, err := store.AddMailboxForOwnerWithRemote(admin.ID, "account-bulk-remote", ICloudRemoteMailbox{
		AnonymousID: "bulk-remote-1",
		Origin:      "APPLE_ACCOUNT",
		Email:       "one-delete@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddMailboxForOwnerWithRemote(admin.ID, "account-bulk-remote", ICloudRemoteMailbox{
		AnonymousID: "bulk-remote-2",
		Origin:      "APPLE_ACCOUNT",
		Email:       "two-delete@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	saveTestAppleAccountSession(t, store, admin.ID, "account-bulk-remote", "bulk-remote@example.com")
	called := []string{}
	handler.deleteRemoteMailbox = func(ctx context.Context, remote Mailbox) error {
		called = append(called, remote.ID)
		return nil
	}

	body := fmt.Sprintf(`{"ids":[%q,%q],"delete_remote":true}`, first.ID, second.ID)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/bulk-delete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("bulk delete status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Deleted       int `json:"deleted"`
		RemoteDeleted int `json:"remote_deleted"`
		Failed        int `json:"failed"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Deleted != 2 || resp.RemoteDeleted != 2 || resp.Failed != 0 {
		t.Fatalf("bulk delete response = %+v", resp)
	}
	if !reflect.DeepEqual(called, []string{first.ID, second.ID}) {
		t.Fatalf("remote delete calls = %#v", called)
	}
	if _, ok := store.FindMailboxByID(first.ID); ok {
		t.Fatal("first mailbox still exists")
	}
	if _, ok := store.FindMailboxByID(second.ID); ok {
		t.Fatal("second mailbox still exists")
	}
}

func TestMailboxExportFiltersByAccountID(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	accOne, err := store.AddAccountForOwner("", "Apple One", "one@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	accTwo, err := store.AddAccountForOwner("", "Apple Two", "two@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", accOne.ID, "ONE", "one-alias@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", accTwo.ID, "TWO", "two-alias@icloud.com"); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis?owner_id=all&account_id="+url.QueryEscape(accOne.ID), strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("account filtered api export status = %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "one-alias@icloud.com----https://mail.example/api/v1/mailboxes/one-alias@icloud.com/code?key=") {
		t.Fatalf("filtered export missing account one API: %q", body)
	}
	if strings.Contains(body, "/code----") {
		t.Fatalf("filtered export still has token column: %q", body)
	}
	if strings.Contains(body, "two-alias@icloud.com") {
		t.Fatalf("filtered export leaked account two: %q", body)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-emails?format=jsonl&owner_id=all&account_id="+url.QueryEscape(accTwo.ID), strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("account filtered email export status = %d body=%s", rr.Code, rr.Body.String())
	}
	body = rr.Body.String()
	if !strings.Contains(body, `"email":"two-alias@icloud.com"`) || strings.Contains(body, "one-alias@icloud.com") || strings.Contains(body, "/api/v1/") {
		t.Fatalf("filtered email export body = %q", body)
	}
}

func TestMailboxExportFiltersGlobalOwnerSentinel(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	globalAccount, err := store.AddAccountForOwner("", "Global Apple", "global@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	userAccount, err := store.AddAccountForOwner("owner-global-export", "User Apple", "user@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", globalAccount.ID, "GLOBAL", "global-alias@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("owner-global-export", userAccount.ID, "USER", "user-alias@icloud.com"); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis?owner_id=__global", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("global owner export status = %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "global-alias@icloud.com----https://mail.example/api/v1/mailboxes/global-alias@icloud.com/code?key=") {
		t.Fatalf("global owner export missing global mailbox API: %q", body)
	}
	if strings.Contains(body, "/code----") {
		t.Fatalf("global owner export still has token column: %q", body)
	}
	if strings.Contains(body, "user-alias@icloud.com") {
		t.Fatalf("global owner export leaked user mailbox: %q", body)
	}
}

func TestMailboxExportPostJSONFiltersByAccountID(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "post-account-filter", "admin123")
	accOne, err := store.AddAccountForOwner("", "Apple One", "one@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	accTwo, err := store.AddAccountForOwner("", "Apple Two", "two@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", accOne.ID, "ONE", "post-one@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", accTwo.ID, "TWO", "post-two@icloud.com"); err != nil {
		t.Fatal(err)
	}

	payload, err := json.Marshal(map[string]any{
		"format":     "jsonl",
		"account_id": accTwo.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-emails?owner_id=all", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("post account filtered export status = %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"email":"post-two@icloud.com"`) || strings.Contains(body, "post-one@icloud.com") {
		t.Fatalf("post account filtered export body = %q", body)
	}
}

func TestMailboxAPIJSONLExportKeepsSeparateTokenField(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "jsonl-api-export", "admin123")
	box := createTestMailboxWithCookie(t, handler, adminCookie, "API", "jsonl-api@icloud.com")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis", strings.NewReader(`{"format":"jsonl"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("jsonl api export status = %d body=%s", rr.Code, rr.Body.String())
	}
	var line struct {
		Email    string `json:"email"`
		APIURL   string `json:"api_url"`
		APIToken string `json:"api_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &line); err != nil {
		t.Fatalf("jsonl decode: %v body=%s", err, rr.Body.String())
	}
	if line.Email != box.Email || line.APIToken != box.APIToken {
		t.Fatalf("jsonl line = %+v, want email/token from mailbox", line)
	}
	if !strings.Contains(line.APIURL, "key="+url.QueryEscape(box.APIToken)) {
		t.Fatalf("jsonl api_url missing mailbox key: %q", line.APIURL)
	}
	if strings.Contains(line.APIURL, "wait_ms=") {
		t.Fatalf("jsonl api_url must not embed wait_ms: %q", line.APIURL)
	}
}

func TestMailboxExportFiltersByAPIExportedState(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "export-state-filter", "admin123")
	exported := createTestMailboxWithCookie(t, handler, adminCookie, "DONE", "already-exported@icloud.com")
	unexported := createTestMailboxWithCookie(t, handler, adminCookie, "PENDING", "not-yet-exported@icloud.com")
	if _, err := store.MarkMailboxesAPIExported([]string{exported.ID}, time.Now()); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-emails?api_exported=0", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unexported filtered export status = %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if body != unexported.Email+"\n" {
		t.Fatalf("unexported filtered export body = %q", body)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-emails?api_exported=1", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("exported filtered export status = %d body=%s", rr.Code, rr.Body.String())
	}
	body = rr.Body.String()
	if body != exported.Email+"\n" {
		t.Fatalf("exported filtered export body = %q", body)
	}
}

func TestMailboxExportFiltersBySearchKeyword(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "export-search-filter", "admin123")
	if _, err := store.AddMailboxForOwner("", "", "Alpha", "alpha-search@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", "", "Beta", "beta-other@icloud.com"); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-emails?owner_id=all&search=alpha", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("search filtered export status = %d body=%s", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); body != "alpha-search@icloud.com\n" {
		t.Fatalf("search filtered export body = %q", body)
	}
}

func TestMailboxExportFiltersUnboundMailboxes(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	account, err := store.AddAccountForOwner("", "Bound Apple", "bound@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", "", "UNBOUND", "unbound@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", account.ID, "BOUND", "bound@icloud.com"); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-emails?owner_id=all&account_id=unbound", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unbound email export status = %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if body != "unbound@icloud.com\n" {
		t.Fatalf("unbound email export body = %q", body)
	}
}

func TestMailboxExportAdminOwnerAndAccountFilter(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	_, normalUser := registerTestUser(t, handler, "alice", "alice123")
	adminAcc, err := store.AddAccountForOwner("", "Admin Apple", "admin@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	userAcc, err := store.AddAccountForOwner(normalUser.ID, "User Apple", "user@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", adminAcc.ID, "ADMIN", "admin-only@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner(normalUser.ID, userAcc.ID, "USER", "user-only@icloud.com"); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-emails?owner_id="+url.QueryEscape(normalUser.ID)+"&account_id="+url.QueryEscape(userAcc.ID), strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("owner/account filtered export status = %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "user-only@icloud.com\n") || strings.Contains(body, "admin-only@icloud.com") {
		t.Fatalf("owner/account filtered export body = %q", body)
	}
}

func TestMailboxExportRejectsInvalidFormat(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-emails?format=xlsx", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid format status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserLoginScopesDataAndFirstUserIsAdmin(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())

	adminCookie, adminUser := registerTestUser(t, handler, "admin", "admin123")
	userCookie, normalUser := registerTestUser(t, handler, "alice", "alice123")
	if !adminUser.IsAdmin {
		t.Fatalf("first registered user should be admin: %+v", adminUser)
	}
	if normalUser.IsAdmin {
		t.Fatalf("second registered user should be normal: %+v", normalUser)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin auth me = %d body=%s", rr.Code, rr.Body.String())
	}
	var me struct {
		Authenticated bool       `json:"authenticated"`
		User          publicUser `json:"user"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if !me.Authenticated || me.User.Username != "admin" || !me.User.IsAdmin {
		t.Fatalf("admin auth me = %+v", me)
	}

	createTestMailboxWithCookie(t, handler, adminCookie, "ADMIN-MBX", "admin@icloud.com")
	userMailbox := createTestMailboxWithCookie(t, handler, userCookie, "USER-MBX", "alice@icloud.com")

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/mailboxes", nil)
	req.AddCookie(userCookie)
	addClosureTestCSRF(req, userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("user list mailboxes = %d body=%s", rr.Code, rr.Body.String())
	}
	var userList struct {
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &userList); err != nil {
		t.Fatal(err)
	}
	if len(userList.Mailboxes) != 1 || userList.Mailboxes[0].Email != "alice@icloud.com" {
		t.Fatalf("user scoped mailboxes = %+v", userList.Mailboxes)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/manage/data", nil)
	req.AddCookie(userCookie)
	addClosureTestCSRF(req, userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("user manage data = %d body=%s", rr.Code, rr.Body.String())
	}
	var userManageData struct {
		UserSummaries []publicUserSummary `json:"user_summaries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &userManageData); err != nil {
		t.Fatal(err)
	}
	if len(userManageData.UserSummaries) != 1 || userManageData.UserSummaries[0].OwnerID != normalUser.ID || userManageData.UserSummaries[0].MailboxCount != 1 {
		t.Fatalf("user summaries = %+v, want one scoped summary with one mailbox", userManageData.UserSummaries)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/manage/data", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin manage data = %d body=%s", rr.Code, rr.Body.String())
	}
	var adminData struct {
		IsAdmin       bool                `json:"is_admin"`
		Users         []publicUser        `json:"users"`
		UserSummaries []publicUserSummary `json:"user_summaries"`
		Mailboxes     []publicMailbox     `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &adminData); err != nil {
		t.Fatal(err)
	}
	if !adminData.IsAdmin || len(adminData.Users) != 2 || len(adminData.Mailboxes) != 2 {
		t.Fatalf("admin manage data = %+v", adminData)
	}
	summaryByOwner := map[string]publicUserSummary{}
	for _, summary := range adminData.UserSummaries {
		summaryByOwner[summary.OwnerID] = summary
	}
	if summaryByOwner[adminUser.ID].MailboxCount != 1 || summaryByOwner[normalUser.ID].MailboxCount != 1 {
		t.Fatalf("admin user summaries = %+v, want both users with one mailbox", adminData.UserSummaries)
	}
	if adminData.Mailboxes[0].OwnerID == "" || adminData.Mailboxes[1].OwnerID == "" {
		t.Fatalf("mailboxes should expose owner_id for admin filtering: %+v", adminData.Mailboxes)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+userMailbox.ID+"/status", strings.NewReader(`{"status":"used"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin mutate user mailbox = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAdminCanDeleteNormalUserAndOwnedData(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())

	adminCookie, adminUser := registerTestUser(t, handler, "admin", "admin123")
	userCookie, normalUser := registerTestUser(t, handler, "alice", "alice123")
	account, err := store.AddAccountForOwner(normalUser.ID, "Alice Apple", "alice@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(normalUser.ID, ICloudSession{
		OwnerID: normalUser.ID,
		AppleID: "alice@example.com",
		DSID:    "alice-dsid",
		Cookies: []SessionCookie{{Name: "session", Value: "secret"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(normalUser.ID, account.ID, "ALICE", "alice-alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "Your OpenAI code is 123456", "noreply@example.com", "123456", time.Now()); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+normalUser.ID, nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin delete user = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Deleted DeleteUserResult `json:"deleted"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Deleted.UserID != normalUser.ID || body.Deleted.Accounts != 1 || body.Deleted.Mailboxes != 1 || body.Deleted.Messages != 1 || body.Deleted.ICloudSessions != 1 || body.Deleted.WebSessions == 0 {
		t.Fatalf("deleted result = %+v", body.Deleted)
	}

	state := store.Snapshot()
	if len(state.Users) != 1 || state.Users[0].ID != adminUser.ID {
		t.Fatalf("users after delete = %+v", state.Users)
	}
	if len(state.Accounts) != 0 || len(state.Mailboxes) != 0 || len(state.Messages) != 0 || len(state.ICloudSessions) != 0 {
		t.Fatalf("owned data after delete accounts=%d mailboxes=%d messages=%d sessions=%d", len(state.Accounts), len(state.Mailboxes), len(state.Messages), len(state.ICloudSessions))
	}
	for _, session := range state.WebSessions {
		if session.UserID == normalUser.ID {
			t.Fatalf("deleted user session still present: %+v", session)
		}
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/manage/data", nil)
	req.AddCookie(userCookie)
	addClosureTestCSRF(req, userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("deleted user manage data = %d body=%s, want 401", rr.Code, rr.Body.String())
	}
}

func TestAdminDeleteUserRejectsSelfAndAdminAccounts(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())

	adminCookie, adminUser := registerTestUser(t, handler, "admin", "admin123")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+adminUser.ID, nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "cannot_delete_self") {
		t.Fatalf("admin self delete = %d body=%s", rr.Code, rr.Body.String())
	}

	secondAdmin, err := store.CreateUser("second-admin", "admin123")
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	for i := range store.state.Users {
		if store.state.Users[i].ID == secondAdmin.ID {
			store.state.Users[i].IsAdmin = true
		}
	}
	if err := store.saveLocked(); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	store.mu.Unlock()
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+secondAdmin.ID, nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "cannot_delete_admin_user") {
		t.Fatalf("delete other admin = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSensitiveKeysAreNotAcceptedFromQueryString(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{APIKey: "global-secret"}, store, discardLogger())

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "management query key rejected",
			method: http.MethodGet,
			path:   "/api/status?admin_key=admin-secret",
		},
		{
			name:   "global api key query rejected on claim",
			method: http.MethodPost,
			path:   "/api/v1/mailboxes/claim?key=global-secret",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s = %d body=%s, want 401", tt.method, tt.path, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestMailboxCodeQueryAcceptsOnlyPerMailboxToken(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "Your OpenAI code is 135790", "noreply@example.com", "Use 135790 to continue.", time.Now()); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{APIKey: "global-secret"}, store, discardLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/alias%40icloud.com/code?key=global-secret&after=2000-01-01T00:00:00Z", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code with global query key = %d body=%s, want 401", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/alias%40icloud.com/code?key="+mailbox.APIToken+"&after=2000-01-01T00:00:00Z", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code with mailbox query key = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "135790" {
		t.Fatalf("code body = %+v", body)
	}
}

func TestMailboxCodeQuerySyncsBeforeReturningCachedOldCode(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-fresh"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-fresh@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "ChatGPT code", "noreply@example.com", "Use 111111 to continue.", time.Now().Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	var calls int64
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		atomic.AddInt64(&calls, 1)
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "remote-new",
				UID:        "2",
				Subject:    "ChatGPT code",
				Body:       "Use 222222 to continue.",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}

	rr := httptest.NewRecorder()
	lookupAfter := time.Now().Add(-10 * time.Second).UTC().Format(time.RFC3339Nano)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+"&after="+url.QueryEscape(lookupAfter), nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code request = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success   bool   `json:"success"`
		Code      string `json:"code"`
		MessageID string `json:"message_id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "222222" {
		t.Fatalf("code body = %+v, want fresh 222222", body)
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("sync calls = %d, want 1", got)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing")
	}
	if updated.LastCodeMessageID == "" || updated.LastCodeMessageID != body.MessageID {
		t.Fatalf("LastCodeMessageID=%q response message_id=%q", updated.LastCodeMessageID, body.MessageID)
	}
}

func TestMailboxCodeQueryReturnsLocalCachedCodeBeforeSync(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-code-local-first"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-local@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "ChatGPT code", "noreply@example.com", "Use 333333 to continue.", time.Now()); err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	var calls int64
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		atomic.AddInt64(&calls, 1)
		return nil, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken, nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code request = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "333333" {
		t.Fatalf("code body = %+v, want local cached 333333", body)
	}
	if got := atomic.LoadInt64(&calls); got != 0 {
		t.Fatalf("sync calls = %d, want 0", got)
	}
}

func TestMailWatcherPreloadsCodeMessages(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-mail-watcher"
	accountID := "acc-mail-watcher"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, accountID, "watcher-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "UPI-1", "watcher@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{
		MailWatcherEnabled:           true,
		MailWatcherFetchLimit:        8,
		MailWatcherInitialFetchLimit: 20,
		MailWatcherLookbackHours:     24,
		PublicSyncMinIntervalMS:      1,
	}, store, discardLogger())
	server := handler.(*Server)
	var gotMaxThreads int
	var gotAfter time.Time
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		gotMaxThreads = maxMessages
		gotAfter = after
		if len(mailboxes) != 1 || mailboxes[0].ID != mailbox.ID {
			t.Fatalf("mailboxes = %+v, want only %s", mailboxes, mailbox.ID)
		}
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "remote-watcher",
				UID:        "10",
				Subject:    "ChatGPT code",
				Body:       "Use 555555 to continue.",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}

	server.markMailWatcherActive(mailbox.ID)
	server.syncMailWatcherRound(context.Background(), true)
	if gotMaxThreads != 20 {
		t.Fatalf("maxThreads = %d, want initial fetch limit 20", gotMaxThreads)
	}
	if gotAfter.IsZero() || time.Since(gotAfter) < 23*time.Hour {
		t.Fatalf("watcher initial after = %v, want roughly 24h lookback", gotAfter)
	}
	if msg, code, ok := latestMailboxCode(store.MessagesForMailbox(mailbox.ID), time.Time{}, "ChatGPT", time.Now()); !ok || code != "555555" || msg.RemoteID != "remote-watcher" {
		t.Fatalf("stored code = msg:%+v code:%q ok:%v, want watcher code 555555", msg, code, ok)
	}
}

func TestMailWatcherPreloadsAPIActiveMailboxesWithoutPriorCodeRequest(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-mail-watcher-auto"
	accountID := "acc-mail-watcher-auto"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, accountID, "watcher-auto@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "UPI-1", "auto-watcher@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{
		MailWatcherEnabled:           true,
		MailWatcherFetchLimit:        8,
		MailWatcherInitialFetchLimit: 20,
		MailWatcherLookbackHours:     24,
		PublicSyncMinIntervalMS:      1,
	}, store, discardLogger())
	server := handler.(*Server)
	var synced int64
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		atomic.AddInt64(&synced, 1)
		if len(mailboxes) != 1 || mailboxes[0].ID != mailbox.ID {
			t.Fatalf("mailboxes = %+v, want auto included %s", mailboxes, mailbox.ID)
		}
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "remote-auto-watcher",
				UID:        "12",
				Subject:    "ChatGPT code",
				Body:       "Use 888888 to continue.",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}

	server.syncMailWatcherRound(context.Background(), true)
	if atomic.LoadInt64(&synced) != 1 {
		t.Fatalf("watcher sync calls = %d, want 1", synced)
	}
	if msg, code, ok := latestMailboxCode(store.MessagesForMailbox(mailbox.ID), time.Time{}, "ChatGPT", time.Now()); !ok || code != "888888" || msg.RemoteID != "remote-auto-watcher" {
		t.Fatalf("stored code = msg:%+v code:%q ok:%v, want auto watcher code 888888", msg, code, ok)
	}
}

func TestMailboxCodeQueryReturnsQuicklyWhileBackgroundSyncContinues(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-fast"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-fast@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "fast@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{PublicFastSyncWaitMS: 20, PublicSyncMinIntervalMS: 1}, store, discardLogger())
	server := handler.(*Server)
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		startedOnce.Do(func() { close(started) })
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "remote-fast",
				UID:        "9",
				Subject:    "ChatGPT code",
				Body:       "Use 444444 to continue.",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}

	start := time.Now()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken, nil)
	handler.ServeHTTP(rr, req)
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("code request took %v, want quick no_code response", elapsed)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("code request = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Success || body.Code != "no_code" {
		t.Fatalf("first response = %+v, want no_code while background sync continues", body)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background sync did not start")
	}
	close(release)

	deadline := time.Now().Add(time.Second)
	for {
		if msg, code, ok := latestMailboxCode(store.MessagesForMailbox(mailbox.ID), time.Time{}, "ChatGPT", time.Now()); ok && code == "444444" {
			if msg.RemoteID != "remote-fast" {
				t.Fatalf("message remote id = %q, want remote-fast", msg.RemoteID)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("background sync did not store code, messages=%+v", store.MessagesForMailbox(mailbox.ID))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMailboxCodeQueryWaitMSWaitsForSyncResult(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-wait-ms"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-wait@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "wait@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{PublicFastSyncWaitMS: 20, PublicSyncMinIntervalMS: 1}, store, discardLogger())
	server := handler.(*Server)
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		time.Sleep(100 * time.Millisecond)
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "remote-wait",
				UID:        "11",
				Subject:    "ChatGPT code",
				Body:       "Use 777777 to continue.",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+"&wait_ms=500", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code request = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "777777" {
		t.Fatalf("code body = %+v, want waited code 777777", body)
	}
}

func TestPublicMailboxCodeDocumentNavigationSkipsWaitAndSync(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-navigate"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-navigate@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "navigate@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{PublicFastSyncWaitMS: 20, PublicSyncMinIntervalMS: 1}, store, discardLogger())
	server := handler.(*Server)
	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	var startedOnce sync.Once
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		startedOnce.Do(func() { close(started) })
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return map[string][]ICloudSyncedMessage{}, nil
	}

	start := time.Now()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+"&wait_ms=5000", nil)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Site", "none")
	handler.ServeHTTP(rr, req)
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("browser document GET took %v, want cache-only no_code without IMAP wait", elapsed)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("code request = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Success || body.Code != "no_code" {
		t.Fatalf("document navigation response = %+v, want no_code", body)
	}
	select {
	case <-started:
		t.Fatal("browser document GET must not start IMAP sync")
	case <-time.After(80 * time.Millisecond):
	}
}

func TestMailboxCodeQueryReturnsCodeInsertedDuringWaitTimeout(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })
	oldLocalPoll := mailboxCodeLocalPollInterval
	mailboxCodeLocalPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { mailboxCodeLocalPollInterval = oldLocalPoll })

	store := newTestStore(t)
	ownerID := "owner-code-timeout-cache"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-timeout@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "timeout@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{PublicFastSyncWaitMS: 20, PublicSyncMinIntervalMS: 1}, store, discardLogger())
	server := handler.(*Server)
	started := make(chan struct{})
	release := make(chan struct{})
	syncDone := make(chan struct{})
	insertDone := make(chan struct{})
	var startedOnce sync.Once
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		defer close(syncDone)
		startedOnce.Do(func() { close(started) })
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return map[string][]ICloudSyncedMessage{}, nil
	}

	go func() {
		defer close(insertDone)
		<-started
		time.Sleep(20 * time.Millisecond)
		_, _ = store.AddMessage(mailbox.ID, "ChatGPT code", "noreply@example.com", "Use 909090 to continue.", time.Now())
	}()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+"&keyword=ChatGPT&wait_ms=500&peek=1", nil)
	start := time.Now()
	handler.ServeHTTP(rr, req)
	elapsed := time.Since(start)
	close(release)
	select {
	case <-syncDone:
	case <-time.After(time.Second):
		t.Fatal("background sync did not finish")
	}
	select {
	case <-insertDone:
	case <-time.After(time.Second):
		t.Fatal("message insert did not finish")
	}
	deadline := time.Now().Add(time.Second)
	for {
		server.mailboxCodeMu.Lock()
		pollers := len(server.mailboxCodePollers)
		server.mailboxCodeMu.Unlock()
		if pollers == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("mailbox code poller still active")
		}
		time.Sleep(time.Millisecond)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("code request = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "909090" {
		t.Fatalf("code body = %+v, want code inserted while poller was still waiting", body)
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("code request took %v, want local insert to be observed before wait_ms timeout", elapsed)
	}
}

func TestMailboxCodeQueryDoesNotRepeatServedCachedCode(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-repeat"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-repeat@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "ChatGPT code", "noreply@example.com", "Use 135790 to continue.", time.Now().Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		return map[string][]ICloudSyncedMessage{}, nil
	}

	requestCode := func(query string) struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
		Error   string `json:"error"`
	} {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+query, nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("code request %q = %d body=%s", query, rr.Code, rr.Body.String())
		}
		var body struct {
			Success bool   `json:"success"`
			Code    string `json:"code"`
			Error   string `json:"error"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	first := requestCode("")
	if !first.Success || first.Code != "135790" {
		t.Fatalf("first code = %+v, want 135790", first)
	}
	second := requestCode("")
	if second.Success || second.Code != "no_code" {
		t.Fatalf("second code = %+v, want no_code without repeating cached OTP", second)
	}
	cached := requestCode("&cache=1")
	if !cached.Success || cached.Code != "135790" {
		t.Fatalf("cache code = %+v, want cached 135790", cached)
	}
}

func TestMailboxCodePeekDoesNotConsumeServedCode(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-peek"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-peek@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "alias-peek@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "ChatGPT code", "noreply@example.com", "Use 246802 to continue.", time.Now().Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		return map[string][]ICloudSyncedMessage{}, nil
	}

	requestCode := func(query string) struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	} {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+query, nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("code request %q = %d body=%s", query, rr.Code, rr.Body.String())
		}
		var body struct {
			Success bool   `json:"success"`
			Code    string `json:"code"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	peek := requestCode("&peek=1")
	if !peek.Success || peek.Code != "246802" {
		t.Fatalf("peek code = %+v, want 246802", peek)
	}
	firstPublic := requestCode("")
	if !firstPublic.Success || firstPublic.Code != "246802" {
		t.Fatalf("public code after peek = %+v, want 246802", firstPublic)
	}
	secondPublic := requestCode("")
	if secondPublic.Success || secondPublic.Code != "no_code" {
		t.Fatalf("second public code = %+v, want no_code", secondPublic)
	}
	secondPeek := requestCode("&peek=1")
	if !secondPeek.Success || secondPeek.Code != "246802" {
		t.Fatalf("peek after public = %+v, want 246802", secondPeek)
	}
}

func TestLatestMailboxCodeSelectsNewestAndHonorsAfter(t *testing.T) {
	oldTime := time.Date(2026, 6, 21, 21, 36, 50, 0, time.FixedZone("CST", 8*3600))
	newTime := oldTime.Add(30 * time.Minute)
	now := newTime.Add(time.Minute)
	messages := []Message{
		{ID: "old", Subject: "Your temporary ChatGPT verification code", Body: "Enter this temporary verification code to continue: 733849", ReceivedAt: oldTime},
		{ID: "new", Subject: "Your temporary ChatGPT verification code", Body: "Enter this temporary verification code to continue: 246810", ReceivedAt: newTime},
	}

	msg, code, ok := latestMailboxCode(messages, time.Time{}, "ChatGPT", now)
	if !ok || msg.ID != "new" || code != "246810" {
		t.Fatalf("latestMailboxCode() msg=%s code=%q ok=%v, want new 246810 true", msg.ID, code, ok)
	}

	msg, code, ok = latestMailboxCode(messages, newTime.Add(-time.Minute), "ChatGPT", now)
	if !ok || msg.ID != "new" || code != "246810" {
		t.Fatalf("latestMailboxCode(after) msg=%s code=%q ok=%v, want new 246810 true", msg.ID, code, ok)
	}

	_, _, ok = latestMailboxCode(messages, newTime.Add(time.Minute), "ChatGPT", now)
	if ok {
		t.Fatalf("latestMailboxCode(after future) ok=true, want false")
	}
}

func TestLatestMailboxCodeOnlyUsesFiveMinuteWindow(t *testing.T) {
	now := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	messages := []Message{
		{ID: "too-old", Subject: "ChatGPT code", Body: "code 111111", ReceivedAt: now.Add(-6 * time.Minute)},
		{ID: "older", Subject: "ChatGPT code", Body: "code 222222", ReceivedAt: now.Add(-4 * time.Minute)},
		{ID: "newest", Subject: "ChatGPT code", Body: "code 333333", ReceivedAt: now.Add(-30 * time.Second)},
	}

	msg, code, ok := latestMailboxCode(messages, time.Time{}, "ChatGPT", now)
	if !ok || msg.ID != "newest" || code != "333333" {
		t.Fatalf("latestMailboxCode() msg=%s code=%q ok=%v, want newest 333333 true", msg.ID, code, ok)
	}

	tooOld := Message{ID: "too-old", Subject: "ChatGPT code", Body: "code 111111", ReceivedAt: now.Add(-6 * time.Minute)}
	_, _, ok = latestMailboxCode([]Message{tooOld}, time.Time{}, "ChatGPT", now)
	if ok {
		t.Fatalf("latestMailboxCode(old only) ok=true, want false")
	}
}

func TestLatestMailboxCodeUsesCreatedAtWhenReceivedAtMissing(t *testing.T) {
	now := time.Date(2026, 6, 21, 20, 6, 0, 0, time.UTC)
	messages := []Message{
		{ID: "old", Subject: "ChatGPT code", Body: "code 111111", CreatedAt: time.Date(2026, 6, 21, 20, 0, 0, 0, time.UTC)},
		{ID: "new", Subject: "ChatGPT code", Body: "code 222222", CreatedAt: time.Date(2026, 6, 21, 20, 5, 0, 0, time.UTC)},
	}

	msg, code, ok := latestMailboxCode(messages, time.Time{}, "ChatGPT", now)
	if !ok || msg.ID != "new" || code != "222222" {
		t.Fatalf("latestMailboxCode() msg=%s code=%q ok=%v, want new 222222 true", msg.ID, code, ok)
	}
}

func TestSyncMailboxSerializesPerOwner(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-sync"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "acc", "sync-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	first, err := store.AddMailboxForOwner(ownerID, "acc", "first", "first@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddMailboxForOwner(ownerID, "acc", "second", "second@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	started := make(chan string, 2)
	release := make(chan struct{})
	var active int64
	var maxActive int64
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		if len(mailboxes) != 1 {
			t.Fatalf("mailboxes = %d, want 1", len(mailboxes))
		}
		mailbox := mailboxes[0]
		nowActive := atomic.AddInt64(&active, 1)
		for {
			old := atomic.LoadInt64(&maxActive)
			if nowActive <= old || atomic.CompareAndSwapInt64(&maxActive, old, nowActive) {
				break
			}
		}
		started <- mailbox.Email
		select {
		case <-release:
		case <-ctx.Done():
			atomic.AddInt64(&active, -1)
			return nil, ctx.Err()
		}
		atomic.AddInt64(&active, -1)
		return map[string][]ICloudSyncedMessage{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	errs := make(chan error, 2)
	go func() {
		_, err := server.syncMailbox(ctx, first, time.Time{}, "ChatGPT")
		errs <- err
	}()
	if got := <-started; got != first.Email {
		t.Fatalf("first started %s, want %s", got, first.Email)
	}
	go func() {
		_, err := server.syncMailbox(ctx, second, time.Time{}, "ChatGPT")
		errs <- err
	}()

	select {
	case got := <-started:
		t.Fatalf("second sync started before first finished: %s", got)
	case <-time.After(50 * time.Millisecond):
	}
	release <- struct{}{}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if got := <-started; got != second.Email {
		t.Fatalf("second started %s, want %s", got, second.Email)
	}
	release <- struct{}{}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&maxActive); got != 1 {
		t.Fatalf("max active sync = %d, want 1", got)
	}
}

func TestMailboxCodeRequestsShareOwnerBatchSync(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-code"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "acc", "batch-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	first, err := store.AddMailboxForOwner(ownerID, "acc", "first", "first@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddMailboxForOwner(ownerID, "acc", "second", "second@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	var calls int64
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		atomic.AddInt64(&calls, 1)
		now := time.Now()
		out := make(map[string][]ICloudSyncedMessage, len(mailboxes))
		for _, mailbox := range mailboxes {
			switch mailbox.Email {
			case first.Email:
				out[mailbox.ID] = []ICloudSyncedMessage{{
					RemoteID:   "r1",
					UID:        "1",
					Subject:    "ChatGPT code",
					Body:       "Use 111111 to continue.",
					ReceivedAt: now,
				}}
			case second.Email:
				out[mailbox.ID] = []ICloudSyncedMessage{{
					RemoteID:   "r2",
					UID:        "2",
					Subject:    "ChatGPT code",
					Body:       "Use 222222 to continue.",
					ReceivedAt: now,
				}}
			}
		}
		return out, nil
	}

	type response struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	requestCode := func(mailbox Mailbox) response {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+"&after=2000-01-01T00:00:00Z", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("code request for %s = %d body=%s", mailbox.Email, rr.Code, rr.Body.String())
		}
		var body response
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var firstBody, secondBody response
	go func() {
		defer wg.Done()
		firstBody = requestCode(first)
	}()
	go func() {
		defer wg.Done()
		secondBody = requestCode(second)
	}()
	wg.Wait()

	if !firstBody.Success || firstBody.Code != "111111" {
		t.Fatalf("first body = %+v, want 111111", firstBody)
	}
	if !secondBody.Success || secondBody.Code != "222222" {
		t.Fatalf("second body = %+v, want 222222", secondBody)
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("batch sync calls = %d, want 1", got)
	}
}

func TestMailboxCodeWaiterSyncUsesRequestKeyword(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-keyword"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "acc", "keyword-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "acc", "keyword", "keyword@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		if keyword != "ChatGPT" {
			return map[string][]ICloudSyncedMessage{}, nil
		}
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "chatgpt-keyword",
				UID:        "99",
				Subject:    "你的 ChatGPT 临时验证码",
				Body:       "验证码：864209",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+"&keyword=ChatGPT&wait_ms=1000", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code request = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "864209" {
		t.Fatalf("code body = %+v, want ChatGPT code 864209", body)
	}
}

func TestSyncMailboxCodeBatchStoresIMAPAccountCursor(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-imap-cursor"
	accountID := "acc-imap-cursor"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, accountID, "cursor-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "cursor", "cursor.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.syncCodeMailboxBatchWithCursor = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (iCloudIMAPSyncResult, error) {
		return iCloudIMAPSyncResult{
			LastUID: "789",
			MessagesByMailbox: map[string][]ICloudSyncedMessage{
				mailbox.ID: {{
					RemoteID:   "imap:789",
					UID:        "789",
					Subject:    "ChatGPT code",
					Body:       "Use 135790 to continue.",
					ReceivedAt: time.Now(),
				}},
			},
		}, nil
	}

	if _, err := server.syncMailbox(context.Background(), mailbox, time.Time{}, "ChatGPT"); err != nil {
		t.Fatal(err)
	}
	session, ok := store.ICloudSessionForOwnerAccount(ownerID, accountID)
	if !ok {
		t.Fatal("session not found")
	}
	state, ok := iCloudIMAPLoginState(session)
	if !ok {
		t.Fatalf("imap state missing: %+v", session)
	}
	if state.IMAPLastSyncUID != "789" {
		t.Fatalf("IMAPLastSyncUID = %q, want 789", state.IMAPLastSyncUID)
	}
	if state.IMAPLastSyncAt.IsZero() {
		t.Fatal("IMAPLastSyncAt is zero")
	}
}

func TestSyncMailboxCodeBatchUsesIMAPStateAfterGateWait(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-imap-fresh-state"
	accountID := "account-imap-fresh-state"
	initial := testIMAPSession(ownerID, accountID, "fresh-state@icloud.com")
	if err := store.SaveICloudSessionForOwner(ownerID, initial); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "fresh-state", "fresh-state.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	seenPassword := make(chan string, 1)
	handler.syncCodeMailboxBatchWithCursor = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (iCloudIMAPSyncResult, error) {
		seenPassword <- state.IMAPAppPassword
		return iCloudIMAPSyncResult{}, nil
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(ownerID, accountID),
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, syncErr := handler.syncMailboxCodeBatchForOwnerWithLimit(
			context.Background(),
			ownerID,
			[]Mailbox{mailbox},
			time.Time{},
			"ChatGPT",
			10,
		)
		done <- syncErr
	}()

	select {
	case <-seenPassword:
		releaseAccountOperation()
		t.Fatal("IMAP sync provider ran before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}

	fresh := initial
	fresh.LoginStates[0].IMAPAppPassword = "fresh-app-password"
	if err := store.SaveICloudSessionForOwner(ownerID, fresh); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case got := <-seenPassword:
		if got != "fresh-app-password" {
			t.Fatalf("IMAP sync app password = %q, want fresh-app-password", got)
		}
	case <-time.After(time.Second):
		t.Fatal("IMAP sync provider was not called")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("IMAP sync error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("IMAP sync did not finish")
	}
}

func TestSyncMailboxBatchUsesICloudSessionAfterGateWait(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-icloud-fresh-session"
	accountID := "account-icloud-fresh-session"
	initial := ICloudSession{
		OwnerID:   ownerID,
		AccountID: accountID,
		AppleID:   "icloud-fresh-session@example.com",
		SavedAt:   time.Now(),
		Cookies: []SessionCookie{{
			Name:   "session",
			Value:  "stale-cookie",
			Domain: "127.0.0.1",
			Path:   "/",
		}},
		LoginStates: []LoginState{{
			Kind: LoginStateICloudWeb,
			Cookies: []SessionCookie{{
				Name:   "session",
				Value:  "stale-cookie",
				Domain: "127.0.0.1",
				Path:   "/",
			}},
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, initial); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "fresh-session", "fresh-session.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	seenCookie := make(chan string, 1)
	handler.syncMailboxBatch = func(ctx context.Context, session ICloudSession, mailboxes []Mailbox, after time.Time, keyword string, maxThreads int) (map[string][]ICloudSyncedMessage, error) {
		seenCookie <- session.Cookies[0].Value
		return map[string][]ICloudSyncedMessage{}, nil
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(ownerID, accountID),
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- handler.syncMailboxBatchForOwnerWithLimit(
			context.Background(),
			ownerID,
			[]Mailbox{mailbox},
			time.Time{},
			"ChatGPT",
			10,
		)
	}()

	select {
	case <-seenCookie:
		releaseAccountOperation()
		t.Fatal("iCloud sync provider ran before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}

	fresh := cloneICloudSession(initial)
	fresh.Cookies[0].Value = "fresh-cookie"
	fresh.LoginStates[0].Cookies[0].Value = "fresh-cookie"
	if err := store.SaveICloudSessionForOwner(ownerID, fresh); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case got := <-seenCookie:
		if got != "fresh-cookie" {
			t.Fatalf("iCloud sync cookie = %q, want fresh-cookie", got)
		}
	case <-time.After(time.Second):
		t.Fatal("iCloud sync provider was not called")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("iCloud sync error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("iCloud sync did not finish")
	}
}

func TestSyncMailboxCodeBatchSkipsEmptyMailboxCursorWrites(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-imap-empty-cursor"
	accountID := "acc-imap-empty-cursor"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, accountID, "empty-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "empty", "empty.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.syncCodeMailboxBatchWithCursor = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (iCloudIMAPSyncResult, error) {
		return iCloudIMAPSyncResult{
			LastUID:           "999",
			MessagesByMailbox: map[string][]ICloudSyncedMessage{},
		}, nil
	}

	if _, err := server.syncMailbox(context.Background(), mailbox, time.Time{}, "ChatGPT"); err != nil {
		t.Fatal(err)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox not found")
	}
	if !updated.LastSyncAt.IsZero() {
		t.Fatalf("LastSyncAt = %s, want zero for empty mailbox sync", updated.LastSyncAt)
	}
	session, ok := store.ICloudSessionForOwnerAccount(ownerID, accountID)
	if !ok {
		t.Fatal("session not found")
	}
	state, ok := iCloudIMAPLoginState(session)
	if !ok {
		t.Fatalf("imap state missing: %+v", session)
	}
	if state.IMAPLastSyncUID != "999" {
		t.Fatalf("IMAPLastSyncUID = %q, want 999", state.IMAPLastSyncUID)
	}
}

func TestEnsureMailWatcherIMAPBaselineStoresAccountUID(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-imap-baseline"
	accountID := "acc-imap-baseline"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, accountID, "baseline-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "baseline", "baseline.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	var calls int
	server.latestIMAPUID = func(ctx context.Context, state LoginState) (string, error) {
		calls++
		return "500", nil
	}
	groups := server.mailWatcherIMAPGroups()
	if len(groups) != 1 {
		t.Fatalf("IMAP groups = %d, want 1", len(groups))
	}
	if err := server.ensureMailWatcherIMAPBaseline(context.Background(), &groups[0]); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("latest IMAP UID calls = %d, want 1", calls)
	}
	session, ok := store.ICloudSessionForOwnerAccount(ownerID, accountID)
	if !ok {
		t.Fatal("session not found")
	}
	state, ok := iCloudIMAPLoginState(session)
	if !ok {
		t.Fatal("imap state missing")
	}
	if state.IMAPLastSyncUID != "500" {
		t.Fatalf("IMAPLastSyncUID = %q, want 500", state.IMAPLastSyncUID)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox not found")
	}
	if !updated.LastSyncAt.IsZero() || updated.LastSyncUID != "" {
		t.Fatalf("mailbox cursor changed: LastSyncAt=%s LastSyncUID=%q", updated.LastSyncAt, updated.LastSyncUID)
	}
}

func TestMailWatcherGroupsExcludeRemoteDeleteIneligibleMailboxes(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-watcher-remote-delete"
	accountID := "acc-watcher-remote-delete"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, accountID, "watcher-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	available, err := store.AddMailboxForOwner(ownerID, accountID, "available", "available.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := store.AddMailboxForOwner(ownerID, accountID, "pending", "pending.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginMailboxRemoteDelete(pending.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	unknown, err := store.AddMailboxForOwner(ownerID, accountID, "unknown", "unknown.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMailboxRemoteDeleteUnknown(unknown.ID, "provider timeout", time.Now()); err != nil {
		t.Fatal(err)
	}
	succeeded, err := store.AddMailboxForOwner(ownerID, accountID, "succeeded", "succeeded.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMailboxRemoteDeleteSucceeded(succeeded.ID, time.Now()); err != nil {
		t.Fatal(err)
	}

	server := NewServer(Config{}, store, discardLogger()).(*Server)
	groups := server.mailWatcherGroups()
	if len(groups) != 1 {
		t.Fatalf("mail watcher groups = %d, want 1: %+v", len(groups), groups)
	}
	if len(groups[0].mailboxes) != 1 || groups[0].mailboxes[0].ID != available.ID {
		t.Fatalf("mail watcher mailboxes = %+v, want only available mailbox %q", groups[0].mailboxes, available.ID)
	}

	imapGroups := server.mailWatcherIMAPGroups()
	if len(imapGroups) != 1 {
		t.Fatalf("IMAP watcher groups = %d, want 1: %+v", len(imapGroups), imapGroups)
	}
	if len(imapGroups[0].mailboxes) != 1 || imapGroups[0].mailboxes[0].ID != available.ID {
		t.Fatalf("IMAP watcher mailboxes = %+v, want only available mailbox %q", imapGroups[0].mailboxes, available.ID)
	}
}

func TestEnsureMailWatcherIMAPBaselineWaitsForMailboxAccountOperation(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-imap-baseline-gate"
	accountID := "acc-imap-baseline-gate"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, accountID, "baseline-gate-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner(ownerID, accountID, "baseline-gate", "baseline-gate.alias@icloud.com"); err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	entered := make(chan struct{})
	handler.latestIMAPUID = func(ctx context.Context, state LoginState) (string, error) {
		close(entered)
		return "501", nil
	}
	groups := handler.mailWatcherIMAPGroups()
	if len(groups) != 1 {
		t.Fatalf("IMAP groups = %d, want 1", len(groups))
	}
	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(ownerID, accountID),
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- handler.ensureMailWatcherIMAPBaseline(context.Background(), &groups[0])
	}()

	select {
	case <-entered:
		releaseAccountOperation()
		t.Fatal("IMAP baseline ran while the mailbox account operation was held")
	case <-time.After(100 * time.Millisecond):
	}
	releaseAccountOperation()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("IMAP baseline did not finish after the mailbox account operation was released")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("IMAP baseline did not query the latest UID")
	}
}

func TestEnsureMailWatcherIMAPBaselineUsesCurrentStateAfterGateWait(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-imap-baseline-fresh-state"
	accountID := "acc-imap-baseline-fresh-state"
	initial := testIMAPSession(ownerID, accountID, "baseline-fresh-state@icloud.com")
	if err := store.SaveICloudSessionForOwner(ownerID, initial); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner(ownerID, accountID, "baseline-fresh-state", "baseline-fresh-state.alias@icloud.com"); err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	seenPassword := make(chan string, 1)
	handler.latestIMAPUID = func(ctx context.Context, state LoginState) (string, error) {
		seenPassword <- state.IMAPAppPassword
		return "502", nil
	}
	groups := handler.mailWatcherIMAPGroups()
	if len(groups) != 1 {
		t.Fatalf("IMAP groups = %d, want 1", len(groups))
	}
	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(ownerID, accountID),
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- handler.ensureMailWatcherIMAPBaseline(context.Background(), &groups[0])
	}()

	select {
	case <-seenPassword:
		releaseAccountOperation()
		t.Fatal("IMAP baseline used a state snapshot before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}

	fresh := cloneICloudSession(initial)
	fresh.LoginStates[0].IMAPAppPassword = "fresh-app-specific-password"
	if err := store.SaveICloudSessionForOwner(ownerID, fresh); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case password := <-seenPassword:
		if password != "fresh-app-specific-password" {
			t.Fatalf("IMAP baseline password = %q, want fresh password", password)
		}
	case <-time.After(time.Second):
		t.Fatal("IMAP baseline did not query the latest UID")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("IMAP baseline error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("IMAP baseline did not finish")
	}
}

func TestEnsureMailWatcherIMAPBaselineRejectsMissingCurrentStateAfterGateWait(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-imap-baseline-missing-state"
	accountID := "acc-imap-baseline-missing-state"
	initial := testIMAPSession(ownerID, accountID, "baseline-missing-state@icloud.com")
	if err := store.SaveICloudSessionForOwner(ownerID, initial); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner(ownerID, accountID, "baseline-missing-state", "baseline-missing-state.alias@icloud.com"); err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	latestCalled := make(chan struct{}, 1)
	handler.latestIMAPUID = func(ctx context.Context, state LoginState) (string, error) {
		latestCalled <- struct{}{}
		return "503", nil
	}
	groups := handler.mailWatcherIMAPGroups()
	if len(groups) != 1 {
		t.Fatalf("IMAP groups = %d, want 1", len(groups))
	}
	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(ownerID, accountID),
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- handler.ensureMailWatcherIMAPBaseline(context.Background(), &groups[0])
	}()

	select {
	case <-latestCalled:
		releaseAccountOperation()
		t.Fatal("IMAP baseline ran before the current state was revalidated")
	case <-time.After(100 * time.Millisecond):
	}

	store.mu.Lock()
	for index := range store.state.ICloudSessions {
		if store.state.ICloudSessions[index].OwnerID == ownerID &&
			store.state.ICloudSessions[index].AccountID == accountID {
			store.state.ICloudSessions[index].LoginStates = nil
		}
	}
	store.mu.Unlock()
	releaseAccountOperation()

	select {
	case err := <-done:
		if !isCodedError(err, "imap_session_missing") {
			t.Fatalf("IMAP baseline error = %#v, want imap_session_missing", err)
		}
	case <-time.After(time.Second):
		t.Fatal("IMAP baseline did not finish after the mailbox account operation was released")
	}
	select {
	case <-latestCalled:
		t.Fatal("IMAP baseline used stale state after the current state disappeared")
	default:
	}
}

func TestMailWatcherIMAPGroupSignatureIgnoresMailboxSyncCursor(t *testing.T) {
	state := LoginState{
		Kind:            LoginStateICloudIMAP,
		IMAPEmail:       "receiver@icloud.com",
		IMAPUsername:    "receiver@icloud.com",
		IMAPHost:        defaultICloudIMAPHost,
		IMAPPort:        defaultICloudIMAPPort,
		IMAPAppPassword: "app-specific-password",
	}
	before := mailWatcherIMAPGroupSignature(state, []Mailbox{{
		ID:          "mbx_1",
		Email:       "alias@icloud.com",
		LastSyncUID: "100",
	}})
	after := mailWatcherIMAPGroupSignature(state, []Mailbox{{
		ID:          "mbx_1",
		Email:       "alias@icloud.com",
		LastSyncUID: "200",
	}})
	if before != after {
		t.Fatalf("signature changed after LastSyncUID update: %q vs %q", before, after)
	}
}

func TestMailWatcherIMAPGroupsIsolateExplicitAccounts(t *testing.T) {
	store := newTestStore(t)
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-imap-isolation"
	accountOne, err := store.AddAccountForOwnerWithProxy(ownerID, "One", "one@example.com", "", "http://proxy-one:8080")
	if err != nil {
		t.Fatal(err)
	}
	accountTwo, err := store.AddAccountForOwnerWithProxy(ownerID, "Two", "two@example.com", "", "http://proxy-two:8080")
	if err != nil {
		t.Fatal(err)
	}

	sessionOne := testIMAPSession(ownerID, accountOne.ID, "shared@icloud.com")
	sessionOne.ProxyURL = accountOne.ProxyURL
	sessionOne.LoginStates[0].ProxyURL = accountOne.ProxyURL
	sessionOne.LoginStates[0].IMAPAppPassword = "password-one"
	sessionTwo := testIMAPSession(ownerID, accountTwo.ID, "shared@icloud.com")
	sessionTwo.ProxyURL = accountTwo.ProxyURL
	sessionTwo.LoginStates[0].ProxyURL = accountTwo.ProxyURL
	sessionTwo.LoginStates[0].IMAPAppPassword = "password-two"
	if err := store.SaveICloudSessionForOwner(ownerID, sessionOne); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(ownerID, sessionTwo); err != nil {
		t.Fatal(err)
	}
	mailboxOne, err := store.AddMailboxForOwner(ownerID, accountOne.ID, "One alias", "one-alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	mailboxTwo, err := store.AddMailboxForOwner(ownerID, accountTwo.ID, "Two alias", "two-alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	groups := server.mailWatcherIMAPGroups()
	if len(groups) != 2 {
		t.Fatalf("IMAP groups = %d, want 2 for isolated accounts: %+v", len(groups), groups)
	}
	seenAccounts := make(map[string]string, len(groups))
	for _, group := range groups {
		if len(group.mailboxes) != 1 {
			t.Fatalf("group %q contains %d mailboxes, want 1: %+v", group.key, len(group.mailboxes), group.mailboxes)
		}
		seenAccounts[group.mailboxes[0].AccountID] = group.state.ProxyURL + "|" + group.state.IMAPAppPassword
	}
	if seenAccounts[mailboxOne.AccountID] != accountOne.ProxyURL+"|password-one" {
		t.Fatalf("account one IMAP state = %q, want %q", seenAccounts[mailboxOne.AccountID], accountOne.ProxyURL+"|password-one")
	}
	if seenAccounts[mailboxTwo.AccountID] != accountTwo.ProxyURL+"|password-two" {
		t.Fatalf("account two IMAP state = %q, want %q", seenAccounts[mailboxTwo.AccountID], accountTwo.ProxyURL+"|password-two")
	}
}

func TestLoginProtectsManagementAPI(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status without admin = %d, want 401", rr.Code)
	}

	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status with admin login = %d, want 200", rr.Code)
	}
}

func TestStoreMigratesLegacyMailboxesToSoleOwnerAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now()
	state := State{
		NextID: 10,
		Users: []User{{
			ID:        "usr_1",
			Username:  "owner@example.com",
			Status:    StatusActive,
			CreatedAt: now,
			UpdatedAt: now,
		}},
		Accounts: []Account{{
			ID:           "acc_1",
			OwnerID:      "usr_1",
			Label:        "main",
			AppleID:      "owner@example.com",
			Status:       StatusActive,
			ICloudStatus: ICloudStatusActive,
			CreatedAt:    now,
			UpdatedAt:    now,
		}},
		Mailboxes: []Mailbox{{
			ID:           "mbx_1",
			OwnerID:      "usr_1",
			Label:        "legacy",
			Email:        "alias@icloud.com",
			APIToken:     "token",
			APIActive:    true,
			ICloudActive: true,
			Status:       StatusAvailable,
			CreatedAt:    now,
			UpdatedAt:    now,
		}},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	if got := snapshot.Mailboxes[0].AccountID; got != "acc_1" {
		t.Fatalf("legacy mailbox account_id = %q, want acc_1", got)
	}
}

func TestClaimMailboxRequiresGlobalAPIKeyAndMarksUsed(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{APIKey: "global-key", PublicBaseURL: "https://mail.example"}, store, discardLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/claim", strings.NewReader(`{"project":"openai","purpose":"register"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("claim without key = %d, want 401", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/claim", strings.NewReader(`{"project":"openai","purpose":"register"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer global-key")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("claim with key = %d, body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool          `json:"success"`
		Mailbox publicMailbox `json:"mailbox"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Mailbox.ID != mailbox.ID || body.Mailbox.Status != StatusUsed {
		t.Fatalf("claim body = %+v", body)
	}
	if !strings.HasPrefix(body.Mailbox.APIURL, "https://mail.example/") {
		t.Fatalf("api_url = %q", body.Mailbox.APIURL)
	}
	if body.Mailbox.APIToken != mailbox.APIToken {
		t.Fatalf("api_token = %q, want stored token", body.Mailbox.APIToken)
	}
	if !strings.Contains(body.Mailbox.APIURL, "key="+url.QueryEscape(mailbox.APIToken)) {
		t.Fatalf("claim api_url missing mailbox key: %q", body.Mailbox.APIURL)
	}
	if strings.Contains(body.Mailbox.APIURL, "wait_ms=") {
		t.Fatalf("claim api_url must not embed wait_ms: %q", body.Mailbox.APIURL)
	}
	if strings.Contains(body.Mailbox.APIURL, "global-key") {
		t.Fatalf("claim api_url leaked global key: %q", body.Mailbox.APIURL)
	}
	if body.Mailbox.OwnerID != "" || body.Mailbox.AccountID != "" || body.Mailbox.RemoteAnonymousID != "" {
		t.Fatalf("claim leaked internal ownership fields: %+v", body.Mailbox)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || updated.Status != StatusUsed {
		t.Fatalf("stored mailbox = %+v ok=%v", updated, ok)
	}
}

func TestLookupMailboxesRequiresGlobalAPIKeyAndKeepsStatus(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{APIKey: "global-key", PublicBaseURL: "https://mail.example"}, store, discardLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/lookup", strings.NewReader(`{"emails":["alias@icloud.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("lookup without key = %d, want 401", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/lookup", strings.NewReader(`{"emails":["ALIAS@icloud.com","missing@icloud.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer global-key")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("lookup with key = %d, body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success   bool            `json:"success"`
		Mailboxes []publicMailbox `json:"mailboxes"`
		Missing   []string        `json:"missing"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || len(body.Mailboxes) != 1 || body.Mailboxes[0].ID != mailbox.ID {
		t.Fatalf("lookup body = %+v", body)
	}
	if len(body.Missing) != 1 || body.Missing[0] != "missing@icloud.com" {
		t.Fatalf("missing = %+v", body.Missing)
	}
	if !strings.HasPrefix(body.Mailboxes[0].APIURL, "https://mail.example/") {
		t.Fatalf("api_url = %q", body.Mailboxes[0].APIURL)
	}
	if body.Mailboxes[0].APIToken != mailbox.APIToken {
		t.Fatalf("lookup api_token = %q, want stored token", body.Mailboxes[0].APIToken)
	}
	if !strings.Contains(body.Mailboxes[0].APIURL, "key="+url.QueryEscape(mailbox.APIToken)) {
		t.Fatalf("lookup api_url missing mailbox key: %q", body.Mailboxes[0].APIURL)
	}
	if strings.Contains(body.Mailboxes[0].APIURL, "wait_ms=") {
		t.Fatalf("lookup api_url must not embed wait_ms: %q", body.Mailboxes[0].APIURL)
	}
	if strings.Contains(body.Mailboxes[0].APIURL, "global-key") {
		t.Fatalf("lookup api_url leaked global key: %q", body.Mailboxes[0].APIURL)
	}
	if body.Mailboxes[0].OwnerID != "" || body.Mailboxes[0].AccountID != "" || body.Mailboxes[0].RemoteAnonymousID != "" {
		t.Fatalf("lookup leaked internal ownership fields: %+v", body.Mailboxes[0])
	}
	updated, ok := store.FindMailboxByEmail("alias@icloud.com")
	if !ok || updated.Status != StatusAvailable {
		t.Fatalf("lookup changed mailbox status: %+v ok=%v", updated, ok)
	}
}

func TestMailboxSchedulerStartsCreatesAndStops(t *testing.T) {
	withDefaultMailboxSchedulerRoundInterval(t, 10*time.Millisecond)
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "timer-user", "timer123")
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		SavedAt:            time.Now(),
		DSID:               "dsid-1",
		PremiumMailBaseURL: "https://example.invalid",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
	}); err != nil {
		t.Fatal(err)
	}

	var seq int64
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		select {
		case <-ctx.Done():
			return Mailbox{}, ICloudRemoteMailbox{}, ctx.Err()
		default:
		}
		n := atomic.AddInt64(&seq, 1)
		if n > 2 {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "当前小时额度已用完", true)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, fmt.Sprintf("sched-%d@icloud.com", n))
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/start", strings.NewReader(`{"batch_size":200,"interval_seconds":60,"label":"SCH"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("start scheduler = %d body=%s", rr.Code, rr.Body.String())
	}

	var status struct {
		Scheduler publicMailboxScheduler `json:"scheduler"`
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/api/icloud/scheduler/status", nil)
		req.AddCookie(cookie)
		addClosureTestCSRF(req, cookie)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("scheduler status = %d body=%s", rr.Code, rr.Body.String())
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Scheduler.Success >= 2 && status.Scheduler.Failed >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status.Scheduler.BatchSize != 1 {
		t.Fatalf("scheduler batch size = %d, want hidden request batch_size ignored as 1", status.Scheduler.BatchSize)
	}
	if status.Scheduler.Success != 2 || status.Scheduler.Failed != 1 || len(status.Scheduler.Events) == 0 {
		t.Fatalf("scheduler did not create until account failed: %+v", status.Scheduler)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/stop", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("stop scheduler = %d body=%s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Scheduler.Running {
		t.Fatalf("scheduler still running after stop: %+v", status.Scheduler)
	}
}

func withDefaultMailboxSchedulerRoundInterval(t *testing.T, interval time.Duration) {
	t.Helper()
	old := defaultMailboxSchedulerRoundInterval
	defaultMailboxSchedulerRoundInterval = interval
	t.Cleanup(func() {
		defaultMailboxSchedulerRoundInterval = old
	})
}

func TestMailboxSchedulerStatusDefaultsRoundInterval(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	cookie, _ := registerTestUser(t, handler, "timer-default-round", "timer123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/icloud/scheduler/status", nil)
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("scheduler status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Scheduler publicMailboxScheduler `json:"scheduler"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Scheduler.RoundIntervalSeconds != 5 {
		t.Fatalf("default round interval = %d, want 5", body.Scheduler.RoundIntervalSeconds)
	}
}

func TestMailboxSchedulerStartAcceptsRoundIntervalSeconds(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "timer-custom-round", "timer123")
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		SavedAt:            time.Now(),
		DSID:               "dsid-round",
		PremiumMailBaseURL: "https://example.invalid",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
	}); err != nil {
		t.Fatal(err)
	}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		<-ctx.Done()
		return Mailbox{}, ICloudRemoteMailbox{}, ctx.Err()
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/start", strings.NewReader(`{"interval_minutes":60,"round_interval_seconds":7,"label":"SCH"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("start scheduler = %d body=%s", rr.Code, rr.Body.String())
	}
	defer func() {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/stop", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		addClosureTestCSRF(req, cookie)
		handler.ServeHTTP(rr, req)
	}()
	var body struct {
		Scheduler publicMailboxScheduler `json:"scheduler"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Scheduler.RoundIntervalSeconds != 7 {
		t.Fatalf("round interval = %d, want 7", body.Scheduler.RoundIntervalSeconds)
	}
}

func TestMailboxSchedulerClearLogsKeepsCounters(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "timer-clear", "timer123")

	job := &mailboxSchedulerJob{
		nextEventID: 2,
		state: mailboxSchedulerState{
			OwnerID:         user.ID,
			Owner:           user.Username,
			BatchSize:       1,
			IntervalSeconds: int(time.Hour.Seconds()),
			Status:          "running",
			Success:         3,
			Failed:          1,
		},
		events: []mailboxSchedulerEvent{
			{ID: 2, At: time.Now(), Type: "failed", Message: "失败记录", Batch: 1, Error: "额度已用完"},
			{ID: 1, At: time.Now(), Type: "created", Message: "创建成功", Batch: 1, Email: "created@icloud.com"},
		},
	}
	server.schedulerMu.Lock()
	server.mailboxSchedulers[user.ID] = job
	server.schedulerMu.Unlock()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/logs/clear", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("clear scheduler logs = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Scheduler publicMailboxScheduler `json:"scheduler"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Scheduler.Events) != 0 {
		t.Fatalf("scheduler events after clear = %+v, want empty", body.Scheduler.Events)
	}
	if body.Scheduler.Success != 3 || body.Scheduler.Failed != 1 {
		t.Fatalf("scheduler counters changed after clear: %+v", body.Scheduler)
	}
}

func TestMailboxSchedulerRunsUntilAllAccountsFailWithOnlyInterval(t *testing.T) {
	withDefaultMailboxSchedulerRoundInterval(t, 10*time.Millisecond)
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "timer-until-fail", "timer123")
	for _, session := range []ICloudSession{
		{
			OwnerID:            user.ID,
			AppleID:            "limit@example.com",
			DSID:               "dsid-limit",
			PremiumMailBaseURL: "https://example.invalid",
			IsICloudPlus:       true,
			CanCreateHME:       true,
			Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie-1", Domain: ".icloud.com", Path: "/"}},
		},
		{
			OwnerID:            user.ID,
			AppleID:            "worker@example.com",
			DSID:               "dsid-worker",
			PremiumMailBaseURL: "https://example.invalid",
			IsICloudPlus:       true,
			CanCreateHME:       true,
			Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie-2", Domain: ".icloud.com", Path: "/"}},
		},
	} {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(sessions))
	}
	limitAccountID := sessions[0].AccountID
	workerAccountID := sessions[1].AccountID
	accountIDs := []string{limitAccountID, workerAccountID}

	var mu sync.Mutex
	attempts := map[string]int{}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		select {
		case <-ctx.Done():
			return Mailbox{}, ICloudRemoteMailbox{}, ctx.Err()
		default:
		}
		mu.Lock()
		attempts[accountID]++
		n := attempts[accountID]
		mu.Unlock()
		if accountID == limitAccountID {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "第一个账号额度已用完", true)
		}
		if n > 2 {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "第二个账号额度已用完", true)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, fmt.Sprintf("%s-%d@icloud.com", accountID, n))
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	body := fmt.Sprintf(`{"account_ids":["%s","%s"],"interval_seconds":60,"label":"SCH"}`, accountIDs[0], accountIDs[1])
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("start scheduler = %d body=%s", rr.Code, rr.Body.String())
	}
	defer func() {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/stop", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		addClosureTestCSRF(req, cookie)
		handler.ServeHTTP(rr, req)
	}()

	var status struct {
		Scheduler publicMailboxScheduler `json:"scheduler"`
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/api/icloud/scheduler/status", nil)
		req.AddCookie(cookie)
		addClosureTestCSRF(req, cookie)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("scheduler status = %d body=%s", rr.Code, rr.Body.String())
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Scheduler.Success >= 2 && status.Scheduler.Failed >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status.Scheduler.BatchSize != 1 {
		t.Fatalf("scheduler batch size = %d, want 1", status.Scheduler.BatchSize)
	}
	if status.Scheduler.Success != 2 || status.Scheduler.Failed != 2 {
		t.Fatalf("scheduler state = success %d failed %d, want success=2 failed=2: %+v", status.Scheduler.Success, status.Scheduler.Failed, status.Scheduler)
	}
	mu.Lock()
	if attempts[limitAccountID] != 1 {
		mu.Unlock()
		t.Fatalf("limited account attempts = %d, want 1; attempts=%+v", attempts[limitAccountID], attempts)
	}
	if attempts[workerAccountID] != 3 {
		mu.Unlock()
		t.Fatalf("worker account attempts = %d, want 3; attempts=%+v", attempts[workerAccountID], attempts)
	}
	mu.Unlock()
}

func TestMailboxSchedulerBatchWaitsBetweenCreateRounds(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-scheduler-round-wait"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AppleID:            "round@example.com",
		DSID:               "dsid-round-wait",
		PremiumMailBaseURL: "https://example.invalid",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	accountID := sessions[0].AccountID

	var attemptsMu sync.Mutex
	var attemptTimes []time.Time
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		attemptsMu.Lock()
		attemptTimes = append(attemptTimes, time.Now())
		attempt := len(attemptTimes)
		attemptsMu.Unlock()
		if attempt > 2 {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "当前小时额度已用完", true)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, fmt.Sprintf("round-%d@icloud.com", attempt))
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	roundInterval := 40 * time.Millisecond
	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	server.runMailboxSchedulerBatch(context.Background(), ownerID, job, mailboxSchedulerConfig{
		AccountIDs:    []string{accountID},
		Label:         "SCH",
		BatchSize:     1,
		RoundInterval: roundInterval,
	}, 1)
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	if len(attemptTimes) != 3 {
		t.Fatalf("attempts = %d, want 3", len(attemptTimes))
	}
	for i := 1; i < len(attemptTimes); i++ {
		if got := attemptTimes[i].Sub(attemptTimes[i-1]); got < roundInterval-5*time.Millisecond {
			t.Fatalf("attempt %d delay = %s, want at least %s", i+1, got, roundInterval)
		}
	}
}

func TestMailboxSchedulerSkipsFailedAccountWithinCurrentBatch(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-scheduler-skip"
	for _, session := range []ICloudSession{
		{OwnerID: ownerID, AppleID: "bad@example.com", DSID: "dsid-bad", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: ownerID, AppleID: "good@example.com", DSID: "dsid-good", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
	} {
		if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(sessions))
	}
	badAccountID := sessions[0].AccountID
	goodAccountID := sessions[1].AccountID
	var attemptsMu sync.Mutex
	attempts := map[string]int{}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		attemptsMu.Lock()
		attempts[accountID]++
		attempt := attempts[accountID]
		attemptsMu.Unlock()
		if accountID == badAccountID {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "当前小时额度已用完", true)
		}
		if attempt > 3 {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "好账号本轮也已用完", true)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, fmt.Sprintf("good-%d@icloud.com", attempt))
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	server.runMailboxSchedulerBatch(context.Background(), ownerID, job, mailboxSchedulerConfig{
		AccountIDs: []string{badAccountID, goodAccountID},
		Label:      "SCH",
		BatchSize:  1,
	}, 1)
	state, events := job.snapshot()
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	if attempts[badAccountID] != 1 {
		t.Fatalf("bad account attempts = %d, want 1; attempts=%+v", attempts[badAccountID], attempts)
	}
	if attempts[goodAccountID] != 4 {
		t.Fatalf("good account attempts = %d, want 4; attempts=%+v", attempts[goodAccountID], attempts)
	}
	if state.Success != 3 || state.Failed != 2 {
		t.Fatalf("scheduler state = %+v, want success=3 failed=2", state)
	}
	if len(events) != 6 {
		t.Fatalf("events = %d, want 6: %+v", len(events), events)
	}
}

func schedulerTestAttemptChannel(ctx context.Context) mailboxCreateChannel {
	channel := mailboxCreateChannelFromContext(ctx)
	if normalizeMailboxCreateChannel(channel) == mailboxCreateChannelAuto {
		return mailboxCreateChannelAppleAccount
	}
	return channel
}

func TestMailboxSchedulerFallsBackToOldInterfaceAfterNewInterfaceFails(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-scheduler-fallback"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AppleID:            "fallback@example.com",
		DSID:               "dsid-fallback",
		PremiumMailBaseURL: "https://example.invalid",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
		LoginStates: []LoginState{
			{Kind: LoginStateAppleAccount, Host: "appleid.apple.com", Origin: "https://account.apple.com", Scnt: "scnt", SessionID: "sid"},
			{Kind: LoginStateICloudWeb, Host: "www.icloud.com", Origin: "https://www.icloud.com", Cookies: []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	accountID := sessions[0].AccountID

	var attemptsMu sync.Mutex
	attempts := map[mailboxCreateChannel]int{}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		channel := schedulerTestAttemptChannel(ctx)
		attemptsMu.Lock()
		attempts[channel]++
		attempt := attempts[channel]
		attemptsMu.Unlock()
		switch channel {
		case mailboxCreateChannelAppleAccount:
			if attempt > 2 {
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("apple_account_limit", "新接口当前小时额度已用完", true)
			}
		case mailboxCreateChannelICloudWeb:
			if attempt > 1 {
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "旧接口当前小时额度已用完", true)
			}
		default:
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("unexpected_channel", "定时创建没有指定接口", false)
		}
		email := fmt.Sprintf("%s-%d@icloud.com", channel, attempt)
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, email)
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true, Origin: string(channel)}, nil
	}

	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	cfg := mailboxSchedulerConfig{
		AccountIDs: []string{accountID},
		Label:      "SCH",
		BatchSize:  1,
	}
	server.runMailboxSchedulerBatch(context.Background(), ownerID, job, cfg, 1)
	state, events := job.snapshot()
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	if attempts[mailboxCreateChannelAppleAccount] != 3 {
		t.Fatalf("new interface attempts = %d, want 3; attempts=%+v", attempts[mailboxCreateChannelAppleAccount], attempts)
	}
	if attempts[mailboxCreateChannelICloudWeb] != 2 {
		t.Fatalf("old interface attempts = %d, want 2; attempts=%+v", attempts[mailboxCreateChannelICloudWeb], attempts)
	}
	if state.Success != 3 || state.Failed != 1 {
		t.Fatalf("scheduler state = %+v, want success=3 failed=1", state)
	}
	var sawSwitch, sawNewCreated, sawOldCreated, sawOldFailed, sawAccountLabel bool
	for _, event := range events {
		if event.Type == "channel_failed" && strings.Contains(event.Message, "切换旧接口继续尝试") {
			sawSwitch = true
		}
		if event.Type == "created" && strings.Contains(event.Message, "新接口创建成功") {
			sawNewCreated = true
		}
		if event.Type == "created" && strings.Contains(event.Message, "旧接口创建成功") {
			sawOldCreated = true
		}
		if event.Type == "failed" && strings.Contains(event.Message, "旧接口创建失败") {
			sawOldFailed = true
		}
		if strings.Contains(event.Message, "fallback@example.com") {
			sawAccountLabel = true
		}
	}
	if !sawSwitch {
		t.Fatalf("events did not include old-interface fallback: %+v", events)
	}
	if !sawNewCreated || !sawOldCreated || !sawOldFailed {
		t.Fatalf("events did not include create channel labels: newCreated=%v oldCreated=%v oldFailed=%v events=%+v", sawNewCreated, sawOldCreated, sawOldFailed, events)
	}
	if !sawAccountLabel {
		t.Fatalf("events did not include login account label: %+v", events)
	}
}

func TestMailboxSchedulerDoesNotFallbackAfterUncertainNewInterfaceCreate(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-scheduler-uncertain"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AppleID:            "uncertain@example.com",
		DSID:               "dsid-uncertain",
		PremiumMailBaseURL: "https://example.invalid",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
		LoginStates: []LoginState{
			{Kind: LoginStateAppleAccount, Host: "appleid.apple.com", Origin: "https://account.apple.com", Scnt: "scnt", SessionID: "sid"},
			{Kind: LoginStateICloudWeb, Host: "www.icloud.com", Origin: "https://www.icloud.com", Cookies: []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	accountID := sessions[0].AccountID

	var attemptsMu sync.Mutex
	attempts := map[mailboxCreateChannel]int{}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		channel := schedulerTestAttemptChannel(ctx)
		attemptsMu.Lock()
		attempts[channel]++
		attemptsMu.Unlock()
		if channel == mailboxCreateChannelAppleAccount {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode(
				"apple_account_create_uncertain",
				"Apple Account 已提交隐私邮箱确认请求，但未收到可确认的结果",
				true,
			)
		}
		return Mailbox{}, ICloudRemoteMailbox{}, errCode("unexpected_channel", "unexpected scheduler fallback", false)
	}

	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	cfg := mailboxSchedulerConfig{
		AccountIDs: []string{accountID},
		Label:      "SCH",
		BatchSize:  1,
	}
	server.runMailboxSchedulerBatch(context.Background(), ownerID, job, cfg, 1)
	server.runMailboxSchedulerBatch(context.Background(), ownerID, job, cfg, 2)
	state, events := job.snapshot()
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	if attempts[mailboxCreateChannelAppleAccount] != 1 {
		t.Fatalf("new interface attempts = %d, want 1; attempts=%+v", attempts[mailboxCreateChannelAppleAccount], attempts)
	}
	if attempts[mailboxCreateChannelICloudWeb] != 0 {
		t.Fatalf("old interface attempts = %d, want 0; attempts=%+v", attempts[mailboxCreateChannelICloudWeb], attempts)
	}
	if state.Success != 0 || state.Failed != 2 {
		t.Fatalf("scheduler state = %+v, want success=0 failed=2 across two batches", state)
	}
	var sawUncertainFailure, sawSwitch bool
	for _, event := range events {
		if event.Type == "failed" && strings.Contains(event.Message, "未收到可确认的结果") {
			sawUncertainFailure = true
		}
		if event.Type == "channel_failed" && strings.Contains(event.Message, "切换旧接口继续尝试") {
			sawSwitch = true
		}
	}
	if !sawUncertainFailure || sawSwitch {
		t.Fatalf("events did not preserve uncertain failure without fallback: uncertain=%v switch=%v events=%+v", sawUncertainFailure, sawSwitch, events)
	}
}

func TestMailboxSchedulerRetriesNewInterfaceAfterTransientEmptyResponse(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-scheduler-transient-new"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AppleID:            "transient@example.com",
		DSID:               "dsid-transient",
		PremiumMailBaseURL: "https://example.invalid",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
		LoginStates: []LoginState{
			{Kind: LoginStateAppleAccount, Host: "appleid.apple.com", Origin: "https://account.apple.com", Scnt: "scnt", SessionID: "sid"},
			{Kind: LoginStateICloudWeb, Host: "www.icloud.com", Origin: "https://www.icloud.com", Cookies: []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	accountID := sessions[0].AccountID

	var attemptsMu sync.Mutex
	attempts := map[mailboxCreateChannel]int{}
	var sequence []mailboxCreateChannel
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		channel := schedulerTestAttemptChannel(ctx)
		attemptsMu.Lock()
		attempts[channel]++
		attempt := attempts[channel]
		sequence = append(sequence, channel)
		attemptsMu.Unlock()
		switch channel {
		case mailboxCreateChannelAppleAccount:
			switch attempt {
			case 1:
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("apple_account_generate_empty", "Apple Account 未返回候选隐私邮箱；阶段：生成候选隐私邮箱；HTTP 200；原始返回：空响应", true)
			case 2:
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("apple_account_generate_empty", "Apple Account 未返回候选隐私邮箱；阶段：生成候选隐私邮箱；HTTP 200；原始返回：空响应", true)
			default:
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("apple_account_hme_limit", "新接口当前小时额度已用完", true)
			}
		case mailboxCreateChannelICloudWeb:
			if attempt > 1 {
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "旧接口当前小时额度已用完", true)
			}
		default:
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("unexpected_channel", "定时创建没有指定接口", false)
		}
		email := fmt.Sprintf("%s-%d@icloud.com", channel, attempt)
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, email)
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true, Origin: string(channel)}, nil
	}

	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	server.runMailboxSchedulerBatch(context.Background(), ownerID, job, mailboxSchedulerConfig{
		AccountIDs: []string{accountID},
		Label:      "SCH",
		BatchSize:  1,
	}, 1)
	state, events := job.snapshot()
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	wantSequence := []mailboxCreateChannel{
		mailboxCreateChannelAppleAccount,
		mailboxCreateChannelAppleAccount,
		mailboxCreateChannelICloudWeb,
		mailboxCreateChannelICloudWeb,
	}
	if !reflect.DeepEqual(sequence, wantSequence) {
		t.Fatalf("channel sequence = %+v, want %+v", sequence, wantSequence)
	}
	if state.Success != 1 || state.Failed != 1 {
		t.Fatalf("scheduler state = %+v, want success=1 failed=1", state)
	}
	var sawTransientRetry bool
	var sawTransientFallback bool
	for _, event := range events {
		if event.Type == "channel_failed" && strings.Contains(event.Message, "HTTP 200") && strings.Contains(event.Message, "下轮重试新接口") {
			sawTransientRetry = true
		}
		if event.Type == "channel_failed" && strings.Contains(event.Message, "HTTP 200") && strings.Contains(event.Message, "切换旧接口继续尝试") {
			sawTransientFallback = true
		}
	}
	if !sawTransientRetry || !sawTransientFallback {
		t.Fatalf("events did not include transient retry and fallback: retry=%v fallback=%v events=%+v", sawTransientRetry, sawTransientFallback, events)
	}
}

func TestMailboxSchedulerOneShotAppleRetryStaysExplicitApple(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-scheduler-oneshot-apple"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AppleID:            "oneshot-apple@example.com",
		DSID:               "dsid-oneshot-apple",
		PremiumMailBaseURL: "https://example.invalid",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
		LoginStates: []LoginState{
			{Kind: LoginStateAppleAccount, Host: "appleid.apple.com", Origin: "https://account.apple.com", Scnt: "scnt", SessionID: "sid"},
			{Kind: LoginStateICloudWeb, Host: "www.icloud.com", Origin: "https://www.icloud.com", Cookies: []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	accountID := sessions[0].AccountID

	var attemptsMu sync.Mutex
	attempts := map[mailboxCreateChannel]int{}
	var sequence []mailboxCreateChannel
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		requested := mailboxCreateChannelFromContext(ctx)
		channel := schedulerTestAttemptChannel(ctx)
		attemptsMu.Lock()
		attempts[channel]++
		attempt := attempts[channel]
		sequence = append(sequence, requested)
		attemptsMu.Unlock()
		switch channel {
		case mailboxCreateChannelAppleAccount:
			switch attempt {
			case 1, 2:
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("apple_account_generate_empty", "Apple Account 未返回候选隐私邮箱；阶段：生成候选隐私邮箱；HTTP 200；原始返回：空响应", true)
			default:
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("apple_account_hme_limit", "新接口当前小时额度已用完", true)
			}
		case mailboxCreateChannelICloudWeb:
			if attempt > 1 {
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "旧接口当前小时额度已用完", true)
			}
		default:
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("unexpected_channel", "定时创建没有指定接口", false)
		}
		email := fmt.Sprintf("%s-%d@icloud.com", channel, attempt)
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, email)
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true, Origin: string(channel)}, nil
	}

	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	server.runMailboxSchedulerBatch(context.Background(), ownerID, job, mailboxSchedulerConfig{
		AccountIDs: []string{accountID},
		Label:      "SCH",
		BatchSize:  1,
	}, 1)
	state, _ := job.snapshot()
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	wantSequence := []mailboxCreateChannel{
		mailboxCreateChannelAuto,
		mailboxCreateChannelAppleAccount,
		mailboxCreateChannelICloudWeb,
		mailboxCreateChannelICloudWeb,
	}
	if !reflect.DeepEqual(sequence, wantSequence) {
		t.Fatalf("requested channel sequence = %+v, want %+v (one-shot Apple retry must stay explicit Apple, not auto)", sequence, wantSequence)
	}
	if state.Success != 1 || state.Failed != 1 {
		t.Fatalf("scheduler state = %+v, want success=1 failed=1", state)
	}
}

func TestCreateAppleAccountMailboxKeepsRefreshedStateWhenCreateFails(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-apple-refresh-fail"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID: ownerID,
		AppleID: "refresh-fail@example.com",
		LoginStates: []LoginState{{
			Kind:      LoginStateAppleAccount,
			Host:      "appleid.apple.com",
			Origin:    "https://account.apple.com",
			Scnt:      "stale-scnt",
			SessionID: "sid",
			APIKey:    "stale-key",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	session := sessions[0]

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("scnt") != "stale-scnt" {
				t.Fatalf("token scnt header = %q, want stale-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "fresh-token-scnt")
			http.SetCookie(w, &http.Cookie{Name: "token-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "fresh-token-scnt" {
				t.Fatalf("manage scnt header = %q, want fresh-token-scnt", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "token-cookie=ok") {
				t.Fatalf("manage cookie header = %q, want token response cookie", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "fresh-manage-scnt")
			http.SetCookie(w, &http.Cookie{Name: "manage-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("add api key header = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "fresh-manage-scnt" {
				t.Fatalf("add scnt header = %q, want fresh-manage-scnt", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "manage-cookie=ok") {
				t.Fatalf("add cookie header = %q, want refreshed cookies", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "fresh-failed-scnt")
			http.SetCookie(w, &http.Cookie{Name: "fail-cookie", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`You have reached the limit of addresses you can create right now. Please try again later.`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	accountKey := mailboxCreateAccountKey(ownerID, session)
	_, err := server.createICloudMailboxRemoteAppleAccount(context.Background(), ownerID, session, "LAB", "", accountKey)
	if err == nil {
		t.Fatal("create error = nil, want Apple Account limit error")
	}
	got := store.ICloudSessionsForOwner(ownerID)[0]
	state, ok := appleAccountLoginState(got)
	if !ok || state.Scnt != "fresh-manage-scnt" || state.APIKey != "fresh-key" {
		t.Fatalf("saved apple account state = %+v ok=%v, want last successful refreshed state after failed create", state, ok)
	}
	cookie := cookieHeader(state.Cookies, ts.URL+"/account/manage/email/private/add")
	if strings.Contains(cookie, "fail-cookie=ok") {
		t.Fatalf("saved cookie header = %q, want failed response cookie ignored", cookie)
	}
	if !strings.Contains(cookie, "manage-cookie=ok") {
		t.Fatalf("saved cookie header = %q, want last successful manage cookie", cookie)
	}
	if remaining := server.mailboxCreateCooldownRemaining(mailboxCreateChannelCooldownKey(accountKey, mailboxCreateChannelAppleAccount)); remaining <= 0 {
		t.Fatalf("apple account cooldown remaining = %v, want positive", remaining)
	}
	if remaining := server.mailboxCreateCooldownRemaining(mailboxCreateChannelCooldownKey(accountKey, mailboxCreateChannelICloudWeb)); remaining > 0 {
		t.Fatalf("icloud web cooldown remaining = %v, want zero when only Apple Account hit limit", remaining)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestCreateAppleAccountMailboxCleansRemoteWhenRefreshedStatePersistenceFails(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-apple-create-session-persist"
	account, err := store.AddAccountForOwner(ownerID, "Apple Account", "create-session-persist@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   account.AppleID,
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt",
			APIKey:          "api-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(10 * time.Minute),
			LastCheckOK:     true,
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}

	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	var paths []string
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hmeEmails":[]}}`))
		case "POST /account/manage/email/private/add":
			_, _ = w.Write([]byte(`{"emailAddress":"generated-session-persist@icloud.com"}`))
		case "PUT /account/manage/email/private/add/complete":
			store.path = badPath
			_, _ = w.Write([]byte(`{"emailAddress":"created-session-persist@icloud.com","id":"remote-session-persist","active":true}`))
		case "GET /account/manage/email/private/remote-session-persist.em":
			_, _ = w.Write([]byte(`{"emailAddress":"created-session-persist@icloud.com","id":"remote-session-persist","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer remoteServer.Close()
	appleAccountManageBaseURL = remoteServer.URL

	var cleanupCalled bool
	var cleaned Mailbox
	handler.deleteRemoteMailbox = func(_ context.Context, mailbox Mailbox) error {
		cleanupCalled = true
		cleaned = mailbox
		return nil
	}

	_, remote, err := handler.createICloudMailboxForOwner(context.Background(), ownerID, account.ID, "LAB", "")
	if !isCodedError(err, "icloud_session_persist_after_mailbox_create") {
		t.Fatalf("create error = %#v, want icloud_session_persist_after_mailbox_create", err)
	}
	if remote.AnonymousID != "remote-session-persist" {
		t.Fatalf("remote = %+v, want the created remote mailbox for cleanup", remote)
	}
	if !cleanupCalled || cleaned.RemoteAnonymousID != "remote-session-persist" {
		t.Fatalf("cleanup = called:%t mailbox:%+v, want remote cleanup", cleanupCalled, cleaned)
	}
	if len(store.Snapshot().Mailboxes) != 0 {
		t.Fatalf("local mailboxes after session persistence failure = %+v, want none", store.Snapshot().Mailboxes)
	}
	if strings.Join(paths, "\n") != strings.Join([]string{
		"GET /account/manage/email/private",
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/remote-session-persist.em",
	}, "\n") {
		t.Fatalf("remote paths = %#v", paths)
	}
}

func TestSaveICloudSessionForOwnerKeepsMultipleAppleAccounts(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-multi"
	for _, session := range []ICloudSession{
		{OwnerID: ownerID, AppleID: "first@example.com", DSID: "dsid-first", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: ownerID, AppleID: "second@example.com", DSID: "dsid-second", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
	} {
		if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
			t.Fatal(err)
		}
	}

	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2: %+v", len(sessions), sessions)
	}
	if sessions[0].AccountID == "" || sessions[1].AccountID == "" || sessions[0].AccountID == sessions[1].AccountID {
		t.Fatalf("account ids not separated: %+v", sessions)
	}
	state := store.SnapshotForOwner(ownerID)
	if len(state.Accounts) != 2 {
		t.Fatalf("accounts = %d, want 2: %+v", len(state.Accounts), state.Accounts)
	}
}

func TestSaveICloudSessionForOwnerMergesLoginStates(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-merge"
	icloudSession := ICloudSession{
		OwnerID:            ownerID,
		AppleID:            "same@example.com",
		DSID:               "dsid-same",
		ClientID:           "client",
		PremiumMailBaseURL: "https://p-maildomainws.icloud.com",
		Host:               "www.icloud.com",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "icloud", Value: "ok", Domain: ".icloud.com", Path: "/"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Host:    "www.icloud.com",
			Cookies: []SessionCookie{{Name: "icloud", Value: "ok", Domain: ".icloud.com", Path: "/"}},
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, icloudSession); err != nil {
		t.Fatal(err)
	}
	appleAccountSession := ICloudSession{
		OwnerID: ownerID,
		AppleID: "same@example.com",
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Host:   "appleid.apple.com",
			Scnt:   "scnt",
			APIKey: "api-key",
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, appleAccountSession); err != nil {
		t.Fatal(err)
	}

	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1: %+v", len(sessions), sessions)
	}
	got := sessions[0]
	if got.DSID != icloudSession.DSID || got.PremiumMailBaseURL != icloudSession.PremiumMailBaseURL || len(got.Cookies) != 1 {
		t.Fatalf("iCloud state was not preserved: %+v", got)
	}
	if _, ok := appleAccountLoginState(got); !ok {
		t.Fatalf("apple account login state missing after merge: %+v", got.LoginStates)
	}
	if !hasLoginStateKind(got.LoginStates, LoginStateICloudWeb) {
		t.Fatalf("iCloud login state missing after merge: %+v", got.LoginStates)
	}
}

func TestSyncICloudMailboxesIsolatesSlowAccounts(t *testing.T) {
	oldTimeout := iCloudMailboxListAccountTimeout
	iCloudMailboxListAccountTimeout = 120 * time.Millisecond
	defer func() { iCloudMailboxListAccountTimeout = oldTimeout }()

	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "sync-isolate", "sync123")

	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer slowServer.Close()
	fastServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"timestamp": 1,
			"result": {
				"forwardToEmails": ["main@example.com"],
				"hmeEmails": [
					{"anonymousId":"fast1","hme":"Fast.Sync@iCloud.com","label":"FAST","isActive":true,"forwardToEmail":"main@example.com","origin":"ON_DEMAND"}
				]
			}
		}`))
	}))
	defer fastServer.Close()

	for _, session := range []ICloudSession{
		{
			OwnerID:            user.ID,
			AppleID:            "slow@example.com",
			DSID:               "slow-dsid",
			ClientID:           "slow-client",
			PremiumMailBaseURL: slowServer.URL,
			Host:               "www.icloud.com",
			Cookies:            []SessionCookie{{Name: "session", Value: "slow", Domain: "127.0.0.1", Path: "/"}},
		},
		{
			OwnerID:            user.ID,
			AppleID:            "fast@example.com",
			DSID:               "fast-dsid",
			ClientID:           "fast-client",
			PremiumMailBaseURL: fastServer.URL,
			Host:               "www.icloud.com",
			Cookies:            []SessionCookie{{Name: "session", Value: "fast", Domain: "127.0.0.1", Path: "/"}},
		},
	} {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/sync", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	started := time.Now()
	handler.ServeHTTP(rr, req)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("sync took %s, want isolated timeout under 1s", elapsed)
	}
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("sync = %d body=%s, want 207 for partial success", rr.Code, rr.Body.String())
	}
	var data struct {
		Success   bool                      `json:"success"`
		Partial   bool                      `json:"partial"`
		Code      string                    `json:"code"`
		Total     int                       `json:"total"`
		Created   int                       `json:"created"`
		Failed    int                       `json:"failed"`
		Results   []syncICloudMailboxResult `json:"results"`
		Mailboxes []publicMailbox           `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if data.Success || !data.Partial || data.Code != "icloud_sync_partial" || data.Total != 1 || data.Created != 1 || data.Failed != 1 {
		t.Fatalf("response = %+v", data)
	}
	if len(data.Mailboxes) != 1 || data.Mailboxes[0].Email != "fast.sync@icloud.com" {
		t.Fatalf("mailboxes = %+v", data.Mailboxes)
	}
	if len(data.Results) != 2 {
		t.Fatalf("results len = %d, want 2", len(data.Results))
	}
	var sawTimeout, sawFast bool
	for _, result := range data.Results {
		if result.AppleID == "slow@example.com" && !strings.Contains(result.Error, "超时") {
			t.Fatalf("slow result = %+v, want timeout error", result)
		}
		if result.AppleID == "slow@example.com" {
			sawTimeout = true
		}
		if result.AppleID == "fast@example.com" && result.Created == 1 && result.Source == string(mailboxCreateChannelICloudWeb) {
			sawFast = true
		}
	}
	if !sawTimeout || !sawFast {
		t.Fatalf("results = %+v, want timeout and fast success", data.Results)
	}
}

func TestSyncICloudMailboxesUsesSessionAfterGateWait(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-icloud-list-fresh"
	accountID := "account-icloud-list-fresh"
	requestSeen := make(chan string, 1)
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestSeen <- r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"timestamp":1,"result":{"hmeEmails":[]}}`))
	}))
	defer remoteServer.Close()

	initial := ICloudSession{
		OwnerID:            ownerID,
		AccountID:          accountID,
		AppleID:            "icloud-list-fresh@example.com",
		DSID:               "icloud-list-fresh-dsid",
		PremiumMailBaseURL: remoteServer.URL,
		Cookies: []SessionCookie{{
			Name:   "session",
			Value:  "stale-cookie",
			Domain: "127.0.0.1",
			Path:   "/",
		}},
		LoginStates: []LoginState{{
			Kind: LoginStateICloudWeb,
			Cookies: []SessionCookie{{
				Name:   "session",
				Value:  "stale-cookie",
				Domain: "127.0.0.1",
				Path:   "/",
			}},
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, initial); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger()).(*Server)

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(ownerID, accountID),
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, syncErr := handler.syncICloudMailboxesForSession(
			context.Background(),
			httptest.NewRequest(http.MethodGet, "/", nil),
			ownerID,
			initial,
		)
		done <- syncErr
	}()

	select {
	case <-requestSeen:
		releaseAccountOperation()
		t.Fatal("iCloud mailbox list ran before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}

	fresh := cloneICloudSession(initial)
	fresh.Cookies[0].Value = "fresh-cookie"
	fresh.LoginStates[0].Cookies[0].Value = "fresh-cookie"
	if err := store.SaveICloudSessionForOwner(ownerID, fresh); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case cookie := <-requestSeen:
		if !strings.Contains(cookie, "session=fresh-cookie") {
			t.Fatalf("iCloud mailbox list cookie = %q, want fresh-cookie", cookie)
		}
	case <-time.After(time.Second):
		t.Fatal("iCloud mailbox list request was not sent")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("iCloud mailbox sync error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("iCloud mailbox sync did not finish")
	}
}

func TestCleanRemoteMailboxUsesSessionAfterGateWait(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-clean-fresh-session"
	accountID := "account-clean-fresh-session"
	requestSeen := make(chan string, 2)
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestSeen <- r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/mailws2/v1/geqs/query":
			_, _ = w.Write([]byte(`{"domainObjects":[{"identifier":"trash","name":"Deleted Messages","messageCount":0}]}`))
		case "/mailws2/v1/message/list":
			_, _ = w.Write([]byte(`{"domainObjects":[]}`))
		default:
			t.Fatalf("unexpected cleanup request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer remoteServer.Close()

	initial := ICloudSession{
		OwnerID:            ownerID,
		AccountID:          accountID,
		AppleID:            "clean-fresh-session@example.com",
		DSID:               "clean-fresh-session-dsid",
		MailGatewayBaseURL: remoteServer.URL,
		Cookies: []SessionCookie{{
			Name:   "session",
			Value:  "stale-cookie",
			Domain: "127.0.0.1",
			Path:   "/",
		}},
		LoginStates: []LoginState{{
			Kind: LoginStateICloudWeb,
			Cookies: []SessionCookie{{
				Name:   "session",
				Value:  "stale-cookie",
				Domain: "127.0.0.1",
				Path:   "/",
			}},
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, initial); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "clean-fresh", "clean-fresh.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger()).(*Server)

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(ownerID, accountID),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+mailbox.ID+"/remote-clean", strings.NewReader(`{"move_synced":false,"empty_trash":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", mailbox.ID)
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.handleCleanRemoteMailbox(rr, req)
		close(done)
	}()

	select {
	case <-requestSeen:
		releaseAccountOperation()
		t.Fatal("remote cleanup ran before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}

	fresh := cloneICloudSession(initial)
	fresh.Cookies[0].Value = "fresh-cookie"
	fresh.LoginStates[0].Cookies[0].Value = "fresh-cookie"
	if err := store.SaveICloudSessionForOwner(ownerID, fresh); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case cookie := <-requestSeen:
		if !strings.Contains(cookie, "session=fresh-cookie") {
			t.Fatalf("remote cleanup cookie = %q, want fresh-cookie", cookie)
		}
	case <-time.After(time.Second):
		select {
		case <-done:
			t.Fatalf("remote cleanup request was not sent; response=%d body=%s", rr.Code, rr.Body.String())
		default:
			t.Fatal("remote cleanup request was not sent")
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("remote cleanup did not finish")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("remote cleanup status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCleanRemoteMailboxesUsesSessionAfterGateWait(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-clean-bulk-fresh-session"
	account, err := store.AddAccountForOwner(ownerID, "Clean bulk fresh", "clean-bulk-fresh-session@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	accountID := account.ID
	requestSeen := make(chan string, 2)
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestSeen <- r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/mailws2/v1/geqs/query":
			_, _ = w.Write([]byte(`{"domainObjects":[{"identifier":"trash","name":"Deleted Messages","messageCount":0}]}`))
		case "/mailws2/v1/message/list":
			_, _ = w.Write([]byte(`{"domainObjects":[]}`))
		default:
			t.Fatalf("unexpected bulk cleanup request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer remoteServer.Close()

	initial := ICloudSession{
		OwnerID:            ownerID,
		AccountID:          accountID,
		AppleID:            "clean-bulk-fresh-session@example.com",
		DSID:               "clean-bulk-fresh-session-dsid",
		MailGatewayBaseURL: remoteServer.URL,
		Cookies: []SessionCookie{{
			Name:   "session",
			Value:  "stale-cookie",
			Domain: "127.0.0.1",
			Path:   "/",
		}},
		LoginStates: []LoginState{{
			Kind: LoginStateICloudWeb,
			Cookies: []SessionCookie{{
				Name:   "session",
				Value:  "stale-cookie",
				Domain: "127.0.0.1",
				Path:   "/",
			}},
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, initial); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner(ownerID, accountID, "clean-bulk-fresh", "clean-bulk-fresh.alias@icloud.com"); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger()).(*Server)

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(ownerID, accountID),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/remote-clean", strings.NewReader(
		fmt.Sprintf(`{"account_id":%q,"move_synced":false,"empty_trash":true}`, accountID),
	))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.handleCleanRemoteMailboxes(rr, req)
		close(done)
	}()

	select {
	case <-requestSeen:
		releaseAccountOperation()
		t.Fatal("bulk remote cleanup ran before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}

	fresh := cloneICloudSession(initial)
	fresh.Cookies[0].Value = "fresh-cookie"
	fresh.LoginStates[0].Cookies[0].Value = "fresh-cookie"
	if err := store.SaveICloudSessionForOwner(ownerID, fresh); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case cookie := <-requestSeen:
		if !strings.Contains(cookie, "session=fresh-cookie") {
			t.Fatalf("bulk remote cleanup cookie = %q, want fresh-cookie", cookie)
		}
	case <-time.After(time.Second):
		select {
		case <-done:
			t.Fatalf("bulk remote cleanup request was not sent; response=%d body=%s", rr.Code, rr.Body.String())
		default:
			t.Fatal("bulk remote cleanup request was not sent")
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bulk remote cleanup did not finish")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("bulk remote cleanup status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSyncICloudMailboxesReturnsFailureWhenAllAccountsFail(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "sync-all-failed", "sync123")

	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "provider unavailable", http.StatusBadGateway)
	}))
	defer remoteServer.Close()

	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		AppleID:            "failed@example.com",
		DSID:               "failed-dsid",
		ClientID:           "failed-client",
		PremiumMailBaseURL: remoteServer.URL,
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "failed", Domain: "127.0.0.1", Path: "/"}},
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/sync", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("sync status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusBadGateway)
	}
	var data struct {
		Success bool                      `json:"success"`
		Code    string                    `json:"code"`
		Message string                    `json:"message"`
		Failed  int                       `json:"failed"`
		Results []syncICloudMailboxResult `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if data.Success || data.Code != "icloud_sync_failed" || data.Failed != 1 || len(data.Results) != 1 {
		t.Fatalf("response = %+v, want failed response with per-account result", data)
	}
	if !strings.Contains(data.Message, "全部") {
		t.Fatalf("message = %q, want all-failed detail", data.Message)
	}
}

func TestSyncICloudMailboxesIncludesAppleAccountOnlySessions(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "sync-apple-only", "sync123")

	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account/manage/email/private" {
			t.Fatalf("Apple Account list path = %q, want /account/manage/email/private", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"result": {
				"hmeEmails": [
					{"id":"apple-only-remote","emailAddress":"apple-only@icloud.com","isActive":true}
				]
			}
		}`))
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("list path = %q, want /v2/hme/list", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"timestamp": 1,
			"result": {
				"forwardToEmails": [],
				"hmeEmails": [
					{"anonymousId":"web-only-remote","hme":"web-only@icloud.com","isActive":true}
				]
			}
		}`))
	}))
	defer webServer.Close()

	sessions := []ICloudSession{
		{
			OwnerID:            user.ID,
			AppleID:            "apple-only@example.com",
			DSID:               "apple-only-dsid",
			PremiumMailBaseURL: "https://apple-account-only.invalid",
			Cookies:            []SessionCookie{{Name: "session", Value: "apple-account-cookie"}},
			LoginStates: []LoginState{{
				Kind:    LoginStateAppleAccount,
				Scnt:    "scnt",
				APIKey:  "api-key",
				Cookies: []SessionCookie{{Name: "session", Value: "apple-account-cookie"}},
			}},
		},
		{
			OwnerID:            user.ID,
			AppleID:            "icloud-web@example.com",
			DSID:               "icloud-web-dsid",
			PremiumMailBaseURL: webServer.URL,
			Cookies:            []SessionCookie{{Name: "session", Value: "icloud-web-cookie"}},
		},
	}
	for _, session := range sessions {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/sync", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sync = %d body=%s", rr.Code, rr.Body.String())
	}

	var data struct {
		Success   bool                      `json:"success"`
		Total     int                       `json:"total"`
		Created   int                       `json:"created"`
		Failed    int                       `json:"failed"`
		Results   []syncICloudMailboxResult `json:"results"`
		Mailboxes []publicMailbox           `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if !data.Success || data.Total != 2 || data.Created != 2 || data.Failed != 0 {
		t.Fatalf("response = %+v, want Apple Account-only session included", data)
	}
	if len(data.Results) != 2 || len(data.Mailboxes) != 2 {
		t.Fatalf("results/mailboxes = %d/%d, want two sessions and two mailboxes", len(data.Results), len(data.Mailboxes))
	}
	var sawApple, sawWeb bool
	for _, result := range data.Results {
		switch result.AppleID {
		case "apple-only@example.com":
			sawApple = result.Source == string(mailboxCreateChannelAppleAccount)
		case "icloud-web@example.com":
			sawWeb = result.Source == string(mailboxCreateChannelICloudWeb)
		}
	}
	if !sawApple || !sawWeb {
		t.Fatalf("results = %+v, want Apple Account and iCloud Web sessions", data.Results)
	}
}

func TestAdminSyncICloudMailboxesCoversAllOwnedSessions(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, admin := registerTestUser(t, handler, "sync-all-admin", "sync123")
	_, normal := registerTestUser(t, handler, "sync-all-user", "sync123")

	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"timestamp": 1,
			"result": {
				"forwardToEmails": [],
				"hmeEmails": [
					{"anonymousId":"admin-sync-remote","hme":"admin-sync@example.com","label":"ADMIN","isActive":true}
				]
			}
		}`))
	}))
	defer adminServer.Close()
	normalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"timestamp": 1,
			"result": {
				"forwardToEmails": [],
				"hmeEmails": [
					{"anonymousId":"user-sync-remote","hme":"user-sync@example.com","label":"USER","isActive":true}
				]
			}
		}`))
	}))
	defer normalServer.Close()

	for _, session := range []ICloudSession{
		{
			OwnerID:            admin.ID,
			AppleID:            "sync-all-admin@example.com",
			DSID:               "sync-all-admin-dsid",
			PremiumMailBaseURL: adminServer.URL,
			Host:               "www.icloud.com",
			Cookies:            []SessionCookie{{Name: "session", Value: "sync-all-admin-cookie", Domain: "127.0.0.1", Path: "/"}},
		},
		{
			OwnerID:            normal.ID,
			AppleID:            "sync-all-user@example.com",
			DSID:               "sync-all-user-dsid",
			PremiumMailBaseURL: normalServer.URL,
			Host:               "www.icloud.com",
			Cookies:            []SessionCookie{{Name: "session", Value: "sync-all-user-cookie", Domain: "127.0.0.1", Path: "/"}},
		},
	} {
		if err := store.SaveICloudSessionForOwner(session.OwnerID, session); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/sync?owner_id=all", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin sync = %d body=%s", rr.Code, rr.Body.String())
	}

	var data struct {
		Success   bool                      `json:"success"`
		Total     int                       `json:"total"`
		Created   int                       `json:"created"`
		Failed    int                       `json:"failed"`
		Results   []syncICloudMailboxResult `json:"results"`
		Mailboxes []publicMailbox           `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if !data.Success || data.Total != 2 || data.Created != 2 || data.Failed != 0 {
		t.Fatalf("admin sync response = %+v, want both owned sessions synchronized", data)
	}
	if len(data.Results) != 2 || len(data.Mailboxes) != 2 {
		t.Fatalf("admin sync response sizes = results:%d mailboxes:%d, want 2 each", len(data.Results), len(data.Mailboxes))
	}
	owners := map[string]bool{}
	for _, mailbox := range data.Mailboxes {
		owners[mailbox.OwnerID] = true
	}
	if !owners[admin.ID] || !owners[normal.ID] {
		t.Fatalf("admin sync mailbox owners = %+v, want admin and normal user", owners)
	}
}

func TestSyncICloudMailboxesDoesNotMarkOtherProviderMailboxesMissing(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "sync-mixed-origin", "sync123")
	account, err := store.AddAccountForOwner(user.ID, "Mixed Origin", "mixed-origin@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	appleCalled := false
	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account/manage/email/private" {
			t.Fatalf("Apple Account list path = %q, want /account/manage/email/private", r.URL.Path)
		}
		appleCalled = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"result": {
				"hmeEmails": [
					{"id":"mixed-apple-missing","emailAddress":"mixed-apple-missing@example.com","isActive":true}
				]
			}
		}`))
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("list path = %q, want /v2/hme/list", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"timestamp": 1,
			"result": {
				"forwardToEmails": [],
				"hmeEmails": [
					{"anonymousId":"mixed-web-listed","hme":"mixed-web-listed@example.com","label":"WEB","isActive":true}
				]
			}
		}`))
	}))
	defer remoteServer.Close()

	session := ICloudSession{
		OwnerID:            user.ID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "mixed-origin-dsid",
		PremiumMailBaseURL: remoteServer.URL,
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "mixed-origin-cookie", Domain: "127.0.0.1", Path: "/"}},
		LoginStates: []LoginState{
			{
				Kind:    LoginStateICloudWeb,
				Cookies: []SessionCookie{{Name: "session", Value: "mixed-origin-cookie", Domain: "127.0.0.1", Path: "/"}},
			},
			{
				Kind:   LoginStateAppleAccount,
				Scnt:   "mixed-origin-scnt",
				APIKey: "mixed-origin-api-key",
			},
		},
	}
	if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
		t.Fatal(err)
	}
	webMailbox, err := store.AddMailboxForOwnerWithRemote(user.ID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "mixed-web-listed",
		Origin:      "ICLOUD_WEB",
		Email:       "mixed-web-listed@example.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	appleMailbox, err := store.AddMailboxForOwnerWithRemote(user.ID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "mixed-apple-missing",
		Origin:      "APPLE_ACCOUNT",
		Email:       "mixed-apple-missing@example.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/sync", strings.NewReader(`{"account_id":"`+account.ID+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("mixed-origin sync = %d body=%s", rr.Code, rr.Body.String())
	}
	var data struct {
		RemoteMissing int `json:"remote_missing"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if data.RemoteMissing != 0 {
		t.Fatalf("remote_missing = %d, want no cross-provider missing mark", data.RemoteMissing)
	}
	if !appleCalled {
		t.Fatal("Apple Account provider was not synchronized when both login states were present")
	}
	currentWeb, ok := store.FindMailboxByID(webMailbox.ID)
	if !ok {
		t.Fatal("listed iCloud Web mailbox disappeared")
	}
	if !currentWeb.ICloudActive || currentWeb.Status == StatusDisabled {
		t.Fatalf("listed iCloud Web mailbox = %+v, want active state", currentWeb)
	}
	currentApple, ok := store.FindMailboxByID(appleMailbox.ID)
	if !ok {
		t.Fatal("Apple Account mailbox disappeared")
	}
	if !currentApple.ICloudActive || currentApple.Status == StatusDisabled || !currentApple.RemoteMissingAt.IsZero() {
		t.Fatalf("Apple Account mailbox = %+v, want unchanged active state", currentApple)
	}
}

func TestSyncICloudMailboxesReportsPartialProviderSourceFailure(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "sync-partial-source", "sync123")
	account, err := store.AddAccountForOwner(user.ID, "Partial Source", "partial-source@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account/manage/email/private" {
			t.Fatalf("Apple Account list path = %q, want /account/manage/email/private", r.URL.Path)
		}
		http.Error(w, "Apple Account provider unavailable", http.StatusBadGateway)
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("iCloud Web list path = %q, want /v2/hme/list", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"timestamp": 1,
			"result": {
				"forwardToEmails": [],
				"hmeEmails": [
					{"anonymousId":"partial-web-listed","hme":"partial-web-listed@example.com","isActive":true}
				]
			}
		}`))
	}))
	defer remoteServer.Close()

	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "partial-source-dsid",
		PremiumMailBaseURL: remoteServer.URL,
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "partial-source-cookie", Domain: "127.0.0.1", Path: "/"}},
		LoginStates: []LoginState{
			{
				Kind:    LoginStateICloudWeb,
				Cookies: []SessionCookie{{Name: "session", Value: "partial-source-cookie", Domain: "127.0.0.1", Path: "/"}},
			},
			{
				Kind:   LoginStateAppleAccount,
				Scnt:   "partial-source-scnt",
				APIKey: "partial-source-api-key",
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/sync", strings.NewReader(`{"account_id":"`+account.ID+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("authoritative-web sync status = %d body=%s, want 200", rr.Code, rr.Body.String())
	}
	var response struct {
		Success bool   `json:"success"`
		Partial bool   `json:"partial"`
		Code    string `json:"code"`
		Failed  int    `json:"failed"`
		Results []struct {
			Error   string `json:"error"`
			Warning string `json:"warning"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Success || response.Partial || response.Code != "" || response.Failed != 0 {
		t.Fatalf("authoritative-web sync response = %+v, want success=true with iCloud Web list as authority", response)
	}
	if len(response.Results) != 1 || response.Results[0].Error != "" || response.Results[0].Warning == "" {
		t.Fatalf("authoritative-web sync results = %+v, want warning without failing the whole sync", response.Results)
	}
}

func TestCreateICloudMailboxCreatesForEachSavedSession(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "multi-create", "multi123")
	for _, session := range []ICloudSession{
		{OwnerID: user.ID, AppleID: "first@example.com", DSID: "dsid-first", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: user.ID, AppleID: "second@example.com", DSID: "dsid-second", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
	} {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	wantAccounts := map[string]bool{}
	for _, session := range sessions {
		wantAccounts[session.AccountID] = false
	}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		if ownerID != user.ID {
			t.Fatalf("ownerID = %q, want %q", ownerID, user.ID)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, accountID+"@icloud.com")
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(`{"label":"LAB"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success   bool            `json:"success"`
		Created   int             `json:"created"`
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Created != 2 || len(body.Mailboxes) != 2 {
		t.Fatalf("body = %+v, want two mailboxes", body)
	}
	for _, mailbox := range body.Mailboxes {
		if _, ok := wantAccounts[mailbox.AccountID]; !ok {
			t.Fatalf("unexpected account id %q in mailbox %+v; want %+v", mailbox.AccountID, mailbox, wantAccounts)
		}
		wantAccounts[mailbox.AccountID] = true
	}
	for accountID, seen := range wantAccounts {
		if !seen {
			t.Fatalf("account %s did not create mailbox", accountID)
		}
	}
}

func TestCreateICloudMailboxUsesSelectedSavedSessions(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "selected-create", "multi123")
	for _, session := range []ICloudSession{
		{OwnerID: user.ID, AppleID: "first@example.com", DSID: "dsid-first", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: user.ID, AppleID: "broken@example.com", DSID: "dsid-broken", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
		{OwnerID: user.ID, AppleID: "third@example.com", DSID: "dsid-third", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "c", Value: "3"}}},
	} {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	selected := []string{sessions[0].AccountID, sessions[2].AccountID}
	var createdMu sync.Mutex
	createdAccounts := map[string]bool{}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		if accountID == sessions[1].AccountID {
			t.Fatalf("broken account %q should not be used", accountID)
		}
		createdMu.Lock()
		createdAccounts[accountID] = true
		createdMu.Unlock()
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, accountID+"@icloud.com")
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	bodyJSON := fmt.Sprintf(`{"label":"SEL","account_ids":["%s","%s"]}`, selected[0], selected[1])
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Created   int             `json:"created"`
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Created != 2 || len(body.Mailboxes) != 2 {
		t.Fatalf("body = %+v, want two selected mailboxes", body)
	}
	createdMu.Lock()
	defer createdMu.Unlock()
	for _, accountID := range selected {
		if !createdAccounts[accountID] {
			t.Fatalf("selected account %q was not used; created=%+v", accountID, createdAccounts)
		}
	}
	if createdAccounts[sessions[1].AccountID] {
		t.Fatalf("unselected account %q was used", sessions[1].AccountID)
	}
}

func TestCreateICloudMailboxResponseIncludesCreateChannel(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "create-channel", "multi123")
	session := ICloudSession{
		OwnerID:      user.ID,
		AppleID:      "channel@example.com",
		DSID:         "dsid-channel",
		IsICloudPlus: true,
		CanCreateHME: true,
		Cookies:      []SessionCookie{{Name: "a", Value: "1"}},
	}
	if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
		t.Fatal(err)
	}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, "created@example.icloud.com")
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true, Origin: "APPLE_ACCOUNT"}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(`{"label":"SOURCE"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Created   int             `json:"created"`
		Mailboxes []publicMailbox `json:"mailboxes"`
		Remotes   []struct {
			Origin       string `json:"origin"`
			Channel      string `json:"channel"`
			ChannelLabel string `json:"channel_label"`
		} `json:"remotes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Created != 1 || len(body.Mailboxes) != 1 || len(body.Remotes) != 1 {
		t.Fatalf("body = %+v, want one created mailbox and remote", body)
	}
	if body.Mailboxes[0].CreateChannel != string(mailboxCreateChannelAppleAccount) || body.Mailboxes[0].CreateChannelLabel != "新接口" {
		t.Fatalf("mailbox channel = %q/%q, want apple_account/新接口", body.Mailboxes[0].CreateChannel, body.Mailboxes[0].CreateChannelLabel)
	}
	if body.Remotes[0].Origin != "APPLE_ACCOUNT" || body.Remotes[0].Channel != string(mailboxCreateChannelAppleAccount) || body.Remotes[0].ChannelLabel != "新接口" {
		t.Fatalf("remote channel = %+v, want APPLE_ACCOUNT apple_account 新接口", body.Remotes[0])
	}
}

func TestCreateICloudMailboxUsesRequestedCreateChannel(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "create-requested-channel", "multi123")
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:      user.ID,
		AppleID:      "requested-channel@example.com",
		DSID:         "dsid-requested-channel",
		IsICloudPlus: true,
		CanCreateHME: true,
		Cookies:      []SessionCookie{{Name: "a", Value: "1"}},
		LoginStates: []LoginState{
			{Kind: LoginStateAppleAccount, Host: "appleid.apple.com", Origin: "https://account.apple.com", Scnt: "scnt"},
			{Kind: LoginStateICloudWeb, Host: "www.icloud.com", Origin: "https://www.icloud.com", Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	accountID := sessions[0].AccountID
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		channel := mailboxCreateChannelFromContext(ctx)
		if channel != mailboxCreateChannelICloudWeb {
			t.Fatalf("create channel = %q, want icloud_web", channel)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, "requested-old@example.icloud.com")
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true, Origin: string(channel)}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(fmt.Sprintf(`{"account_id":%q,"label":"REQ","create_channel":"icloud_web"}`, accountID)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateSettingsAreSavedServerSide(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "create-settings", "multi123")
	account, err := store.AddAccountForOwner(user.ID, "A", "a@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/create-settings", strings.NewReader(fmt.Sprintf(`{
		"label":"UPI",
		"note":"server side",
		"account_ids":[%q],
		"create_channel":"apple_account",
		"scheduler_create_channel":"icloud_web",
		"apple_account_two_factor_method":"phone",
		"icloud_web_two_factor_method":"trusted_device",
		"scheduler_interval_minutes":30,
		"scheduler_round_interval_seconds":8,
		"mailbox_page_size":25
	}`, account.ID)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("save settings = %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/create-settings", nil)
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get settings = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Settings struct {
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
		} `json:"settings"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Settings.Label != "UPI" ||
		body.Settings.Note != "server side" ||
		!reflect.DeepEqual(body.Settings.AccountIDs, []string{account.ID}) ||
		body.Settings.CreateChannel != string(mailboxCreateChannelAppleAccount) ||
		body.Settings.SchedulerCreateChannel != string(mailboxCreateChannelICloudWeb) ||
		body.Settings.AppleAccountTwoFactorMethod != appleTwoFactorMethodPhone ||
		body.Settings.ICloudWebTwoFactorMethod != appleTwoFactorMethodTrustedDevice ||
		body.Settings.SchedulerIntervalMinutes != 30 ||
		body.Settings.SchedulerRoundIntervalSeconds != 8 ||
		body.Settings.MailboxPageSize != 25 {
		t.Fatalf("settings = %+v, want saved server config", body.Settings)
	}
}

func TestSchedulerCreateChannelsRespectRequestedChannel(t *testing.T) {
	session := ICloudSession{
		Cookies: []SessionCookie{{Name: "a", Value: "1"}},
		LoginStates: []LoginState{
			{Kind: LoginStateAppleAccount, Host: "appleid.apple.com", Origin: "https://account.apple.com", Scnt: "scnt"},
			{Kind: LoginStateICloudWeb, Host: "www.icloud.com", Origin: "https://www.icloud.com", Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		},
	}
	if got := schedulerCreateChannelsForSession(session, mailboxCreateChannelICloudWeb); !reflect.DeepEqual(got, []mailboxCreateChannel{mailboxCreateChannelICloudWeb}) {
		t.Fatalf("old-only channels = %+v", got)
	}
	if got := schedulerCreateChannelsForSession(session, mailboxCreateChannelAppleAccount); !reflect.DeepEqual(got, []mailboxCreateChannel{mailboxCreateChannelAppleAccount}) {
		t.Fatalf("new-only channels = %+v", got)
	}
	if got := schedulerCreateChannelsForSession(session, mailboxCreateChannelAuto); !reflect.DeepEqual(got, []mailboxCreateChannel{mailboxCreateChannelAppleAccount, mailboxCreateChannelICloudWeb}) {
		t.Fatalf("auto channels = %+v", got)
	}
}

func TestCreateICloudMailboxReturnsAccountFailuresWhenAllSelectedSessionsFail(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "all-fail-create", "multi123")
	for _, session := range []ICloudSession{
		{OwnerID: user.ID, AppleID: "first@example.com", DSID: "dsid-first", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: user.ID, AppleID: "second@example.com", DSID: "dsid-second", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
	} {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "当前小时额度已用完", true)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(`{"label":"FAIL"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("create = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success  bool                   `json:"success"`
		Message  string                 `json:"message"`
		Created  int                    `json:"created"`
		Failures []createMailboxFailure `json:"failures"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Success || strings.TrimSpace(body.Message) == "" || body.Created != 0 || len(body.Failures) != 2 {
		t.Fatalf("body = %+v, want two account failures", body)
	}
}

func TestSyncMailboxUsesMailboxAccountSession(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-account-sync"
	for _, session := range []ICloudSession{
		testIMAPSession(ownerID, "", "first@example.com"),
		testIMAPSession(ownerID, "", "second@example.com"),
	} {
		if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(sessions))
	}
	targetAccountID := sessions[1].AccountID
	mailbox, err := store.AddMailboxForOwner(ownerID, targetAccountID, "target", "target@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		if state.IMAPEmail != "second@example.com" {
			t.Fatalf("sync used IMAP email %q, want second@example.com", state.IMAPEmail)
		}
		if len(mailboxes) != 1 || mailboxes[0].AccountID != targetAccountID {
			t.Fatalf("sync mailboxes = %+v, want account %q", mailboxes, targetAccountID)
		}
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "m1",
				UID:        "1",
				Subject:    "ChatGPT code",
				Body:       "Use 123456 to continue.",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}
	count, err := server.syncMailbox(context.Background(), mailbox, time.Time{}, "ChatGPT")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("synced = %d, want 1", count)
	}
}

func newTestStore(t *testing.T) *FileStore {
	t.Helper()
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func saveTestAppleAccountSession(t *testing.T, store *FileStore, ownerID, accountID, appleID string) {
	t.Helper()
	now := time.Now()
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:   ownerID,
		AccountID: accountID,
		AppleID:   appleID,
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			APIKey:          "test-api-key",
			Scnt:            "scnt",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(10 * time.Minute),
			LastCheckOK:     true,
		}},
	}); err != nil {
		t.Fatal(err)
	}
}

func saveTestICloudWebSession(t *testing.T, store *FileStore, ownerID, accountID, appleID string) {
	t.Helper()
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AccountID:          accountID,
		AppleID:            appleID,
		DSID:               "test-dsid",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		PremiumMailBaseURL: "https://p123-mailws.icloud.com",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "session", Value: "cookie"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
}

func registerTestUser(t *testing.T, handler http.Handler, username, password string) (*http.Cookie, publicUser) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(`{"username":"`+username+`","password":"`+password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("register user %s = %d body=%s", username, rr.Code, rr.Body.String())
	}
	var body struct {
		User publicUser `json:"user"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			return cookie, body.User
		}
	}
	t.Fatalf("register user %s did not set session cookie", username)
	return nil, publicUser{}
}

func createTestMailboxWithCookie(t *testing.T, handler http.Handler, cookie *http.Cookie, label, email string) publicMailbox {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes", strings.NewReader(`{"label":"`+label+`","email":"`+email+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create mailbox %s = %d body=%s", email, rr.Code, rr.Body.String())
	}
	var body struct {
		Mailbox publicMailbox `json:"mailbox"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Mailbox
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func zeroTime() time.Time {
	return time.Time{}
}
