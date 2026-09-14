package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func addClosureTestCSRF(req *http.Request, sessionCookie *http.Cookie) {
	token := csrfTokenForSession(sessionCookie.Value)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token, Path: "/"})
	req.Header.Set(csrfHeaderName, token)
}

func TestBrowserMutationRequiresCSRFAndSameOrigin(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	cookie, _ := registerTestUser(t, handler, "csrf-user", "password123")

	req := httptest.NewRequest(http.MethodPost, "/api/create-settings", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrfTokenForSession(cookie.Value), Path: "/"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), `"code":"csrf_invalid"`) {
		t.Fatalf("missing CSRF token status=%d body=%s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), `"code":"csrf_invalid"`) {
		t.Fatalf("logout without CSRF status=%d body=%s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/create-settings", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), `"code":"csrf_invalid"`) {
		t.Fatalf("cross-origin mutation status=%d body=%s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/create-settings", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://mail.example")
	req.Host = "mail.example"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("same-origin mutation status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestReverseProxyHeadersDriveOriginBaseURLAndSecureCookie(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)

	tests := []struct {
		name           string
		forwarded      string
		forwardedHost  string
		forwardedProto string
		wantBaseURL    string
	}{
		{
			name:           "x-forwarded headers",
			forwardedHost:  "mail.example:8443, 127.0.0.1:8787",
			forwardedProto: "https, http",
			wantBaseURL:    "https://mail.example:8443",
		},
		{
			name:        "rfc forwarded header",
			forwarded:   `for=192.0.2.1;proto=https;host="mail.example"`,
			wantBaseURL: "https://mail.example",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://internal.example/api/create-settings", nil)
			req.Host = "internal.example:8787"
			req.Header.Set("Origin", tt.wantBaseURL)
			if tt.forwarded != "" {
				req.Header.Set("Forwarded", tt.forwarded)
			}
			if tt.forwardedHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.forwardedHost)
			}
			if tt.forwardedProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.forwardedProto)
			}
			if !requestOriginMatches(req) {
				t.Fatalf("requestOriginMatches = false for forwarded request")
			}
			if got := requestBaseURL(req); got != tt.wantBaseURL {
				t.Fatalf("requestBaseURL = %q, want %q", got, tt.wantBaseURL)
			}
			if !handler.secureCookie(req) {
				t.Fatal("secureCookie = false behind forwarded HTTPS")
			}
		})
	}
}

func TestMessageSyncSkipsRemoteDeleteStatesBeforeResolvingSessions(t *testing.T) {
	for _, status := range []string{"pending", "unknown", "failed", "succeeded"} {
		t.Run(status, func(t *testing.T) {
			store := newTestStore(t)
			handler := NewServer(Config{}, store, discardLogger()).(*Server)
			handler.mailboxSyncMinInterval = 0
			mailbox, err := store.AddMailboxForOwnerWithRemote("owner-sync-"+status, "account-sync-"+status, ICloudRemoteMailbox{
				AnonymousID: "remote-sync-" + status,
				Origin:      mailboxRemoteOriginAppleAccount,
				Email:       "sync-" + status + "@icloud.com",
				IsActive:    true,
			}, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := store.BeginMailboxRemoteDelete(mailbox.ID, time.Now()); err != nil {
				t.Fatal(err)
			}
			if status != "pending" {
				if err := store.MarkMailboxRemoteDeleteFailed(mailbox.ID, "provider failure", time.Now()); err != nil {
					t.Fatal(err)
				}
				if status == "unknown" {
					if err := store.MarkMailboxRemoteDeleteUnknown(mailbox.ID, "transport uncertain", time.Now()); err != nil {
						t.Fatal(err)
					}
				} else if status == "succeeded" {
					if err := store.MarkMailboxRemoteDeleteSucceeded(mailbox.ID, time.Now()); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := store.SaveICloudSessionForOwner(mailbox.OwnerID, ICloudSession{
				OwnerID:   mailbox.OwnerID,
				AccountID: mailbox.AccountID,
				AppleID:   "sync-" + status + "@example.com",
				LoginStates: []LoginState{{
					Kind:            LoginStateICloudIMAP,
					IMAPEmail:       "sync-" + status + "@icloud.com",
					IMAPAppPassword: "app-password",
				}},
			}); err != nil {
				t.Fatal(err)
			}

			codeCalled := false
			handler.syncCodeMailboxBatchWithCursor = func(context.Context, LoginState, []Mailbox, time.Time, string, int) (iCloudIMAPSyncResult, error) {
				codeCalled = true
				return iCloudIMAPSyncResult{}, nil
			}
			if _, err := handler.syncMailboxCodeBatchForOwnerWithLimit(
				context.Background(),
				mailbox.OwnerID,
				[]Mailbox{mailbox},
				time.Time{},
				"OpenAI",
				1,
			); err != nil {
				t.Fatalf("IMAP sync error = %v, want skipped mailbox", err)
			}
			if codeCalled {
				t.Fatal("IMAP provider was called for mailbox in remote delete state")
			}

			webCalled := false
			handler.syncMailboxBatch = func(context.Context, ICloudSession, []Mailbox, time.Time, string, int) (map[string][]ICloudSyncedMessage, error) {
				webCalled = true
				return nil, nil
			}
			if err := handler.syncMailboxBatchForOwnerWithLimit(
				context.Background(),
				mailbox.OwnerID,
				[]Mailbox{mailbox},
				time.Time{},
				"OpenAI",
				1,
			); err != nil {
				t.Fatalf("iCloud Web sync error = %v, want skipped mailbox", err)
			}
			if webCalled {
				t.Fatal("iCloud Web provider was called for mailbox in remote delete state")
			}
		})
	}
}

func TestSensitiveExportsRejectGET(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, _ := registerTestUser(t, handler, "export-admin", "password123")

	for _, path := range []string{
		"/api/runtime/export",
		"/api/runtime/export-mailbox-apis",
		"/api/runtime/export-mailbox-emails",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		addClosureTestCSRF(req, cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s status=%d body=%s, want 405", path, rr.Code, rr.Body.String())
		}
	}
}

func TestAdminICloudSessionIncludesAllOwners(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, admin := registerTestUser(t, handler, "session-admin", "password123")
	_, user := registerTestUser(t, handler, "session-user", "password123")

	for _, session := range []ICloudSession{
		{OwnerID: admin.ID, AccountID: "admin-account", AppleID: "admin@example.com", SavedAt: time.Now()},
		{OwnerID: user.ID, AccountID: "user-account", AppleID: "user@example.com", SavedAt: time.Now()},
	} {
		if err := store.SaveICloudSessionForOwner(session.OwnerID, session); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/icloud/session?owner_id=all", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin session status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Sessions []json.RawMessage `json:"sessions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Sessions) != 2 {
		t.Fatalf("admin session count=%d body=%s, want 2", len(body.Sessions), rr.Body.String())
	}
}

func TestAdminDeleteUserRemoteFailureRetainsLocalData(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "delete-admin", "password123")
	_, user := registerTestUser(t, handler, "delete-user", "password123")
	account, err := store.AddAccountForOwner(user.ID, "Apple", "delete@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote(user.ID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "remote-delete-1",
		Origin:      mailboxRemoteOriginAppleAccount,
		Email:       "delete-alias@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	saveTestAppleAccountSession(t, store, user.ID, account.ID, account.AppleID)

	var calls atomic.Int32
	fail := atomic.Bool{}
	fail.Store(true)
	handler.deleteRemoteMailbox = func(ctx context.Context, mailbox Mailbox) error {
		calls.Add(1)
		if fail.Load() {
			return errCode("remote_delete_failed", "远端删除失败", true)
		}
		return nil
	}

	deleteUser := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+user.ID, nil)
		req.AddCookie(adminCookie)
		addClosureTestCSRF(req, adminCookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	rr := deleteUser()
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("remote failure status=%d body=%s, want 502", rr.Code, rr.Body.String())
	}
	if _, ok := store.UserByID(user.ID); !ok {
		t.Fatal("user deleted after remote failure")
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); !ok {
		t.Fatal("mailbox deleted after remote failure")
	}

	fail.Store(false)
	rr = deleteUser()
	if rr.Code != http.StatusOK {
		t.Fatalf("remote success status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, ok := store.UserByID(user.ID); ok {
		t.Fatal("user remains after remote success")
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("mailbox remains after remote success")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("remote delete calls=%d, want 2", got)
	}
}

func TestUserDeletionBlocksLocalMailboxDeleteAfterDeletionStarts(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("owner-delete-local-race", "account-delete-local-race", ICloudRemoteMailbox{
		AnonymousID: "remote-delete-local-race",
		Origin:      mailboxRemoteOriginAppleAccount,
		Email:       "local-race@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	releaseDeletion, err := handler.beginUserDeletion(mailbox.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseDeletion()

	err = handler.deleteMailboxForRequestWithOptions(context.Background(), mailbox.ID, false, false)
	if !isCodedError(err, "user_delete_in_progress") {
		t.Fatalf("local delete error = %#v, want user_delete_in_progress", err)
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); !ok {
		t.Fatal("local mailbox was deleted while owner deletion was in progress")
	}
}

func TestClaimMailboxSkipsOwnerBeingDeleted(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{APIKey: "global-api-key"}, store, discardLogger()).(*Server)
	ownerID := "owner-claim-delete-race"
	mailbox, err := store.AddMailboxForOwnerWithRemote(ownerID, "account-claim-delete-race", ICloudRemoteMailbox{
		AnonymousID: "remote-claim-delete-race",
		Origin:      mailboxRemoteOriginICloudWeb,
		Email:       "claim-delete-race@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	releaseDeletion, err := handler.beginUserDeletion(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseDeletion()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/claim", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "global-api-key")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"code":"no_available_mailbox"`) {
		t.Fatalf("claim status=%d body=%s, want no_available_mailbox", rr.Code, rr.Body.String())
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared while owner deletion was in progress")
	}
	if current.Status != StatusAvailable {
		t.Fatalf("mailbox status=%q, want %q", current.Status, StatusAvailable)
	}
}

func TestSnapshotForOwnerDoesNotExposeMismatchedMailboxMessages(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-message-scope"
	otherOwnerID := "other-message-scope"
	ownerMailbox, err := store.AddMailboxForOwner(ownerID, "", "owner", "owner@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	otherMailbox, err := store.AddMailboxForOwner(otherOwnerID, "", "other", "other@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	legitimate, err := store.AddMessage(ownerMailbox.ID, "legitimate", "sender@example.com", "body", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	store.state.Messages = append(store.state.Messages, Message{
		ID:         "malformed-cross-owner-message",
		OwnerID:    ownerID,
		MailboxID:  otherMailbox.ID,
		Subject:    "must not leak",
		From:       "attacker@example.com",
		Body:       "cross-owner",
		ReceivedAt: time.Now(),
		CreatedAt:  time.Now(),
	})
	if err := store.saveLocked(); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	store.mu.Unlock()

	scoped := store.SnapshotForOwner(ownerID)
	if len(scoped.Messages) != 1 {
		t.Fatalf("scoped message count=%d, want 1: %#v", len(scoped.Messages), scoped.Messages)
	}
	if scoped.Messages[0].ID != legitimate.ID {
		t.Fatalf("scoped message id=%q, want legitimate message %q", scoped.Messages[0].ID, legitimate.ID)
	}
}

func TestAPIURLAndExportIncludeMailboxTokenInURL(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example", APIKey: "global-secret"}, store, discardLogger()).(*Server)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mailbox := Mailbox{
		Email:    "alias@icloud.com",
		APIToken: "secret-api-token",
	}

	wantURL := "https://mail.example/api/v1/mailboxes/alias@icloud.com/code?key=secret-api-token"
	got := handler.mailboxAPIURL(req, mailbox)
	if got != wantURL {
		t.Fatalf("mailboxAPIURL = %q, want %q", got, wantURL)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse mailboxAPIURL: %v", err)
	}
	if parsed.Query().Get("key") != mailbox.APIToken {
		t.Fatalf("mailboxAPIURL key = %q, want mailbox token", parsed.Query().Get("key"))
	}
	if parsed.Query().Get("wait_ms") != "" {
		t.Fatalf("backend api_url must not embed wait_ms: %q", got)
	}
	if strings.Contains(got, "global-secret") {
		t.Fatalf("mailboxAPIURL leaked global api_key: %q", got)
	}

	record := handler.mailboxExportRecord(req, mailbox, mailboxExportAPI)
	if len(record) != 2 || record[0] != mailbox.Email || record[1] != wantURL {
		t.Fatalf("API export record=%v, want email and complete URL", record)
	}
}

func TestPublicMailboxCodeURLAcceptsMailboxTokenWithoutSession(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "API", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{PublicBaseURL: "https://mail.example", APIKey: "global-secret"}, store, discardLogger()).(*Server)
	apiURL := handler.mailboxAPIURL(httptest.NewRequest(http.MethodGet, "/", nil), mailbox)
	parsed, err := url.Parse(apiURL)
	if err != nil {
		t.Fatalf("parse mailboxAPIURL: %v", err)
	}
	if parsed.Query().Get("key") != mailbox.APIToken {
		t.Fatalf("mailboxAPIURL key = %q, want %q in %q", parsed.Query().Get("key"), mailbox.APIToken, apiURL)
	}

	codeReq := httptest.NewRequest(http.MethodGet, parsed.EscapedPath()+"?"+parsed.RawQuery+"&cache=1", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, codeReq)
	if rr.Code == http.StatusUnauthorized || strings.Contains(rr.Body.String(), "invalid_api_key") {
		t.Fatalf("public api_url was rejected without session: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"code":"no_code"`) && !strings.Contains(rr.Body.String(), `"success":true`) {
		t.Fatalf("public api_url body = %s, want no_code or success", rr.Body.String())
	}
}

func TestUncodedErrorsAreNotReturnedByHTTPAPI(t *testing.T) {
	rr := httptest.NewRecorder()
	writeError(rr, http.StatusBadGateway, errors.New("provider raw response: secret-token"))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadGateway)
	}
	if strings.Contains(rr.Body.String(), "secret-token") {
		t.Fatalf("uncoded error leaked through API: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"code":"internal_error"`) ||
		!strings.Contains(rr.Body.String(), `"message":"操作失败"`) {
		t.Fatalf("unexpected sanitized error body: %s", rr.Body.String())
	}
}

func TestProviderErrorsDoNotExposeRawResponse(t *testing.T) {
	raw := `{"secret":"provider-token","message":"You have reached the limit of addresses"}`
	for name, err := range map[string]error{
		"icloud": iCloudAPIError(raw),
		"apple":  appleAccountAPIError(http.StatusBadGateway, []byte("<html>provider-token</html>"), "创建邮箱"),
	} {
		if err == nil {
			t.Fatalf("%s error is nil", name)
		}
		if strings.Contains(err.Error(), "provider-token") || strings.Contains(err.Error(), "原始返回") {
			t.Fatalf("%s error leaks raw response: %q", name, err.Error())
		}
	}
}
