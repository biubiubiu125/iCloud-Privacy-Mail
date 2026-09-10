package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileStoreMigratesLegacyAccountlessSessionToMatchingAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := State{
		NextID: 2,
		Accounts: []Account{{
			ID:       "account-legacy-session",
			OwnerID:  "owner-legacy-session",
			AppleID:  "legacy-session@example.com",
			ProxyURL: "http://new-proxy:8080",
		}},
		ICloudSessions: []ICloudSession{{
			OwnerID:  "owner-legacy-session",
			AppleID:  "legacy-session@example.com",
			ProxyURL: "http://old-proxy:8080",
			LoginStates: []LoginState{{
				Kind:     LoginStateAppleAccount,
				ProxyURL: "http://old-proxy:8080",
				Scnt:     "scnt",
			}},
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
		t.Fatalf("NewFileStore: %v", err)
	}
	session, ok := store.ICloudSessionForOwnerAccount("owner-legacy-session", "account-legacy-session")
	if !ok {
		t.Fatal("legacy accountless session was not bound to the matching account")
	}
	if session.AccountID != "account-legacy-session" {
		t.Fatalf("session account id = %q, want account-legacy-session", session.AccountID)
	}
	if session.ProxyURL != "http://new-proxy:8080" {
		t.Fatalf("session proxy = %q, want configured account proxy", session.ProxyURL)
	}
	for _, loginState := range session.LoginStates {
		if loginState.ProxyURL != "http://new-proxy:8080" {
			t.Fatalf("login state proxy = %q, want configured account proxy", loginState.ProxyURL)
		}
	}

	persistedData, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted State
	if err := json.Unmarshal(persistedData, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.ICloudSessions) != 1 ||
		persisted.ICloudSessions[0].AccountID != "account-legacy-session" ||
		persisted.ICloudSessions[0].ProxyURL != "http://new-proxy:8080" {
		t.Fatalf("persisted migrated session = %+v", persisted.ICloudSessions)
	}
}

func TestFileStoreDoesNotExposeAmbiguousLegacyAccountlessSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := State{
		NextID: 3,
		Accounts: []Account{
			{ID: "account-ambiguous-one", OwnerID: "owner-ambiguous", AppleID: "same@example.com"},
			{ID: "account-ambiguous-two", OwnerID: "owner-ambiguous", AppleID: "same@example.com"},
		},
		ICloudSessions: []ICloudSession{{
			OwnerID:  "owner-ambiguous",
			AppleID:  "same@example.com",
			ProxyURL: "http://stale-proxy:8080",
			LoginStates: []LoginState{{
				Kind:     LoginStateICloudWeb,
				ProxyURL: "http://stale-proxy:8080",
				Cookies:  []SessionCookie{{Name: "session", Value: "cookie"}},
			}},
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
		t.Fatalf("NewFileStore: %v", err)
	}
	if sessions := store.ICloudSessionsForOwner("owner-ambiguous"); len(sessions) != 0 {
		t.Fatalf("ambiguous legacy sessions = %+v, want no usable session", sessions)
	}
	for _, accountID := range []string{"account-ambiguous-one", "account-ambiguous-two"} {
		if _, ok := store.ICloudSessionForOwnerAccount("owner-ambiguous", accountID); ok {
			t.Fatalf("ambiguous legacy session was selected for account %s", accountID)
		}
	}
}

func TestUpdateAccountProxyRepairsAccountlessLegacySession(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwnerWithProxy(
		"owner-update-legacy-session",
		"Legacy session",
		"legacy-update@example.com",
		"",
		"http://old-proxy:8080",
	)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.state.ICloudSessions = append(store.state.ICloudSessions, ICloudSession{
		OwnerID:  "owner-update-legacy-session",
		AppleID:  account.AppleID,
		ProxyURL: "http://stale-proxy:8080",
		LoginStates: []LoginState{{
			Kind:     LoginStateICloudIMAP,
			ProxyURL: "http://stale-proxy:8080",
		}},
	})
	store.mu.Unlock()

	if _, err := store.UpdateAccountProxyForOwner("owner-update-legacy-session", account.ID, "http://new-proxy:8080"); err != nil {
		t.Fatal(err)
	}
	session, ok := store.ICloudSessionForOwnerAccount("owner-update-legacy-session", account.ID)
	if !ok {
		t.Fatal("repaired legacy session was not found")
	}
	if session.ProxyURL != "http://new-proxy:8080" {
		t.Fatalf("repaired session proxy = %q, want new proxy", session.ProxyURL)
	}
	for _, loginState := range session.LoginStates {
		if loginState.ProxyURL != "http://new-proxy:8080" {
			t.Fatalf("repaired login state proxy = %q, want new proxy", loginState.ProxyURL)
		}
	}
}

func TestSideEffectingMailboxCodeGETRequiresCSRFForBrowserSession(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "code-csrf-user", "password123")
	mailbox, err := store.AddMailboxForOwner(user.ID, "", "Code CSRF", "code-csrf@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "ChatGPT code", "noreply@example.com", "Use 246810 to continue.", time.Now()); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/mailboxes/"+mailbox.ID+"/code?keyword=ChatGPT", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), `"code":"csrf_invalid"`) {
		t.Fatalf("side-effecting browser code GET status=%d body=%s, want CSRF rejection", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/mailboxes/"+mailbox.ID+"/code?keyword=ChatGPT", nil)
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"code":"246810"`) {
		t.Fatalf("same-origin code GET status=%d body=%s, want successful code response", rr.Code, rr.Body.String())
	}
}

func TestJSONResponsesDisableCaching(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSON(rr, http.StatusOK, map[string]any{"success": true})
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestBulkDeleteRejectsIDsOutsideSelectionScope(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "bulk-scope-user", "password123")
	accountA, err := store.AddAccountForOwner(user.ID, "Account A", "scope-a@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	accountB, err := store.AddAccountForOwner(user.ID, "Account B", "scope-b@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailboxA, err := store.AddMailboxForOwner(user.ID, accountA.ID, "A", "scope-a@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner(user.ID, accountB.ID, "B", "scope-b@icloud.com"); err != nil {
		t.Fatal(err)
	}

	body := `{"ids":["` + mailboxA.ID + `"],"scope":{"account_key":"` + accountB.ID + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/bulk-delete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("bulk scoped delete status=%d body=%s, want 207", rr.Code, rr.Body.String())
	}
	if _, ok := store.FindMailboxByID(mailboxA.ID); !ok {
		t.Fatal("mailbox outside selection scope was deleted")
	}
	if !strings.Contains(rr.Body.String(), "不再符合当前筛选条件") {
		t.Fatalf("bulk scoped delete body=%s, want selection scope failure detail", rr.Body.String())
	}
}
