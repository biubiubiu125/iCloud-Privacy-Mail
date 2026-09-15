package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminHomeLoginAutoMatchDoesNotBindOtherUser(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "admin-home-login", "admin123")
	_, user := registerTestUser(t, handler, "user-home-login", "user123")
	account, err := store.AddAccountForOwner(user.ID, "User Apple", "other-owner@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/start", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	_, err = handler.resolveLoginTarget(req, account.AppleID, "")
	if !isCodedError(err, "apple_id_exists_other_owner") {
		t.Fatalf("home auto-match error = %#v, want apple_id_exists_other_owner", err)
	}
}

func TestAdminHomeLoginAutoMatchRejectsGlobalAppleID(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "admin-home-global-login", "admin123")
	if _, err := store.AddAccountForOwner("", "Global Apple", "global-login@example.com", ""); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/start", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	_, err := handler.resolveLoginTarget(req, "global-login@example.com", "")
	if !isCodedError(err, "apple_id_exists_other_owner") {
		t.Fatalf("home auto-match global error = %#v, want apple_id_exists_other_owner", err)
	}
}

func TestAdminHomeLoginAllowsNewAppleID(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, admin := registerTestUser(t, handler, "admin-home-new-login", "admin123")
	if _, err := store.AddAccountForOwner("", "Global Apple", "already-global@example.com", ""); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/start", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	target, err := handler.resolveLoginTarget(req, "brand-new@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if target.AccountID != "" || target.OwnerID != admin.ID {
		t.Fatalf("new Apple ID target = %+v, want new account under admin %q", target, admin.ID)
	}
}

func TestUserLoginAutoMatchRejectsOtherOwnerAppleID(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	registerTestUser(t, handler, "admin-user-login-other", "admin123")
	cookie, _ := registerTestUser(t, handler, "user-login-other", "user123")
	_, other := registerTestUser(t, handler, "other-login-owner", "other123")
	account, err := store.AddAccountForOwner(other.ID, "Other Apple", "taken-by-other@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/start", nil)
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	_, err = handler.resolveLoginTarget(req, account.AppleID, "")
	if !isCodedError(err, "apple_id_exists_other_owner") {
		t.Fatalf("user auto-match error = %#v, want apple_id_exists_other_owner", err)
	}
}

func TestAdminHomeLoginExplicitOtherAccountIsRejected(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "admin-home-explicit", "admin123")
	_, user := registerTestUser(t, handler, "user-home-explicit", "user123")
	account, err := store.AddAccountForOwner(user.ID, "User Apple", "explicit-other@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/start", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	_, err = handler.resolveLoginTarget(req, account.AppleID, account.ID)
	if !isCodedError(err, "account_not_found") {
		t.Fatalf("explicit out-of-scope login error = %#v, want account_not_found", err)
	}
}

func TestAdminHomeLoginProxyDoesNotUseOtherUserProxy(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "admin-home-proxy", "admin123")
	_, user := registerTestUser(t, handler, "user-home-proxy", "user123")
	if _, err := store.AddAccountForOwnerWithProxy(user.ID, "User Apple", "home-proxy@example.com", "", "127.0.0.1:7890"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/start", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	if got := handler.loginProxyForRequest(req, "HOME-PROXY@EXAMPLE.COM", ""); got != "" {
		t.Fatalf("home admin login proxy = %q, want empty", got)
	}
}

func TestAdminEmptyCreateDoesNotUseGlobalSessions(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "admin-empty-create", "admin123")
	if err := store.SaveICloudSessionForOwner("", ICloudSession{
		AppleID:      "global-create@example.com",
		DSID:         "dsid-global-create",
		IsICloudPlus: true,
		CanCreateHME: true,
		Cookies:      []SessionCookie{{Name: "g", Value: "1"}},
	}); err != nil {
		t.Fatal(err)
	}
	handler.createMailboxForOwner = func(context.Context, string, string, string, string) (Mailbox, ICloudRemoteMailbox, error) {
		t.Fatal("create should not run against global sessions from admin home")
		return Mailbox{}, ICloudRemoteMailbox{}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(`{"label":"HOME"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("empty admin home create status = %d body=%s, want 502", rr.Code, rr.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "icloud_session_missing" {
		t.Fatalf("empty admin home create code = %q, want icloud_session_missing", body.Code)
	}
}

func TestAdminEmptySchedulerDoesNotUseGlobalSessions(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "admin-empty-scheduler", "admin123")
	if err := store.SaveICloudSessionForOwner("", ICloudSession{
		AppleID:      "global-scheduler@example.com",
		DSID:         "dsid-global-scheduler",
		IsICloudPlus: true,
		CanCreateHME: true,
		Cookies:      []SessionCookie{{Name: "g", Value: "1"}},
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/start", strings.NewReader(`{"interval_seconds":3600}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty admin home scheduler status = %d body=%s, want 400", rr.Code, rr.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "icloud_session_missing" {
		t.Fatalf("empty admin home scheduler code = %q, want icloud_session_missing", body.Code)
	}
}

func TestAdminHomeIMAPSaveRejectsOtherUserAccount(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	handler.checkIMAPLogin = func(context.Context, string, string) error { return nil }
	adminCookie, _ := registerTestUser(t, handler, "admin-home-imap", "admin123")
	_, user := registerTestUser(t, handler, "user-home-imap", "user123")
	account, err := store.AddAccountForOwner(user.ID, "User Apple", "home-imap@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/save", strings.NewReader(
		`{"account_id":"`+account.ID+`","email":"home-imap@icloud.com","app_password":"app-secret"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("home imap save status = %d body=%s, want 403", rr.Code, rr.Body.String())
	}
}

func TestAdminHomeProxyUpdateRejectsOtherUserAccount(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin-home-proxy-update", "admin123")
	_, user := registerTestUser(t, handler, "user-home-proxy-update", "user123")
	account, err := store.AddAccountForOwner(user.ID, "User Apple", "home-proxy-update@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPatch, "/api/accounts/"+account.ID, strings.NewReader(`{"proxy_url":"127.0.0.1:7890"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("home proxy update status = %d body=%s, want 404", rr.Code, rr.Body.String())
	}
	updated, ok := store.FindAccountByID(account.ID)
	if !ok || updated.ProxyURL != "" {
		t.Fatalf("out-of-scope proxy update mutated account = %+v ok=%t", updated, ok)
	}
}

func TestAdminHomeManualMailboxCreateRejectsOtherUserAccount(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin-home-mailbox", "admin123")
	_, user := registerTestUser(t, handler, "user-home-mailbox", "user123")
	account, err := store.AddAccountForOwner(user.ID, "User Apple", "home-mailbox@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes", strings.NewReader(
		`{"account_id":"`+account.ID+`","label":"x","email":"home-mailbox@icloud.com"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("home mailbox create status = %d body=%s, want 404", rr.Code, rr.Body.String())
	}
}

func TestUnmarkMailboxAPIExportAcceptsRollbackTokenWithoutExportedAt(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	cookie, _ := registerTestUser(t, handler, "unmark-token", "user123")
	mailbox := createTestMailboxWithCookie(t, handler, cookie, "API", "unmark-token@icloud.com")

	exportReq := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis", strings.NewReader(
		`{"format":"txt","rollback_token":"export-token-home-1"}`,
	))
	exportReq.Header.Set("Content-Type", "application/json")
	exportReq.AddCookie(cookie)
	addClosureTestCSRF(exportReq, cookie)
	exportRR := httptest.NewRecorder()
	handler.ServeHTTP(exportRR, exportReq)
	if exportRR.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", exportRR.Code, exportRR.Body.String())
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || current.APIExportedAt.IsZero() {
		t.Fatalf("mailbox not marked exported: %+v ok=%t", current, ok)
	}

	unmarkReq := httptest.NewRequest(http.MethodPost, "/api/runtime/unmark-mailbox-apis", strings.NewReader(
		`{"rollback_token":"export-token-home-1"}`,
	))
	unmarkReq.Header.Set("Content-Type", "application/json")
	unmarkReq.AddCookie(cookie)
	addClosureTestCSRF(unmarkReq, cookie)
	unmarkRR := httptest.NewRecorder()
	handler.ServeHTTP(unmarkRR, unmarkReq)
	if unmarkRR.Code != http.StatusOK {
		t.Fatalf("unmark status = %d body=%s", unmarkRR.Code, unmarkRR.Body.String())
	}
	current, ok = store.FindMailboxByID(mailbox.ID)
	if !ok || !current.APIExportedAt.IsZero() {
		t.Fatalf("mailbox still marked exported after token rollback: %+v ok=%t", current, ok)
	}
}

func TestIndexTemplateHomeExportHintIsSelfScoped(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	if strings.Contains(html, "管理员导出全量数据") {
		t.Fatal("index template still claims admin homepage exports all data")
	}
	if !strings.Contains(html, "管理员首页默认只导出自己的数据") {
		t.Fatal("index template must say admin homepage export is self-scoped")
	}
}

func TestIndexTemplateRollsBackAPIExportWhenFetchFails(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "async function downloadExportFile", "async function exportMailboxAPIs")
	for _, marker := range []string{
		"rollback_token",
		"await rollbackMailboxAPIExport(null, requestOptions, path)",
		"newExportRollbackToken",
	} {
		if !strings.Contains(block, marker) && !strings.Contains(html, marker) {
			t.Errorf("index downloadExportFile missing fetch-fail rollback marker %q", marker)
		}
	}
}

func TestManageTemplateUpdateAccountProxySendsOwnerID(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatal(err)
	}
	block := scriptFunctionBlock(t, string(data), "async function updateAccountProxy", "function mailboxBindAccounts")
	for _, marker := range []string{
		"params.set('owner_id', '__global')",
		"params.set('owner_id', 'all')",
		"params.set('owner_id', selectedOwner)",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("manage proxy update missing owner_id marker %q in %s", marker, block)
		}
	}
}

func TestManageTemplateRollsBackAPIExportWhenFetchFails(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "async function downloadExportFile", "async function exportMailboxAPIs")
	for _, marker := range []string{
		"rollback_token",
		"await rollbackMailboxAPIExport(null, requestOptions, path)",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("manage downloadExportFile missing fetch-fail rollback marker %q in %s", marker, block)
		}
	}
}

func TestIndexTemplateCreateRequiresSelectableSessions(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	block := scriptFunctionBlock(t, string(data), "function selectedCreateAccounts", "function selectedCreateAccountIDsArray")
	if !strings.Contains(block, "sessions.length === 0") {
		t.Fatalf("selectedCreateAccounts must refuse empty login sessions, block=%s", block)
	}
}
