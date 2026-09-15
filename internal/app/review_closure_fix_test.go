package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRemoteDeleteMissingIdentityDoesNotLockLocalMailbox(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwner("owner-missing-remote", "account-missing-remote", "alias", "missing-remote@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	err = handler.deleteMailboxForRequestWithOptions(context.Background(), mailbox.ID, true, false)
	if !isCodedError(err, "icloud_mailbox_anonymous_id_missing") {
		t.Fatalf("error = %#v, want icloud_mailbox_anonymous_id_missing", err)
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("local mailbox was deleted after identity validation failure")
	}
	if current.RemoteDeleteStatus != "" {
		t.Fatalf("remote delete status = %q, want empty", current.RemoteDeleteStatus)
	}
	if err := handler.deleteMailboxForRequestWithOptions(context.Background(), mailbox.ID, false, false); err != nil {
		t.Fatalf("local delete after validation failure: %v", err)
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("local mailbox still present after local-only delete")
	}
}

func TestRemoteDeleteMissingSessionDoesNotLockLocalMailbox(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("owner-missing-session", "account-missing-session", ICloudRemoteMailbox{
		AnonymousID: "remote-no-session",
		Origin:      "APPLE_ACCOUNT",
		Email:       "missing-session@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	err = handler.deleteMailboxForRequestWithOptions(context.Background(), mailbox.ID, true, false)
	if !isCodedError(err, "apple_account_session_missing") {
		t.Fatalf("error = %#v, want apple_account_session_missing", err)
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("local mailbox was deleted after session validation failure")
	}
	if current.RemoteDeleteStatus != "" {
		t.Fatalf("remote delete status = %q, want empty", current.RemoteDeleteStatus)
	}
}

func TestAppleAccountRemoteDeleteTreatsNotFoundAsSuccess(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodDelete || (!strings.HasSuffix(r.URL.Path, "/stop") && !strings.HasSuffix(r.URL.Path, "/remove")) {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	_, err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailboxWithAppleAccount(context.Background(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt",
			APIKey:          "api-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(10 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "anonymous-gone")
	if err != nil {
		t.Fatalf("404 remove should be treated as already deleted, got %#v", err)
	}
	if got, want := strings.Join(paths, "\n"), "DELETE /account/manage/email/private/anonymous-gone/stop\nDELETE /account/manage/email/private/anonymous-gone/remove"; got != want {
		t.Fatalf("paths = %q, want %q", got, want)
	}
}

func TestICloudWebRemoteDeleteTreatsAlreadyGoneAsSuccess(t *testing.T) {
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/hme/deactivate":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":false,"error":{"errorCode":"HME_ALREADY_INACTIVE","errorMessage":"already deactivated"}}`))
		case "/v1/hme/delete":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"success":false,"error":{"errorMessage":"not found"}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailbox(context.Background(), ICloudSession{
		DSID:               "dsid",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		PremiumMailBaseURL: ts.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
	}, "old-remote-id")
	if err != nil {
		t.Fatalf("already-gone web delete should succeed, got %#v", err)
	}
	if got := strings.Join(paths, "\n"); got != "POST /v1/hme/deactivate\nPOST /v1/hme/delete" {
		t.Fatalf("paths = %q", got)
	}
}

func TestHTTPClientWithEmptyProxyIgnoresEnvironmentProxy(t *testing.T) {
	var hitTarget bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitTarget = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("http_proxy", "http://127.0.0.1:9")
	t.Setenv("https_proxy", "http://127.0.0.1:9")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:9")
	t.Setenv("all_proxy", "socks5://127.0.0.1:9")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	client, err := httpClientWithProxy(&http.Client{Timeout: 2 * time.Second}, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("empty proxy should dial directly, got %v", err)
	}
	defer resp.Body.Close()
	if !hitTarget || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("target hit=%t status=%d", hitTarget, resp.StatusCode)
	}
}

func TestAdminHomeMailboxListDoesNotIncludeOtherUsers(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, admin := registerTestUser(t, handler, "home-admin", "admin123")
	_, user := registerTestUser(t, handler, "home-user", "user123")
	adminMailbox, err := store.AddMailboxForOwner(admin.ID, "acc-admin", "ADMIN", "admin-home@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner(user.ID, "acc-user", "USER", "user-home@icloud.com"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/mailboxes", nil)
	req.AddCookie(adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin home list status = %d body=%s", rr.Code, rr.Body.String())
	}
	var response struct {
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Mailboxes) != 1 || response.Mailboxes[0].ID != adminMailbox.ID {
		t.Fatalf("admin home mailboxes = %+v, want only admin mailbox", response.Mailboxes)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/mailboxes?owner_id="+user.ID, nil)
	req.AddCookie(adminCookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Mailboxes) != 1 || response.Mailboxes[0].OwnerID != user.ID {
		t.Fatalf("admin filtered mailboxes = %+v, want user mailbox", response.Mailboxes)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/manage/data", nil)
	req.AddCookie(adminCookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("manage data status = %d body=%s", rr.Code, rr.Body.String())
	}
	var manage struct {
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &manage); err != nil {
		t.Fatal(err)
	}
	if len(manage.Mailboxes) != 2 {
		t.Fatalf("manage data mailboxes = %d, want 2", len(manage.Mailboxes))
	}
}

func TestUpdateAccountProxyOmittingFieldDoesNotClear(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "proxy-omit", "user123")
	account, err := store.AddAccountForOwnerWithProxy(user.ID, "Proxy", "proxy-omit@example.com", "", "http://127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPatch, "/api/accounts/"+account.ID, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("omit proxy status = %d body=%s", rr.Code, rr.Body.String())
	}
	updated, ok := store.FindAccountByID(account.ID)
	if !ok || updated.ProxyURL != "http://127.0.0.1:7890" {
		t.Fatalf("proxy after omit = %+v ok=%t", updated, ok)
	}
}

func TestIMAPConnectPreservesLeftoverBytesAfterHTTP200(t *testing.T) {
	raw := "HTTP/1.1 200 Connection Established\r\n\r\nIMAP leftover"
	reader := bufio.NewReader(bytes.NewReader([]byte(raw)))
	if _, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect}); err != nil {
		t.Fatal(err)
	}
	base := &net.TCPConn{}
	conn, err := wrapHTTPConnectConn(base, reader)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("IMAP leftover"))
	n, err := conn.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read leftover: %v", err)
	}
	if string(buf[:n]) != "IMAP leftover" {
		t.Fatalf("leftover = %q, want IMAP leftover", buf[:n])
	}
}

func TestIMAPDialErrorPreservesUnsupportedProxyScheme(t *testing.T) {
	err := imapDialError(errCode("unsupported_proxy_scheme", "当前代理仅支持 HTTP/HTTPS 代理", false))
	if !isCodedError(err, "unsupported_proxy_scheme") {
		t.Fatalf("error = %#v, want unsupported_proxy_scheme", err)
	}
}

func TestAppleAccountEmptyListMarksLocalMailboxesMissing(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account/manage/email/private" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hmeEmails":[]}`))
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	account, err := store.AddAccountForOwner("owner-empty-apple", "Empty", "empty-apple@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote("owner-empty-apple", account.ID, ICloudRemoteMailbox{
		AnonymousID: "keep-local",
		Origin:      mailboxRemoteOriginAppleAccount,
		Email:       "keep-local@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	session := ICloudSession{
		OwnerID:   "owner-empty-apple",
		AccountID: account.ID,
		AppleID:   account.AppleID,
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			APIKey:          "api-key",
			Scnt:            "scnt",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(10 * time.Minute),
			LastCheckOK:     true,
		}},
	}
	if err := store.SaveICloudSessionForOwner("owner-empty-apple", session); err != nil {
		t.Fatal(err)
	}

	result, _, err := handler.syncICloudMailboxesForSession(
		context.Background(),
		httptest.NewRequest(http.MethodGet, "/", nil),
		"owner-empty-apple",
		session,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.RemoteEmpty || result.RemoteMissing != 1 {
		t.Fatalf("empty Apple Account list result = %+v, want remote missing marked", result)
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing after empty Apple Account list")
	}
	if current.ICloudActive || current.Status != StatusDisabled || current.RemoteMissingAt.IsZero() {
		t.Fatalf("empty Apple Account list did not mark mailbox missing: %+v", current)
	}
}

func TestBulkDeletePartialSuccessSetsPartialFlag(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "bulk-partial", "user123")
	okMailbox, err := store.AddMailboxForOwner(user.ID, "acc-partial", "OK", "partial-ok@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/bulk-delete", strings.NewReader(
		`{"ids":["`+okMailbox.ID+`","missing-id"],"delete_remote":false}`,
	))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d body=%s, want 207", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool `json:"success"`
		Partial bool `json:"partial"`
		Deleted int  `json:"deleted"`
		Failed  int  `json:"failed"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Success || !body.Partial || body.Deleted != 1 || body.Failed != 1 {
		t.Fatalf("bulk delete body = %+v", body)
	}
}

func TestUnmarkMailboxAPIExportClearsMatchingTimestamp(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	cookie, _ := registerTestUser(t, handler, "unmark-export", "user123")
	mailbox := createTestMailboxWithCookie(t, handler, cookie, "API", "unmark-export@icloud.com")

	exportReq := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis", strings.NewReader(`{"format":"txt"}`))
	exportReq.Header.Set("Content-Type", "application/json")
	exportReq.AddCookie(cookie)
	addClosureTestCSRF(exportReq, cookie)
	exportRR := httptest.NewRecorder()
	handler.ServeHTTP(exportRR, exportReq)
	if exportRR.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", exportRR.Code, exportRR.Body.String())
	}
	exportedAt := exportRR.Header().Get("X-IPM-API-Exported-At")
	if exportedAt == "" {
		t.Fatal("export response missing X-IPM-API-Exported-At")
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || current.APIExportedAt.IsZero() {
		t.Fatalf("mailbox not marked exported: %+v ok=%t", current, ok)
	}

	unmarkReq := httptest.NewRequest(http.MethodPost, "/api/runtime/unmark-mailbox-apis", strings.NewReader(`{"exported_at":"`+exportedAt+`"}`))
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
		t.Fatalf("mailbox still marked exported: %+v ok=%t", current, ok)
	}
}

func TestDockerWorkflowAndDockerfileCloseReleaseLoop(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(sourceFile), "..", "..")
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	dockerText := string(dockerfile)
	for _, marker := range []string{
		"COPY go.mod go.sum ./",
		"-X icloud-privacy-mail/internal/app.AppVersion",
		"chown -R ipm:ipm /app",
	} {
		if !strings.Contains(dockerText, marker) {
			t.Errorf("Dockerfile missing %q", marker)
		}
	}
	copyBinaryAt := strings.Index(dockerText, "COPY --from=builder /out/icloud-privacy-mail /app/icloud-privacy-mail")
	chownAt := strings.LastIndex(dockerText, "chown -R ipm:ipm /app")
	if copyBinaryAt < 0 || chownAt < 0 || copyBinaryAt > chownAt {
		t.Fatalf("binary must be copied before final chown:\n%s", dockerText)
	}

	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "docker-image.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	for _, marker := range []string{
		"type=sha",
		"type=raw,value=latest,enable={{is_default_branch}}",
		"platforms: linux/amd64,linux/arm64",
		"APP_VERSION=${{ env.APP_VERSION }}",
		"type=cacheonly",
		"push: ${{ env.PUSH_IMAGE == 'true' }}",
		"if: env.PUSH_IMAGE == 'true'",
		`AppVersion = "`,
	} {
		if !strings.Contains(text, marker) {
			t.Errorf("docker workflow missing %q", marker)
		}
	}
	if strings.Contains(text, "APP_VERSION=dev") {
		t.Fatal("docker workflow must not force APP_VERSION=dev on branch builds")
	}
}

func TestPanelWriteTimeoutAllowsLongBulkRemoteDelete(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(sourceFile), "..", "..", "cmd", "panel", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "WriteTimeout:      15 * time.Minute") {
		t.Fatalf("panel WriteTimeout must allow long bulk remote deletes:\n%s", data)
	}
}

func TestIndexTemplateBulkRemoteDeleteOnlyConfirmsUnknown(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	block := scriptFunctionBlock(t, string(data), "async function deleteSelectedMailboxes", "async function cleanAllRemoteCodes")
	if !strings.Contains(block, "selectedMailboxHasRemoteDeleteStatus('unknown')") {
		t.Fatalf("bulk remote delete must confirm unknown rows across pages: %s", block)
	}
	if !strings.Contains(block, "confirm_failed: !deleteRemote && hasFailed") {
		t.Fatalf("bulk local delete must confirm failed rows: %s", block)
	}
	if !strings.Contains(block, "confirm_unknown: hasUnknown") {
		t.Fatalf("bulk delete must send confirm_unknown for unknown rows: %s", block)
	}
	if strings.Contains(block, "confirm_unknown: !!deleteRemote,") {
		t.Fatal("bulk remote delete must not blindly set confirm_unknown")
	}
}

func TestIndexTemplateRollsBackAPIExportWhenBlobReadFails(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	block := scriptFunctionBlock(t, string(data), "async function downloadExportFile", "async function exportMailboxAPIs")
	for _, marker := range []string{
		"X-IPM-API-Exported-At",
		"/api/runtime/unmark-mailbox-apis",
		"blob = await res.blob()",
		"owner_id",
		"rollback_token",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("downloadExportFile missing rollback marker %q in %s", marker, block)
		}
	}
}

func TestREADMEDocumentsDockerImageTags(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(sourceFile), "..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, marker := range []string{
		"ghcr.io/biubiubiu125/icloud-privacy-mail:latest",
		"sha-",
		"linux/amd64",
		"linux/arm64",
		"data_path",
		"docker login ghcr.io",
		"IPM_CONFIG_FORCE",
	} {
		if !strings.Contains(text, marker) {
			t.Errorf("README docker section missing %q", marker)
		}
	}
}

func TestAppleAccountRemoteDeleteDoesNotTreatHTML404AsSuccess(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/stop"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/remove"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>not found</body></html>`))
		default:
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	_, err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailboxWithAppleAccount(context.Background(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt",
			APIKey:          "api-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(10 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "anonymous-html")
	if err == nil {
		t.Fatal("HTML 404 remove must not be treated as already deleted")
	}
}

func TestICloudWebRemoteDeleteDoesNotTreatHTML404AsSuccess(t *testing.T) {
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>login</body></html>`))
	}))
	defer ts.Close()

	err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailbox(context.Background(), ICloudSession{
		DSID:               "dsid",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		PremiumMailBaseURL: ts.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
	}, "old-remote-id")
	if err == nil {
		t.Fatal("HTML 404 web delete must not be treated as already gone")
	}
	if !isCodedError(err, "icloud_html_response") {
		t.Fatalf("error = %#v, want icloud_html_response", err)
	}
	if got := strings.Join(paths, "\n"); got != "POST /v1/hme/deactivate" {
		t.Fatalf("paths = %q, want only deactivate", got)
	}
}

func TestICloudWebRemoteDeleteTreatsDeactivateHTTP404ThenDelete404AsGone(t *testing.T) {
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"success":false,"error":{"errorMessage":"not found"}}`))
	}))
	defer ts.Close()

	err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailbox(context.Background(), ICloudSession{
		DSID:               "dsid",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		PremiumMailBaseURL: ts.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
	}, "gone-remote-id")
	if err != nil {
		t.Fatalf("JSON 404 deactivate+delete should succeed as gone, got %#v", err)
	}
	if got := strings.Join(paths, "\n"); got != "POST /v1/hme/deactivate\nPOST /v1/hme/delete" {
		t.Fatalf("paths = %q", got)
	}
}

func TestUnmarkMailboxAPIExportHonorsOwnerQuery(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "unmark-owner-admin", "admin123")
	userCookie, user := registerTestUser(t, handler, "unmark-owner-user", "user123")
	mailbox := createTestMailboxWithCookie(t, handler, userCookie, "API", "unmark-owner@icloud.com")

	exportReq := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis?owner_id="+user.ID, strings.NewReader(`{"format":"txt"}`))
	exportReq.Header.Set("Content-Type", "application/json")
	exportReq.AddCookie(adminCookie)
	addClosureTestCSRF(exportReq, adminCookie)
	exportRR := httptest.NewRecorder()
	handler.ServeHTTP(exportRR, exportReq)
	if exportRR.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", exportRR.Code, exportRR.Body.String())
	}
	exportedAt := exportRR.Header().Get("X-IPM-API-Exported-At")
	if exportedAt == "" {
		t.Fatal("export response missing X-IPM-API-Exported-At")
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || current.APIExportedAt.IsZero() {
		t.Fatalf("mailbox not marked exported: %+v ok=%t", current, ok)
	}

	unmarkReq := httptest.NewRequest(http.MethodPost, "/api/runtime/unmark-mailbox-apis?owner_id="+user.ID, strings.NewReader(`{"exported_at":"`+exportedAt+`"}`))
	unmarkReq.Header.Set("Content-Type", "application/json")
	unmarkReq.AddCookie(adminCookie)
	addClosureTestCSRF(unmarkReq, adminCookie)
	unmarkRR := httptest.NewRecorder()
	handler.ServeHTTP(unmarkRR, unmarkReq)
	if unmarkRR.Code != http.StatusOK {
		t.Fatalf("unmark status = %d body=%s", unmarkRR.Code, unmarkRR.Body.String())
	}
	current, ok = store.FindMailboxByID(mailbox.ID)
	if !ok || !current.APIExportedAt.IsZero() {
		t.Fatalf("mailbox still marked exported: %+v ok=%t", current, ok)
	}
}

func TestAdminBulkDeleteEmptyOwnerScopeDoesNotIncludeOtherUsers(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, admin := registerTestUser(t, handler, "scope-admin", "admin123")
	_, user := registerTestUser(t, handler, "scope-user", "user123")
	adminMailbox, err := store.AddMailboxForOwner(admin.ID, "acc-admin-scope", "ADMIN", "scope-admin@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	userMailbox, err := store.AddMailboxForOwner(user.ID, "acc-user-scope", "USER", "scope-user@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"ids":["` + adminMailbox.ID + `","` + userMailbox.ID + `"],"delete_remote":false,"scope":{}}`
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/bulk-delete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d body=%s, want 207", rr.Code, rr.Body.String())
	}
	if _, ok := store.FindMailboxByID(adminMailbox.ID); ok {
		t.Fatal("admin mailbox should be deleted under current-owner scope")
	}
	if _, ok := store.FindMailboxByID(userMailbox.ID); !ok {
		t.Fatal("other user's mailbox was deleted under empty owner scope")
	}
}

func TestLocalMailboxDeleteCanConfirmFailedRemoteDelete(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-confirm-failed", ICloudRemoteMailbox{
		AnonymousID: "confirm-failed-remote",
		Origin:      "APPLE_ACCOUNT",
		Email:       "confirm-failed@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginMailboxRemoteDelete(mailbox.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMailboxRemoteDeleteFailed(mailbox.ID, "远端删除失败", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := handler.deleteMailboxForRequestWithAccess(context.Background(), mailbox.ID, nil, false, false, true); err != nil {
		t.Fatalf("confirmed failed local delete: %v", err)
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("mailbox remains after confirmed failed local delete")
	}
}

func TestLocalMailboxDeleteCanConfirmUnknownRemoteDelete(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-confirm-unknown-local", ICloudRemoteMailbox{
		AnonymousID: "confirm-unknown-local-remote",
		Origin:      "APPLE_ACCOUNT",
		Email:       "confirm-unknown-local@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginMailboxRemoteDelete(mailbox.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMailboxRemoteDeleteUnknown(mailbox.ID, "远端结果未知", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := handler.deleteMailboxForRequestWithAccess(context.Background(), mailbox.ID, nil, false, true, false); err != nil {
		t.Fatalf("confirmed unknown local delete: %v", err)
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("mailbox remains after confirmed unknown local delete")
	}
}

func TestConfirmedUnknownRemoteDeleteKeepsUnknownWhenValidationFails(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("owner-unknown-keep", "account-unknown-keep", ICloudRemoteMailbox{
		AnonymousID: "unknown-keep-remote",
		Origin:      "APPLE_ACCOUNT",
		Email:       "unknown-keep@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginMailboxRemoteDelete(mailbox.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMailboxRemoteDeleteUnknown(mailbox.ID, "远端结果未知", time.Now()); err != nil {
		t.Fatal(err)
	}
	err = handler.deleteMailboxForRequestWithAccess(context.Background(), mailbox.ID, nil, true, true, false)
	if !isCodedError(err, "apple_account_session_missing") {
		t.Fatalf("error = %#v, want apple_account_session_missing", err)
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox was deleted after failed unknown remote retry")
	}
	if current.RemoteDeleteStatus != "unknown" {
		t.Fatalf("remote delete status = %q, want unknown", current.RemoteDeleteStatus)
	}
}

func TestAdminHomeStatusDoesNotIncludeOtherUsers(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, admin := registerTestUser(t, handler, "status-admin", "admin123")
	_, user := registerTestUser(t, handler, "status-user", "user123")
	if _, err := store.AddMailboxForOwner(admin.ID, "acc-admin-status", "ADMIN", "admin-status@icloud.com"); err != nil {
		t.Fatal(err)
	}
	userAccount, err := store.AddAccountForOwner(user.ID, "User", "user-status@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner(user.ID, userAccount.ID, "USER", "user-status@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:   user.ID,
		AccountID: userAccount.ID,
		AppleID:   userAccount.AppleID,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Accounts       int                   `json:"accounts"`
		Mailboxes      int                   `json:"mailboxes"`
		ICloudSessions []publicICloudSession `json:"icloud_sessions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Mailboxes != 1 {
		t.Fatalf("admin home mailbox count = %d, want 1", body.Mailboxes)
	}
	for _, session := range body.ICloudSessions {
		if session.AccountID == userAccount.ID || session.AppleID == userAccount.AppleID {
			t.Fatalf("admin home status leaked other user session: %+v", session)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/api/accounts", nil)
	req.AddCookie(adminCookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	var accounts struct {
		Accounts []publicAccount `json:"accounts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &accounts); err != nil {
		t.Fatal(err)
	}
	for _, account := range accounts.Accounts {
		if account.ID == userAccount.ID {
			t.Fatal("admin home accounts leaked other user account")
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/api/accounts?owner_id="+user.ID, nil)
	req.AddCookie(adminCookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if err := json.Unmarshal(rr.Body.Bytes(), &accounts); err != nil {
		t.Fatal(err)
	}
	if len(accounts.Accounts) != 1 || accounts.Accounts[0].OwnerID != user.ID {
		t.Fatalf("admin accounts?owner_id=user = %+v, want that user", accounts.Accounts)
	}
}

func TestAdminHomeSyncDoesNotTouchOtherUsers(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "sync-home-admin", "admin123")
	_, user := registerTestUser(t, handler, "sync-home-user", "user123")
	account, err := store.AddAccountForOwner(user.ID, "User Apple", "sync-home-user@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:   user.ID,
		AccountID: account.ID,
		AppleID:   account.AppleID,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/sync", strings.NewReader(`{"account_id":"`+account.ID+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("admin home sync of other account status = %d body=%s, want 404", rr.Code, rr.Body.String())
	}
}

func TestUnmarkMailboxAPIExportIgnoresUnexportedFilter(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	cookie, _ := registerTestUser(t, handler, "unmark-unexported", "user123")
	mailbox := createTestMailboxWithCookie(t, handler, cookie, "API", "unmark-unexported@icloud.com")

	exportReq := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis?api_exported=0", strings.NewReader(`{"format":"txt"}`))
	exportReq.Header.Set("Content-Type", "application/json")
	exportReq.AddCookie(cookie)
	addClosureTestCSRF(exportReq, cookie)
	exportRR := httptest.NewRecorder()
	handler.ServeHTTP(exportRR, exportReq)
	if exportRR.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", exportRR.Code, exportRR.Body.String())
	}
	exportedAt := exportRR.Header().Get("X-IPM-API-Exported-At")
	if exportedAt == "" {
		t.Fatal("export response missing X-IPM-API-Exported-At")
	}

	unmarkReq := httptest.NewRequest(http.MethodPost, "/api/runtime/unmark-mailbox-apis?api_exported=0", strings.NewReader(`{"exported_at":"`+exportedAt+`"}`))
	unmarkReq.Header.Set("Content-Type", "application/json")
	unmarkReq.AddCookie(cookie)
	addClosureTestCSRF(unmarkReq, cookie)
	unmarkRR := httptest.NewRecorder()
	handler.ServeHTTP(unmarkRR, unmarkReq)
	if unmarkRR.Code != http.StatusOK {
		t.Fatalf("unmark status = %d body=%s", unmarkRR.Code, unmarkRR.Body.String())
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || !current.APIExportedAt.IsZero() {
		t.Fatalf("mailbox still marked exported after unexported-filter rollback: %+v ok=%t", current, ok)
	}
}

func TestBulkDeleteTimeBudgetFitsPanelWriteTimeout(t *testing.T) {
	if bulkDeleteTimeBudget != 12*time.Minute {
		t.Fatalf("bulkDeleteTimeBudget = %s, want 12m", bulkDeleteTimeBudget)
	}
	if bulkDeleteTimeBudget >= 15*time.Minute {
		t.Fatal("bulk delete budget must finish before panel WriteTimeout")
	}
}

func TestSchemeDocumentsDefaultBranchPushPolicy(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(sourceFile), "..", "..", "iCloud-Privacy-Mail-统一归属与邮箱池增强总方案.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, marker := range []string{
		"仅默认分支",
		"其他分支只构建、不推送",
		"IPM_CONFIG_FORCE=1",
	} {
		if !strings.Contains(text, marker) {
			t.Errorf("scheme missing %q", marker)
		}
	}
}

func TestAppleAccountRemoteDeleteStopNotFoundContinuesToRemove(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/stop"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/remove"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	_, err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailboxWithAppleAccount(context.Background(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt",
			APIKey:          "api-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(10 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "stop-gone")
	if err != nil {
		t.Fatalf("JSON 404 stop should continue to remove, got %#v", err)
	}
	if got, want := strings.Join(paths, "\n"), "DELETE /account/manage/email/private/stop-gone/stop\nDELETE /account/manage/email/private/stop-gone/remove"; got != want {
		t.Fatalf("paths = %q, want %q", got, want)
	}
}

func TestAppleAccountRemoteDeleteStopAlreadyInactiveContinuesToRemove(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/stop"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"errorCode":"already_inactive"}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/remove"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	_, err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailboxWithAppleAccount(context.Background(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt",
			APIKey:          "api-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(10 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "already-inactive")
	if err != nil {
		t.Fatalf("already inactive stop should continue to remove, got %#v", err)
	}
	if got, want := strings.Join(paths, "\n"), "DELETE /account/manage/email/private/already-inactive/stop\nDELETE /account/manage/email/private/already-inactive/remove"; got != want {
		t.Fatalf("paths = %q, want %q", got, want)
	}
}

func TestAppleAccountRemoteDeleteStopFailureDoesNotCallRemove(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodDelete || !strings.HasSuffix(r.URL.Path, "/stop") {
			t.Fatalf("unexpected request = %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errorCode":"temporary"}`))
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	_, err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailboxWithAppleAccount(context.Background(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt",
			APIKey:          "api-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(10 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "stop-fail")
	if err == nil {
		t.Fatal("stop failure should abort delete")
	}
	if !isCodedError(err, "apple_account_api_failed") {
		t.Fatalf("error = %#v, want apple_account_api_failed", err)
	}
	if got := strings.Join(paths, "\n"); got != "DELETE /account/manage/email/private/stop-fail/stop" {
		t.Fatalf("paths = %q, want only stop", got)
	}
}

func TestAppleAccountRemoteDeleteAuthRetrySkipsSecondStop(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	removeHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("scnt", "retry-token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("scnt", "retry-manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"retry-api-key"}`))
		case "DELETE /account/manage/email/private/auth-retry/stop":
			if strings.Count(strings.Join(paths, "\n"), "/stop") > 1 {
				t.Fatal("auth retry must not call /stop again after it already succeeded")
			}
			_, _ = w.Write([]byte(`{}`))
		case "DELETE /account/manage/email/private/auth-retry/remove":
			removeHits++
			if removeHits == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"service_errors":[{"message":"authentication_failed"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request = %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	_, err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailboxWithAppleAccount(context.Background(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt",
			APIKey:          "api-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(10 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "auth-retry")
	if err != nil {
		t.Fatalf("auth retry after successful stop should finish remove, got %#v", err)
	}
	want := strings.Join([]string{
		"DELETE /account/manage/email/private/auth-retry/stop",
		"DELETE /account/manage/email/private/auth-retry/remove",
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"DELETE /account/manage/email/private/auth-retry/remove",
	}, "\n")
	if got := strings.Join(paths, "\n"); got != want {
		t.Fatalf("paths = %q, want %q", got, want)
	}
}

func TestAppleAccountRemoteDeleteAuthRetryKeepsDeactivatedWhenSecondRemoveFails(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	removeHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("scnt", "retry-token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("scnt", "retry-manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"retry-api-key"}`))
		case "DELETE /account/manage/email/private/auth-retry-fail/stop":
			if strings.Count(strings.Join(paths, "\n"), "/stop") > 1 {
				t.Fatal("auth retry must not call /stop again after it already succeeded")
			}
			_, _ = w.Write([]byte(`{}`))
		case "DELETE /account/manage/email/private/auth-retry-fail/remove":
			removeHits++
			if removeHits == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"service_errors":[{"message":"authentication_failed"}]}`))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"errorCode":"temporary"}`))
		default:
			t.Fatalf("unexpected request = %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-auth-retry-fail"
	account, err := store.AddAccountForOwner(ownerID, "Auth retry fail", "auth-retry-fail@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
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
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote(ownerID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "auth-retry-fail",
		Origin:      mailboxRemoteOriginAppleAccount,
		Email:       "auth-retry-fail@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	err = handler.deleteRemoteMailboxForRequest(context.Background(), mailbox)
	if err == nil {
		t.Fatal("second remove failure should keep the local mailbox")
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("local mailbox was removed after auth-retry remove failure")
	}
	if updated.ICloudActive {
		t.Fatal("icloud_active should stay false after first stop succeeded")
	}
	if updated.Status != StatusDisabled {
		t.Fatalf("status = %q, want disabled after stop succeeded", updated.Status)
	}
	if updated.RemoteDeleteStatus != "failed" {
		t.Fatalf("remote delete status = %q, want failed", updated.RemoteDeleteStatus)
	}
	if strings.Count(strings.Join(paths, "\n"), "/stop") != 1 {
		t.Fatalf("paths = %q, want a single /stop", strings.Join(paths, "\n"))
	}
}

func TestICloudWebRemoteDeleteMapsStillActiveError(t *testing.T) {
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/hme/deactivate":
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		case "/v1/hme/delete":
			_, _ = w.Write([]byte(`{"success":false,"error":{"errorCode":"-41000","errorMessage":"cannot delete an active address"}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailbox(context.Background(), ICloudSession{
		DSID:               "dsid",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		PremiumMailBaseURL: ts.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
	}, "still-active-id")
	if !isCodedError(err, "icloud_hme_still_active") {
		t.Fatalf("error = %#v, want icloud_hme_still_active", err)
	}
	if got := strings.Join(paths, "\n"); got != "POST /v1/hme/deactivate\nPOST /v1/hme/delete" {
		t.Fatalf("paths = %q", got)
	}
}

func TestICloudWebRemoteDeleteKeepsLocalActiveWhenStillActive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/hme/deactivate":
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		case "/v1/hme/delete":
			_, _ = w.Write([]byte(`{"success":false,"error":{"errorCode":"-41000","errorMessage":"cannot delete an active address"}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-web-still-active"
	account, err := store.AddAccountForOwner(ownerID, "Web still active", "web-still-active@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "web-still-active-dsid",
		ClientID:           "web-still-active-client",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		PremiumMailBaseURL: ts.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "session", Value: "cookie"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote(ownerID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "still-active-remote",
		Origin:      mailboxRemoteOriginICloudWeb,
		Email:       "still-active@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	err = handler.deleteRemoteMailboxForRequest(context.Background(), mailbox)
	if !isCodedError(err, "icloud_hme_still_active") {
		t.Fatalf("error = %#v, want icloud_hme_still_active", err)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("local mailbox was removed after still-active remote delete")
	}
	if !updated.ICloudActive {
		t.Fatal("icloud_active must stay true when provider says the address is still active")
	}
	if updated.Status != StatusAvailable {
		t.Fatalf("status = %q, want available when still-active delete failed", updated.Status)
	}
	if updated.RemoteDeleteStatus != "failed" {
		t.Fatalf("remote delete status = %q, want failed", updated.RemoteDeleteStatus)
	}
	if !strings.Contains(updated.RemoteDeleteError, "仍在使用中") {
		t.Fatalf("remote delete error = %q, want still-active detail", updated.RemoteDeleteError)
	}
}

func TestAppleAccountMailboxListAcceptsPrivateEmailList(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account/manage/email/private" {
			t.Fatalf("request path = %q, want Apple Account mailbox list", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"hideMyEmailBootData": {
				"privateEmailList": [
					{"id":"official-active","emailAddress":"official-active@icloud.com"}
				],
				"inactivePrivateEmailList": [
					{"id":"official-inactive","emailAddress":"official-inactive@icloud.com"}
				]
			}
		}`))
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	remotes, _, err := (&ICloudClient{client: server.Client()}).ListPrivacyMailboxesForOriginWithSession(
		context.Background(),
		ICloudSession{LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt",
			APIKey:          "api-key",
			LastCheckedAt:   time.Now(),
			ManageExpiresAt: time.Now().Add(time.Hour),
			LastCheckOK:     true,
		}}},
		mailboxRemoteOriginAppleAccount,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(remotes) != 2 {
		t.Fatalf("remotes = %+v, want two official list items", remotes)
	}
	byID := map[string]ICloudRemoteMailbox{}
	for _, remote := range remotes {
		byID[remote.AnonymousID] = remote
	}
	active, ok := byID["official-active"]
	if !ok || !active.IsActive || active.Email != "official-active@icloud.com" {
		t.Fatalf("active remote = %+v", active)
	}
	inactive, ok := byID["official-inactive"]
	if !ok || inactive.IsActive || inactive.Email != "official-inactive@icloud.com" {
		t.Fatalf("inactive remote = %+v", inactive)
	}
}

func TestAppleAccountEmptyPrivateEmailListIsComplete(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account/manage/email/private" {
			t.Fatalf("request path = %q, want Apple Account mailbox list", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"privateEmailList":[],"inactivePrivateEmailList":[]}`))
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	remotes, _, err := (&ICloudClient{client: server.Client()}).ListPrivacyMailboxesForOriginWithSession(
		context.Background(),
		ICloudSession{LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt",
			APIKey:          "api-key",
			LastCheckedAt:   time.Now(),
			ManageExpiresAt: time.Now().Add(time.Hour),
			LastCheckOK:     true,
		}}},
		mailboxRemoteOriginAppleAccount,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(remotes) != 0 {
		t.Fatalf("remotes = %+v, want empty complete list", remotes)
	}
}

func TestRemoteSyncDoesNotReactivateFailedDisabledMailbox(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-failed-disabled", ICloudRemoteMailbox{
		AnonymousID: "failed-disabled-remote",
		Origin:      mailboxRemoteOriginAppleAccount,
		Email:       "failed-disabled@icloud.com",
		IsActive:    false,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMailboxRemoteDeleteFailed(mailbox.ID, "stop ok remove failed", time.Now()); err != nil {
		t.Fatal(err)
	}

	updated, created, err := store.UpsertMailboxFromRemote("", "account-failed-disabled", ICloudRemoteMailbox{
		AnonymousID: "failed-disabled-remote",
		Origin:      mailboxRemoteOriginAppleAccount,
		Email:       "failed-disabled@icloud.com",
		Label:       "still-listed",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("failed-disabled mailbox was recreated")
	}
	if updated.RemoteDeleteStatus != "failed" || updated.ICloudActive || updated.Status != StatusDisabled {
		t.Fatalf("failed disabled mailbox was reactivated by sync: %+v", updated)
	}
	if updated.Label != "still-listed" {
		t.Fatalf("label = %q, want still-listed", updated.Label)
	}
}

func testAppleAccountListSession() ICloudSession {
	return ICloudSession{LoginStates: []LoginState{{
		Kind:            LoginStateAppleAccount,
		Scnt:            "scnt",
		APIKey:          "api-key",
		LastCheckedAt:   time.Now(),
		ManageExpiresAt: time.Now().Add(time.Hour),
		LastCheckOK:     true,
	}}}
}

func TestAppleAccountMailboxListAcceptsPreconditionFailed(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/account/manage/email/private" {
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPreconditionFailed)
		_, _ = w.Write([]byte(`{"privateEmailList":[{"id":"precondition-id","emailAddress":"precondition@icloud.com"}],"inactivePrivateEmailList":[]}`))
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	remotes, _, err := (&ICloudClient{client: server.Client()}).ListPrivacyMailboxesForOriginWithSession(
		context.Background(),
		testAppleAccountListSession(),
		mailboxRemoteOriginAppleAccount,
	)
	if err != nil {
		t.Fatalf("412 list should use official body, got %v", err)
	}
	if len(remotes) != 1 || remotes[0].AnonymousID != "precondition-id" || remotes[0].Email != "precondition@icloud.com" {
		t.Fatalf("remotes = %+v, want official 412 list item", remotes)
	}
}

func TestAppleAccountCreateAcceptsPreconditionFailedOnAdd(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = w.Write([]byte(`{"emailAddress":"candidate@icloud.com"}`))
		case "PUT /account/manage/email/private/add/complete":
			_, _ = w.Write([]byte(`{"emailAddress":"created@icloud.com","id":"created-id","active":true}`))
		case "GET /account/manage/email/private/created-id.em":
			_, _ = w.Write([]byte(`{"emailAddress":"created@icloud.com","id":"created-id","active":true}`))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
		}
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	remote, _, err := (&ICloudClient{client: server.Client()}).createPrivacyMailboxWithAppleAccountState(
		context.Background(),
		ICloudSession{},
		LoginState{Kind: LoginStateAppleAccount, APIKey: "api-key", Scnt: "scnt"},
		"",
		"label",
		"note",
	)
	if err != nil {
		t.Fatalf("412 add should continue create, got %v", err)
	}
	if remote.AnonymousID != "created-id" || remote.Email != "created@icloud.com" {
		t.Fatalf("remote = %+v, want created-id", remote)
	}
}

func TestAppleAccountCreateAcceptsPreconditionFailedOnComplete(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			_, _ = w.Write([]byte(`{"emailAddress":"candidate@icloud.com"}`))
		case "PUT /account/manage/email/private/add/complete":
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = w.Write([]byte(`{"emailAddress":"created@icloud.com","id":"complete-id","active":true}`))
		case "GET /account/manage/email/private/complete-id.em":
			_, _ = w.Write([]byte(`{"emailAddress":"created@icloud.com","id":"complete-id","active":true}`))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
		}
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	remote, _, err := (&ICloudClient{client: server.Client()}).createPrivacyMailboxWithAppleAccountState(
		context.Background(),
		ICloudSession{},
		LoginState{Kind: LoginStateAppleAccount, APIKey: "api-key", Scnt: "scnt"},
		"",
		"label",
		"note",
	)
	if err != nil {
		t.Fatalf("412 complete should use official body, got %v", err)
	}
	if remote.AnonymousID != "complete-id" || remote.Email != "created@icloud.com" {
		t.Fatalf("remote = %+v, want complete-id", remote)
	}
}

func TestAppleAccountRemoteDeleteRejectsNoContent(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/stop") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	_, err := (&ICloudClient{client: server.Client()}).DeletePrivacyMailboxWithAppleAccount(
		context.Background(),
		testAppleAccountListSession(),
		"",
		"no-content-id",
	)
	if !isCodedError(err, "apple_account_api_failed") {
		t.Fatalf("204 stop should fail, got %#v", err)
	}
	if got := strings.Join(paths, "\n"); got != "DELETE /account/manage/email/private/no-content-id/stop" {
		t.Fatalf("paths = %q, want stop only", got)
	}
}

func TestAppleAccountMailboxListPrefersOfficialListsOverHMEEmails(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"hmeEmails": [{"id":"legacy-id","emailAddress":"same@icloud.com"}],
			"privateEmailList": [{"id":"official-id","emailAddress":"same@icloud.com"}],
			"inactivePrivateEmailList": []
		}`))
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	remotes, _, err := (&ICloudClient{client: server.Client()}).ListPrivacyMailboxesForOriginWithSession(
		context.Background(),
		testAppleAccountListSession(),
		mailboxRemoteOriginAppleAccount,
	)
	if err != nil {
		t.Fatalf("overlapping official lists should not be incomplete, got %v", err)
	}
	if len(remotes) != 1 || remotes[0].AnonymousID != "official-id" {
		t.Fatalf("remotes = %+v, want official-id only", remotes)
	}
}

func TestAppleAccountMailboxListFallsBackToHMEEmailsWhenOfficialListsEmpty(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"hmeEmails": [{"id":"legacy-id","emailAddress":"legacy@icloud.com"}],
			"privateEmailList": [],
			"inactivePrivateEmailList": []
		}`))
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	remotes, _, err := (&ICloudClient{client: server.Client()}).ListPrivacyMailboxesForOriginWithSession(
		context.Background(),
		testAppleAccountListSession(),
		mailboxRemoteOriginAppleAccount,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(remotes) != 1 || remotes[0].AnonymousID != "legacy-id" {
		t.Fatalf("remotes = %+v, want hmeEmails fallback", remotes)
	}
}

func TestICloudWebMailboxListPrefersAnonymousID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/hme/list" {
			http.Error(w, "unexpected "+r.URL.Path, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":{"hmeEmails":[{"id":"opaque-id","anonymousId":"web-anon","hme":"web@icloud.com","isActive":true}]}}`))
	}))
	defer server.Close()

	remotes, err := (&ICloudClient{client: server.Client()}).listICloudWebPrivacyMailboxes(context.Background(), ICloudSession{
		DSID:               "dsid",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		PremiumMailBaseURL: server.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(remotes) != 1 || remotes[0].AnonymousID != "web-anon" {
		t.Fatalf("remotes = %+v, want web anonymousId", remotes)
	}
}

func TestAppleAccountMailboxDetailRejectsPreconditionFailed(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			_, _ = w.Write([]byte(`{"emailAddress":"candidate@icloud.com"}`))
		case "PUT /account/manage/email/private/add/complete":
			_, _ = w.Write([]byte(`{"emailAddress":"created@icloud.com","id":"complete-id","active":true}`))
		case "GET /account/manage/email/private/complete-id.em":
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = w.Write([]byte(`{"emailAddress":"wrong@icloud.com","id":"wrong-id","active":true}`))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
		}
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	remote, _, err := (&ICloudClient{client: server.Client()}).createPrivacyMailboxWithAppleAccountState(
		context.Background(),
		ICloudSession{},
		LoginState{Kind: LoginStateAppleAccount, APIKey: "api-key", Scnt: "scnt"},
		"",
		"label",
		"note",
	)
	if err != nil {
		t.Fatalf("create should keep complete payload when detail 412, got %v", err)
	}
	if remote.AnonymousID != "complete-id" || remote.Email != "created@icloud.com" {
		t.Fatalf("remote = %+v, want complete-id not 412 detail body", remote)
	}
}

func TestAppleAccountRemoteDeleteAuthRetryAfterPreRefreshSkipsSecondStop(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name  string
		state LoginState
	}{
		{
			name: "keepalive_fail_count",
			state: LoginState{
				Kind:               LoginStateAppleAccount,
				Scnt:               "scnt",
				APIKey:             "api-key",
				LastCheckedAt:      now,
				ManageExpiresAt:    now.Add(10 * time.Minute),
				LastCheckOK:        false,
				KeepAliveFailCount: 1,
			},
		},
		{
			name: "expired_manage",
			state: LoginState{
				Kind:            LoginStateAppleAccount,
				Scnt:            "scnt",
				APIKey:          "api-key",
				LastCheckedAt:   now.Add(-time.Hour),
				ManageExpiresAt: now.Add(-time.Minute),
				LastCheckOK:     true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldBaseURL := appleAccountManageBaseURL
			defer func() { appleAccountManageBaseURL = oldBaseURL }()

			var paths []string
			removeHits := 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.Method+" "+r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				switch r.Method + " " + r.URL.Path {
				case "GET /account/manage/gs/ws/token":
					w.Header().Set("scnt", "retry-token-scnt")
					_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
				case "GET /account/manage":
					w.Header().Set("scnt", "retry-manage-scnt")
					_, _ = w.Write([]byte(`{"apiKey":"retry-api-key"}`))
				case "DELETE /account/manage/email/private/pre-refresh/stop":
					if strings.Count(strings.Join(paths, "\n"), "/stop") > 1 {
						http.Error(w, "auth retry must not call /stop again", http.StatusBadRequest)
						return
					}
					_, _ = w.Write([]byte(`{}`))
				case "DELETE /account/manage/email/private/pre-refresh/remove":
					removeHits++
					if removeHits == 1 {
						w.WriteHeader(http.StatusUnauthorized)
						_, _ = w.Write([]byte(`{"service_errors":[{"message":"authentication_failed"}]}`))
						return
					}
					_, _ = w.Write([]byte(`{}`))
				default:
					http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
				}
			}))
			defer ts.Close()
			appleAccountManageBaseURL = ts.URL

			_, err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailboxWithAppleAccount(context.Background(), ICloudSession{
				LoginStates: []LoginState{tt.state},
			}, "", "pre-refresh")
			if err != nil {
				t.Fatalf("auth retry after pre-refresh stop should finish remove, got %#v", err)
			}
			want := strings.Join([]string{
				"GET /account/manage/gs/ws/token",
				"GET /account/manage",
				"DELETE /account/manage/email/private/pre-refresh/stop",
				"DELETE /account/manage/email/private/pre-refresh/remove",
				"GET /account/manage/gs/ws/token",
				"GET /account/manage",
				"DELETE /account/manage/email/private/pre-refresh/remove",
			}, "\n")
			if got := strings.Join(paths, "\n"); got != want {
				t.Fatalf("paths = %q, want %q", got, want)
			}
		})
	}
}

func TestAppleAccountRemoteDeleteSkipsStopForPersistedInactiveMailbox(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.Method+" "+r.URL.Path != "DELETE /account/manage/email/private/inactive-id/remove" {
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-inactive-skip-stop"
	account, err := store.AddAccountForOwner(ownerID, "Inactive skip stop", "inactive-skip-stop@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
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
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote(ownerID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "inactive-id",
		Origin:      mailboxRemoteOriginAppleAccount,
		Email:       "inactive-skip-stop@icloud.com",
		IsActive:    false,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if mailbox.ICloudActive {
		t.Fatal("fixture mailbox should already be inactive")
	}

	if err := handler.deleteICloudMailboxRemote(context.Background(), mailbox); err != nil {
		t.Fatalf("inactive mailbox delete = %#v", err)
	}
	if got := strings.Join(paths, "\n"); got != "DELETE /account/manage/email/private/inactive-id/remove" {
		t.Fatalf("paths = %q, want remove only", got)
	}
}

func TestCreatedRemoteCleanupRetriesRemoveOnlyAfterStopWhenRemoveFails(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	removeHits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "DELETE /account/manage/email/private/cleanup-retry/stop":
			if strings.Count(strings.Join(paths, "\n"), "/stop") > 1 {
				http.Error(w, "cleanup retry must not call /stop again", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{}`))
		case "DELETE /account/manage/email/private/cleanup-retry/remove":
			removeHits++
			if removeHits == 1 {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte(`{"error":"temporary provider failure"}`))
				return
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-cleanup-retry"
	account, err := store.AddAccountForOwner(ownerID, "Cleanup retry", "cleanup-retry@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
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
	}); err != nil {
		t.Fatal(err)
	}

	err = handler.cleanupCreatedRemoteMailbox(context.Background(), ownerID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "cleanup-retry",
		Origin:      mailboxRemoteOriginAppleAccount,
		Email:       "cleanup-retry@icloud.com",
		IsActive:    true,
	})
	if err != nil {
		t.Fatalf("cleanup after stop should retry remove only, got %#v", err)
	}
	want := strings.Join([]string{
		"DELETE /account/manage/email/private/cleanup-retry/stop",
		"DELETE /account/manage/email/private/cleanup-retry/remove",
		"DELETE /account/manage/email/private/cleanup-retry/remove",
	}, "\n")
	if got := strings.Join(paths, "\n"); got != want {
		t.Fatalf("paths = %q, want %q", got, want)
	}
}

func TestMarkMailboxesRemoteMissingSkipsUnresolvedRemoteDelete(t *testing.T) {
	store := newTestStore(t)
	pending, err := store.AddMailboxForOwnerWithRemote("owner-missing-unresolved", "account-missing-unresolved", ICloudRemoteMailbox{
		AnonymousID: "pending-id",
		Origin:      mailboxRemoteOriginAppleAccount,
		Email:       "pending-missing@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginMailboxRemoteDelete(pending.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	failed, err := store.AddMailboxForOwnerWithRemote("owner-missing-unresolved", "account-missing-unresolved", ICloudRemoteMailbox{
		AnonymousID: "failed-id",
		Origin:      mailboxRemoteOriginAppleAccount,
		Email:       "failed-missing@icloud.com",
		IsActive:    false,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMailboxRemoteDeleteFailed(failed.ID, "remove failed", time.Now()); err != nil {
		t.Fatal(err)
	}
	plain, err := store.AddMailboxForOwnerWithRemote("owner-missing-unresolved", "account-missing-unresolved", ICloudRemoteMailbox{
		AnonymousID: "plain-id",
		Origin:      mailboxRemoteOriginAppleAccount,
		Email:       "plain-missing@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	checkedAt := time.Now()
	count, err := store.MarkMailboxesRemoteMissing("owner-missing-unresolved", "account-missing-unresolved", map[string]struct{}{}, checkedAt)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("missing count = %d, want 1 plain mailbox", count)
	}
	currentPending, ok := store.FindMailboxByID(pending.ID)
	if !ok {
		t.Fatal("pending mailbox missing")
	}
	if currentPending.RemoteDeleteStatus != "pending" || !currentPending.ICloudActive || !currentPending.RemoteMissingAt.IsZero() {
		t.Fatalf("pending mailbox was marked remote missing: %+v", currentPending)
	}
	currentFailed, ok := store.FindMailboxByID(failed.ID)
	if !ok {
		t.Fatal("failed mailbox missing")
	}
	if currentFailed.RemoteDeleteStatus != "failed" || currentFailed.ICloudActive || !currentFailed.RemoteMissingAt.IsZero() {
		t.Fatalf("failed mailbox was marked remote missing: %+v", currentFailed)
	}
	currentPlain, ok := store.FindMailboxByID(plain.ID)
	if !ok {
		t.Fatal("plain mailbox missing")
	}
	if currentPlain.ICloudActive || currentPlain.Status != StatusDisabled || currentPlain.RemoteMissingAt.IsZero() {
		t.Fatalf("plain mailbox was not marked remote missing: %+v", currentPlain)
	}
}

func TestAppleAccountReactivateAndUpdateRequireOK(t *testing.T) {
	if appleAccountHTTPStatusIsSuccess(http.MethodPost, "/account/manage/email/private/id/reactivate", http.StatusNoContent) {
		t.Fatal("reactivate 204 must not count as HME success")
	}
	if !appleAccountHTTPStatusIsSuccess(http.MethodPost, "/account/manage/email/private/id/reactivate", http.StatusOK) {
		t.Fatal("reactivate 200 should count as HME success")
	}
	if appleAccountHTTPStatusIsSuccess(http.MethodPost, "/account/manage/email/private/id/note", http.StatusNoContent) {
		t.Fatal("update note 204 must not count as HME success")
	}
	if !appleAccountHTTPStatusIsSuccess(http.MethodPost, "/account/manage/email/private/id/note", http.StatusOK) {
		t.Fatal("update note 200 should count as HME success")
	}
}
