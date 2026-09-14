package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnableMailboxRestoresAPIAfterDisable(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "enable-after-disable", "password123")
	mailbox, err := store.AddMailboxForOwner(user.ID, "", "Enable", "enable-after-disable@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	disableReq := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+mailbox.ID+"/disable", strings.NewReader("{}"))
	disableReq.Header.Set("Content-Type", "application/json")
	disableReq.AddCookie(cookie)
	addClosureTestCSRF(disableReq, cookie)
	disableRR := httptest.NewRecorder()
	handler.ServeHTTP(disableRR, disableReq)
	if disableRR.Code != http.StatusOK {
		t.Fatalf("disable status = %d body=%s", disableRR.Code, disableRR.Body.String())
	}
	disabled, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing after disable")
	}
	if disabled.APIActive || disabled.Status != StatusDisabled {
		t.Fatalf("after disable mailbox = %+v", disabled)
	}

	enableReq := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+mailbox.ID+"/enable", strings.NewReader("{}"))
	enableReq.Header.Set("Content-Type", "application/json")
	enableReq.AddCookie(cookie)
	addClosureTestCSRF(enableReq, cookie)
	enableRR := httptest.NewRecorder()
	handler.ServeHTTP(enableRR, enableReq)
	if enableRR.Code != http.StatusOK {
		t.Fatalf("enable status = %d body=%s", enableRR.Code, enableRR.Body.String())
	}
	enabled, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing after enable")
	}
	if !enabled.APIActive || enabled.Status != StatusAvailable {
		t.Fatalf("after enable mailbox = %+v", enabled)
	}
}

func TestEnableMailboxRejectsRemoteDeletedMailbox(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "enable-remote-deleted", "password123")
	mailbox, err := store.AddMailboxForOwnerWithRemote(user.ID, "account-enable-remote-deleted", ICloudRemoteMailbox{
		AnonymousID: "enable-remote-deleted",
		Origin:      "ICLOUD_WEB",
		Email:       "enable-remote-deleted@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMailboxRemoteDeleteSucceeded(mailbox.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	expected, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing after remote delete mark")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+mailbox.ID+"/enable", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("enable remote-deleted status = %d body=%s, want 409", rr.Code, rr.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "mailbox_remote_deleted" {
		t.Fatalf("enable remote-deleted code = %q body=%s", body.Code, rr.Body.String())
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after blocked enable")
	}
	if current != expected {
		t.Fatalf("mailbox changed after blocked enable: got=%+v want=%+v", current, expected)
	}
}

func TestEnableMailboxReturnsPersistenceFailureAs500(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("", "", "ENABLE-PERSIST-FAILURE", "enable-persist-failure@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	inactive := false
	if _, err := store.SetMailboxStatus(mailbox.ID, &inactive, nil, StatusDisabled, "API 已停用"); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "enable-persist", "admin123")
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+mailbox.ID+"/enable", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("enable persist status = %d body=%s, want 500", rr.Code, rr.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "mailbox_status_persist_failed" {
		t.Fatalf("enable persist code = %q body=%s", body.Code, rr.Body.String())
	}
}

func TestFilterMailboxesForListByUsageAPIAndRemoteStatus(t *testing.T) {
	accounts := mailboxAccountMap(nil)
	mailboxes := []Mailbox{
		{ID: "available", Email: "available@icloud.com", Status: StatusAvailable, APIActive: true},
		{ID: "active", Email: "active@icloud.com", Status: StatusActive, APIActive: true},
		{ID: "used", Email: "used@icloud.com", Status: StatusUsed, APIActive: true},
		{ID: "failed", Email: "failed@icloud.com", Status: StatusFailed, APIActive: true},
		{ID: "disabled", Email: "disabled@icloud.com", Status: StatusDisabled, APIActive: false},
		{ID: "api-off", Email: "api-off@icloud.com", Status: StatusAvailable, APIActive: false},
		{ID: "unknown", Email: "unknown@icloud.com", Status: StatusAvailable, APIActive: true, RemoteDeleteStatus: "unknown"},
		{ID: "failed-remote", Email: "failed-remote@icloud.com", Status: StatusAvailable, APIActive: true, RemoteDeleteStatus: "failed"},
	}

	unused := mailboxIDs(filterMailboxesForList(mailboxes, accounts, url.Values{"status": []string{"unused"}}))
	if strings.Join(unused, ",") != "available,active,api-off,unknown,failed-remote" {
		t.Fatalf("unused filter = %v", unused)
	}
	used := mailboxIDs(filterMailboxesForList(mailboxes, accounts, url.Values{"status": []string{"used"}}))
	if strings.Join(used, ",") != "used" {
		t.Fatalf("used filter = %v", used)
	}
	apiOff := mailboxIDs(filterMailboxesForList(mailboxes, accounts, url.Values{"api_active": []string{"0"}}))
	if strings.Join(apiOff, ",") != "disabled,api-off" {
		t.Fatalf("api_active=0 filter = %v", apiOff)
	}
	unknown := mailboxIDs(filterMailboxesForList(mailboxes, accounts, url.Values{"remote_delete": []string{"unknown"}}))
	if strings.Join(unknown, ",") != "unknown" {
		t.Fatalf("remote_delete=unknown filter = %v", unknown)
	}
	failedRemote := mailboxIDs(filterMailboxesForList(mailboxes, accounts, url.Values{"remote_delete": []string{"failed"}}))
	if strings.Join(failedRemote, ",") != "failed-remote" {
		t.Fatalf("remote_delete=failed filter = %v", failedRemote)
	}
}

func TestListMailboxesAppliesUsageAndAPIFilters(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "list-status-filter", "password123")
	available, err := store.AddMailboxForOwner(user.ID, "", "Available", "list-available@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	used, err := store.AddMailboxForOwner(user.ID, "", "Used", "list-used@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetMailboxStatus(used.ID, nil, nil, StatusUsed, "claimed"); err != nil {
		t.Fatal(err)
	}
	disabled, err := store.AddMailboxForOwner(user.ID, "", "Disabled", "list-disabled@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	inactive := false
	if _, err := store.SetMailboxStatus(disabled.ID, &inactive, nil, StatusDisabled, "API 已停用"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/mailboxes?status=unused", nil)
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unused list status = %d body=%s", rr.Code, rr.Body.String())
	}
	got := listMailboxIDs(t, rr)
	if len(got) != 1 || got[0] != available.ID {
		t.Fatalf("unused list = %v, want only %s", got, available.ID)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/mailboxes?status=used", nil)
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	got = listMailboxIDs(t, rr)
	if len(got) != 1 || got[0] != used.ID {
		t.Fatalf("used list = %v, want only %s", got, used.ID)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/mailboxes?api_active=0", nil)
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	got = listMailboxIDs(t, rr)
	if len(got) != 1 || got[0] != disabled.ID {
		t.Fatalf("api_active=0 list = %v, want only %s", got, disabled.ID)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/mailboxes?status=maybe", nil)
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid status filter status = %d body=%s, want 400", rr.Code, rr.Body.String())
	}
}

func TestMailboxExportFiltersByUsageStatus(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "export-status-filter", "admin123")
	available := createTestMailboxWithCookie(t, handler, adminCookie, "Available", "export-available@icloud.com")
	used := createTestMailboxWithCookie(t, handler, adminCookie, "Used", "export-used@icloud.com")
	if _, err := store.SetMailboxStatus(used.ID, nil, nil, StatusUsed, "claimed"); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-emails?status=unused", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unused export status = %d body=%s", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); body != available.Email+"\n" {
		t.Fatalf("unused export body = %q", body)
	}
}

func TestBulkStatusEnablesSelectedMailboxes(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "bulk-enable", "password123")
	first, err := store.AddMailboxForOwner(user.ID, "", "One", "bulk-enable-one@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddMailboxForOwner(user.ID, "", "Two", "bulk-enable-two@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	inactive := false
	for _, mailbox := range []Mailbox{first, second} {
		if _, err := store.SetMailboxStatus(mailbox.ID, &inactive, nil, StatusDisabled, "API 已停用"); err != nil {
			t.Fatal(err)
		}
	}

	body := `{"ids":["` + first.ID + `","` + second.ID + `"],"status":"available","api_active":true,"note":"面板批量启用 API"}`
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/bulk-status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("bulk enable status = %d body=%s", rr.Code, rr.Body.String())
	}
	var response struct {
		Success bool `json:"success"`
		Updated int  `json:"updated"`
		Failed  int  `json:"failed"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Success || response.Updated != 2 || response.Failed != 0 {
		t.Fatalf("bulk enable response = %+v body=%s", response, rr.Body.String())
	}
	for _, id := range []string{first.ID, second.ID} {
		current, ok := store.FindMailboxByID(id)
		if !ok {
			t.Fatalf("mailbox %s missing after bulk enable", id)
		}
		if !current.APIActive || current.Status != StatusAvailable {
			t.Fatalf("mailbox %s after bulk enable = %+v", id, current)
		}
	}
}

func TestBulkStatusRejectsIDsOutsideSelectionScope(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "bulk-status-scope", "password123")
	accountA, err := store.AddAccountForOwner(user.ID, "Account A", "status-scope-a@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	accountB, err := store.AddAccountForOwner(user.ID, "Account B", "status-scope-b@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailboxA, err := store.AddMailboxForOwner(user.ID, accountA.ID, "A", "status-scope-a@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner(user.ID, accountB.ID, "B", "status-scope-b@icloud.com"); err != nil {
		t.Fatal(err)
	}

	body := `{"ids":["` + mailboxA.ID + `"],"status":"used","scope":{"account_key":"` + accountB.ID + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/bulk-status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("bulk scoped status = %d body=%s, want 207", rr.Code, rr.Body.String())
	}
	current, ok := store.FindMailboxByID(mailboxA.ID)
	if !ok {
		t.Fatal("mailbox disappeared after scoped bulk status")
	}
	if current.Status != StatusAvailable {
		t.Fatalf("mailbox outside scope was mutated: %+v", current)
	}
	if !strings.Contains(rr.Body.String(), "不再符合当前筛选条件") {
		t.Fatalf("bulk scoped status body=%s, want selection scope failure detail", rr.Body.String())
	}
}

func TestBulkStatusCannotResurrectRemoteDeletedMailbox(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "bulk-status-remote-deleted", "password123")
	mailbox, err := store.AddMailboxForOwnerWithRemote(user.ID, "account-bulk-status-remote-deleted", ICloudRemoteMailbox{
		AnonymousID: "bulk-status-remote-deleted",
		Origin:      "ICLOUD_WEB",
		Email:       "bulk-status-remote-deleted@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMailboxRemoteDeleteSucceeded(mailbox.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	expected, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing after remote delete mark")
	}

	body := `{"ids":["` + mailbox.ID + `"],"status":"available","api_active":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/bulk-status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("bulk resurrect status = %d body=%s, want 207", rr.Code, rr.Body.String())
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after blocked bulk status")
	}
	if current != expected {
		t.Fatalf("remote-deleted mailbox changed: got=%+v want=%+v", current, expected)
	}
}

func mailboxIDs(mailboxes []Mailbox) []string {
	out := make([]string, 0, len(mailboxes))
	for _, mailbox := range mailboxes {
		out = append(out, mailbox.ID)
	}
	return out
}

func listMailboxIDs(t *testing.T, rr *httptest.ResponseRecorder) []string {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(body.Mailboxes))
	for _, mailbox := range body.Mailboxes {
		ids = append(ids, mailbox.ID)
	}
	return ids
}
