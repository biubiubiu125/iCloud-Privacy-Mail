package app

import (
	"bytes"
	"context"
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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestJSONRequestParsersRejectTrailingValues(t *testing.T) {
	t.Run("mailbox export request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis", strings.NewReader(`{"format":"jsonl"} {"format":"csv"}`))
		_, err := parseMailboxExportRequest(req)
		if !isCodedError(err, "invalid_export_request") {
			t.Fatalf("parseMailboxExportRequest error = %#v, want invalid_export_request", err)
		}
	})

	t.Run("generic JSON request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/accounts", strings.NewReader(`{"label":"one"} {"label":"two"}`))
		var payload struct {
			Label string `json:"label"`
		}
		err := decodeJSON(req, &payload)
		if !isCodedError(err, "bad_json") {
			t.Fatalf("decodeJSON error = %#v, want bad_json", err)
		}
	})
}

func TestWriteAtomicFileCreatesPrivateStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	content := []byte(`{"version":1}`)
	if err := writeAtomicFile(path, content, 0o600); err != nil {
		t.Fatalf("writeAtomicFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read atomic file: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("atomic file content = %q, want %q", got, content)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat atomic file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("atomic file mode = %o, want 600", info.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary atomic file still exists: err=%v", err)
	}
}

func TestFileStoreTightensExistingStateFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"next_id":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := NewFileStore(path); err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode = %o, want 600", info.Mode().Perm())
	}
}

func TestFileStoreMigratesMailboxOwnerFromAccountID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := State{
		NextID: 2,
		Accounts: []Account{{
			ID:      "acc_legacy_owner",
			OwnerID: "usr_legacy_owner",
			AppleID: "legacy-owner@example.com",
		}},
		Mailboxes: []Mailbox{{
			ID:        "mbx_legacy_owner",
			AccountID: "acc_legacy_owner",
			Email:     "legacy-owner@icloud.com",
			APIToken:  "legacy-token",
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
	mailbox, ok := store.FindMailboxByID("mbx_legacy_owner")
	if !ok {
		t.Fatal("migrated mailbox not found")
	}
	if mailbox.OwnerID != "usr_legacy_owner" {
		t.Fatalf("migrated mailbox owner = %q, want %q", mailbox.OwnerID, "usr_legacy_owner")
	}
}

func TestAccountMailboxCreateReconciliationStatePersistsAndClears(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwner("owner-reconciliation-state", "Reconciliation", "reconciliation@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	checkedAt := time.Date(2026, 9, 7, 12, 34, 56, 0, time.UTC)
	if err := store.MarkAccountMailboxCreateReconciliationRequiredForOrigin(
		account.OwnerID,
		account.ID,
		mailboxRemoteOriginICloudWeb,
		"Apple Account 创建结果不确定",
		checkedAt,
	); err != nil {
		t.Fatal(err)
	}

	got, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared after marking reconciliation state")
	}
	if !got.MailboxCreateReconciliationRequired ||
		!got.MailboxCreateReconciliationAt.Equal(checkedAt) ||
		got.MailboxCreateReconciliationError != "Apple Account 创建结果不确定" ||
		got.MailboxCreateReconciliationOrigin != mailboxRemoteOriginICloudWeb {
		t.Fatalf("account reconciliation state = %+v", got)
	}

	if err := store.ClearAccountMailboxCreateReconciliationRequired(account.OwnerID, account.ID); err != nil {
		t.Fatal(err)
	}
	got, ok = store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared after clearing reconciliation state")
	}
	if got.MailboxCreateReconciliationRequired ||
		!got.MailboxCreateReconciliationAt.IsZero() ||
		got.MailboxCreateReconciliationError != "" ||
		got.MailboxCreateReconciliationOrigin != "" {
		t.Fatalf("account reconciliation state after clear = %+v", got)
	}
}

func TestMailboxCreateBlocksAccountWithUncertainRemoteResult(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	store := newTestStore(t)
	ownerID := "owner-reconciliation-gate"
	account, err := store.AddAccountForOwner(ownerID, "Reconciliation gate", "reconciliation-gate@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   account.AppleID,
		LoginStates: []LoginState{{
			Kind:        LoginStateAppleAccount,
			Scnt:        "scnt",
			APIKey:      "api-key",
			LastCheckOK: true,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAccountMailboxCreateReconciliationRequired(
		ownerID,
		account.ID,
		"需要先同步远端列表",
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	var providerCalls atomic.Int32
	handler.createMailboxForOwner = func(context.Context, string, string, string, string) (Mailbox, ICloudRemoteMailbox, error) {
		providerCalls.Add(1)
		return Mailbox{}, ICloudRemoteMailbox{}, errors.New("provider should not be called")
	}
	_, _, failures, err := handler.createMailboxesForOwnerWithChannels(
		context.Background(),
		ownerID,
		[]mailboxCreateRequest{{AccountID: account.ID, Channel: mailboxCreateChannelAppleAccount}},
		"",
		"",
	)
	if !isCodedError(err, "mailbox_create_reconciliation_required") {
		t.Fatalf("create error = %#v, want mailbox_create_reconciliation_required", err)
	}
	if got := providerCalls.Load(); got != 0 {
		t.Fatalf("provider calls = %d, want 0", got)
	}
	if len(failures) != 1 || failures[0].Code != "mailbox_create_reconciliation_required" {
		t.Fatalf("failures = %+v, want reconciliation gate failure", failures)
	}
}

func TestMailboxCreateAutoSyncsReconciliationAndCreatesViaWebWhenAppleListUnauthorized(t *testing.T) {
	fixture := startAppleUnauthorizedWebCreateServers(t)
	defer fixture.cleanup()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-auto-sync-create"
	account, err := store.AddAccountForOwner(ownerID, "Auto sync create", "auto-sync-create@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(ownerID, fixture.session(ownerID, account.ID, account.AppleID)); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAccountMailboxCreateReconciliationRequiredForOrigin(
		ownerID,
		account.ID,
		mailboxRemoteOriginAppleAccount,
		"Apple Account 已提交隐私邮箱确认请求，但未收到可确认的结果",
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}

	mailboxes, _, failures, err := handler.createMailboxesForOwnerWithChannels(
		context.Background(),
		ownerID,
		[]mailboxCreateRequest{{AccountID: account.ID, Channel: mailboxCreateChannelAuto}},
		"AUTO",
		"",
	)
	if err != nil {
		t.Fatalf("auto create after locked reconciliation = %#v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("auto create failures = %+v, want none", failures)
	}
	if len(mailboxes) != 1 || mailboxes[0].Email != "auto-created@icloud.com" {
		t.Fatalf("created mailboxes = %+v, want auto-created@icloud.com", mailboxes)
	}
	if fixture.addCalls.Load() != 0 {
		t.Fatalf("Apple Account generate calls = %d, want 0 after list 401", fixture.addCalls.Load())
	}
	if fixture.listCalls.Load() == 0 {
		t.Fatal("Apple Account list was not probed before auto create")
	}
	if fixture.webGenCalls.Load() == 0 {
		t.Fatal("iCloud Web create was not used after automatic reconciliation")
	}
	account, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared after auto create")
	}
	if account.MailboxCreateReconciliationRequired {
		t.Fatal("reconciliation lock was not cleared before automatic create")
	}
}

func TestAutoMailboxCreateFallsBackToWebWhenAppleListUnauthorizedBeforeGenerate(t *testing.T) {
	fixture := startAppleUnauthorizedWebCreateServers(t)
	defer fixture.cleanup()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-auto-list-401"
	account, err := store.AddAccountForOwner(ownerID, "Auto list 401", "auto-list-401@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	session := fixture.session(ownerID, account.ID, account.AppleID)
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}

	mailbox, remote, err := handler.createICloudMailboxForOwner(context.Background(), ownerID, account.ID, "AUTO", "")
	if err != nil {
		t.Fatal(err)
	}
	if fixture.addCalls.Load() != 0 {
		t.Fatalf("Apple Account generate calls = %d, want 0 when list is unauthorized", fixture.addCalls.Load())
	}
	if fixture.listCalls.Load() == 0 {
		t.Fatal("Apple Account list was not probed before auto create")
	}
	if remote.Email != "auto-created@icloud.com" || remote.AnonymousID != "web-auto-1" || remote.Origin != mailboxRemoteOriginICloudWeb {
		t.Fatalf("fallback remote = %+v, want iCloud Web mailbox", remote)
	}
	if mailbox.Email != "auto-created@icloud.com" {
		t.Fatalf("fallback mailbox = %+v, want locally saved iCloud Web mailbox", mailbox)
	}
}

func TestMailboxCreateStillBlocksWhenAutomaticSyncCannotConfirm(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var listCalls, generateCalls atomic.Int32
	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			listCalls.Add(1)
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		case "GET /account/manage/gs/ws/token":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "GET /account/manage/section/privacy":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html>privacy</html>`))
		case "GET /bootstrap/portal":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/hme/list":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		case "/v1/hme/generate", "/v1/hme/reserve":
			generateCalls.Add(1)
			t.Fatalf("iCloud Web create was called while reconciliation was still blocked: %s", r.URL.Path)
		default:
			t.Fatalf("unexpected iCloud Web request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer webServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-auto-sync-still-blocked"
	account, err := store.AddAccountForOwner(ownerID, "Auto sync still blocked", "auto-sync-still-blocked@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "auto-sync-still-blocked-dsid",
		PremiumMailBaseURL: webServer.URL,
		Host:               "www.icloud.com",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "session", Value: "web-cookie"}},
		LoginStates: []LoginState{
			{
				Kind:            LoginStateAppleAccount,
				Scnt:            "scnt",
				APIKey:          "api-key",
				LastCheckedAt:   now,
				LastCheckOK:     true,
				ManageExpiresAt: now.Add(time.Hour),
			},
			{
				Kind:    LoginStateICloudWeb,
				Cookies: []SessionCookie{{Name: "session", Value: "web-cookie"}},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAccountMailboxCreateReconciliationRequiredForOrigin(
		ownerID,
		account.ID,
		mailboxRemoteOriginAppleAccount,
		"Apple Account 创建结果不确定",
		now,
	); err != nil {
		t.Fatal(err)
	}

	_, _, failures, err := handler.createMailboxesForOwnerWithChannels(
		context.Background(),
		ownerID,
		[]mailboxCreateRequest{{AccountID: account.ID, Channel: mailboxCreateChannelAuto}},
		"BLOCK",
		"",
	)
	if !isCodedError(err, "mailbox_create_reconciliation_required") {
		t.Fatalf("create error = %#v, want mailbox_create_reconciliation_required", err)
	}
	if listCalls.Load() == 0 {
		t.Fatal("automatic sync did not attempt Apple Account list")
	}
	if generateCalls.Load() != 0 {
		t.Fatalf("create provider calls = %d, want 0 while lock remains", generateCalls.Load())
	}
	if len(failures) != 1 || failures[0].Code != "mailbox_create_reconciliation_required" {
		t.Fatalf("failures = %+v, want reconciliation gate failure", failures)
	}
	account, ok := store.FindAccountByID(account.ID)
	if !ok || !account.MailboxCreateReconciliationRequired {
		t.Fatalf("account reconciliation state = %+v, want lock retained", account)
	}
}

func TestMailboxSchedulerAutoSyncsReconciliationThenCreatesViaWeb(t *testing.T) {
	fixture := startAppleUnauthorizedWebCreateServers(t)
	defer fixture.cleanup()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-scheduler-auto-sync"
	account, err := store.AddAccountForOwner(ownerID, "Scheduler auto sync", "scheduler-auto-sync@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(ownerID, fixture.session(ownerID, account.ID, account.AppleID)); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAccountMailboxCreateReconciliationRequiredForOrigin(
		ownerID,
		account.ID,
		mailboxRemoteOriginAppleAccount,
		"Apple Account 已提交隐私邮箱确认请求，但未收到可确认的结果",
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}

	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	handler.runMailboxSchedulerBatch(context.Background(), ownerID, job, mailboxSchedulerConfig{
		AccountIDs:    []string{account.ID},
		Label:         "SCH",
		BatchSize:     1,
		RoundInterval: 0,
	}, 1)
	state, events := job.snapshot()
	if state.Success < 1 {
		t.Fatalf("scheduler state = %+v events=%+v, want at least one success", state, events)
	}
	if fixture.addCalls.Load() != 0 {
		t.Fatalf("Apple Account generate calls = %d, want 0", fixture.addCalls.Load())
	}
	var sawWebCreate bool
	for _, event := range events {
		if event.Type == "created" && strings.Contains(event.Message, "旧接口") && strings.Contains(event.Message, "auto-created@icloud.com") {
			sawWebCreate = true
			break
		}
	}
	if !sawWebCreate {
		t.Fatalf("scheduler events = %+v, want a successful iCloud Web create after automatic sync", events)
	}
}

type appleUnauthorizedWebCreateFixture struct {
	appleURL    string
	webURL      string
	listCalls   *atomic.Int32
	addCalls    *atomic.Int32
	webGenCalls *atomic.Int32
	cleanup     func()
}

func startAppleUnauthorizedWebCreateServers(t *testing.T) appleUnauthorizedWebCreateFixture {
	t.Helper()
	oldBaseURL := appleAccountManageBaseURL
	listCalls := &atomic.Int32{}
	addCalls := &atomic.Int32{}
	webGenCalls := &atomic.Int32{}
	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/account/manage/email/private"):
			listCalls.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case r.Method == http.MethodGet && r.URL.Path == "/account/manage/gs/ws/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case r.Method == http.MethodGet && r.URL.Path == "/account/manage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/account/manage/email/private/add":
			addCalls.Add(1)
			t.Fatal("Apple Account generate should not run after list unauthorized")
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	appleAccountManageBaseURL = appleServer.URL
	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/hme/list":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hmeEmails":[{"anonymousId":"existing-1","hme":"existing@icloud.com","label":"EXISTING","isActive":true}]}}`))
		case "/v1/hme/generate":
			webGenCalls.Add(1)
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":"auto-created@icloud.com"}}`))
		case "/v1/hme/reserve":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":{"anonymousId":"web-auto-1","hme":"auto-created@icloud.com","label":"AUTO","isActive":true}}}`))
		case "/v1/hme/deactivate", "/v1/hme/delete":
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		default:
			t.Fatalf("unexpected iCloud Web request %s %s", r.Method, r.URL.Path)
		}
	}))
	return appleUnauthorizedWebCreateFixture{
		appleURL:    appleServer.URL,
		webURL:      webServer.URL,
		listCalls:   listCalls,
		addCalls:    addCalls,
		webGenCalls: webGenCalls,
		cleanup: func() {
			webServer.Close()
			appleServer.Close()
			appleAccountManageBaseURL = oldBaseURL
		},
	}
}

func (f appleUnauthorizedWebCreateFixture) session(ownerID, accountID, appleID string) ICloudSession {
	now := time.Now()
	return ICloudSession{
		OwnerID:            ownerID,
		AccountID:          accountID,
		AppleID:            appleID,
		DSID:               ownerID + "-dsid",
		PremiumMailBaseURL: f.webURL,
		Host:               "www.icloud.com",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "session", Value: "web-cookie"}},
		LoginStates: []LoginState{
			{
				Kind:            LoginStateAppleAccount,
				Scnt:            "scnt",
				APIKey:          "api-key",
				LastCheckedAt:   now,
				LastCheckOK:     true,
				ManageExpiresAt: now.Add(time.Hour),
			},
			{
				Kind:    LoginStateICloudWeb,
				Cookies: []SessionCookie{{Name: "session", Value: "web-cookie"}},
			},
		},
	}
}

func TestMailboxCreatePersistenceFailureLeavesInMemoryReconciliationGate(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-reconciliation-persist-failure"
	account, err := store.AddAccountForOwner(ownerID, "Reconciliation persist failure", "reconciliation-persist-failure@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   account.AppleID,
		LoginStates: []LoginState{{
			Kind:        LoginStateICloudWeb,
			Cookies:     []SessionCookie{{Name: "session", Value: "cookie"}},
			LastCheckOK: true,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	var providerCalls atomic.Int32
	handler.createMailboxForOwner = func(context.Context, string, string, string, string) (Mailbox, ICloudRemoteMailbox, error) {
		providerCalls.Add(1)
		return Mailbox{}, ICloudRemoteMailbox{}, errCode(
			"icloud_create_uncertain",
			"远端创建结果不确定",
			true,
		)
	}
	requests := []mailboxCreateRequest{{AccountID: account.ID, Channel: mailboxCreateChannelICloudWeb}}
	_, _, _, firstErr := handler.createMailboxesForOwnerWithChannels(context.Background(), ownerID, requests, "", "")
	if !isCodedError(firstErr, "mailbox_create_reconciliation_state_persist_failed") {
		t.Fatalf("first create error = %#v, want mailbox_create_reconciliation_state_persist_failed", firstErr)
	}
	if got := providerCalls.Load(); got != 1 {
		t.Fatalf("provider calls after first create = %d, want 1", got)
	}
	accountAfterFailure, ok := store.FindAccountByID(account.ID)
	if !ok || !accountAfterFailure.MailboxCreateReconciliationRequired {
		t.Fatalf("account reconciliation state after persistence failure = %+v, want in-memory gate", accountAfterFailure)
	}

	_, _, _, secondErr := handler.createMailboxesForOwnerWithChannels(context.Background(), ownerID, requests, "", "")
	if !isCodedError(secondErr, "mailbox_create_reconciliation_required") {
		t.Fatalf("second create error = %#v, want mailbox_create_reconciliation_required", secondErr)
	}
	if got := providerCalls.Load(); got != 1 {
		t.Fatalf("provider calls after second create = %d, want still 1", got)
	}
}

func TestRuntimeExportRequiresAdminSession(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	_, _ = registerTestUser(t, handler, "runtime-export-admin", "admin123")
	userCookie, user := registerTestUser(t, handler, "runtime-export-user", "user123")
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID: user.ID,
		DSID:    "runtime-export-sensitive-dsid",
		Cookies: []SessionCookie{{Name: "session", Value: "sensitive-cookie"}},
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export?include_messages=true", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(userCookie)
	addClosureTestCSRF(req, userCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("normal user runtime export status = %d body=%s, want 401", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "sensitive-cookie") {
		t.Fatalf("normal user runtime export leaked session data: %q", rr.Body.String())
	}
}

func TestSensitiveExportsDisableCaching(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "sensitive-export-admin", "admin123")
	mailbox, err := store.AddMailboxForOwner("", "", "Sensitive export", "sensitive-export@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	runtimeReq := httptest.NewRequest(http.MethodPost, "/api/runtime/export", strings.NewReader(`{}`))
	runtimeReq.Header.Set("Content-Type", "application/json")
	runtimeReq.AddCookie(adminCookie)
	addClosureTestCSRF(runtimeReq, adminCookie)
	runtimeRR := httptest.NewRecorder()
	handler.ServeHTTP(runtimeRR, runtimeReq)
	if runtimeRR.Code != http.StatusOK {
		t.Fatalf("runtime export status = %d body=%s", runtimeRR.Code, runtimeRR.Body.String())
	}
	if got := runtimeRR.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("runtime export Cache-Control = %q, want no-store", got)
	}

	apiReq := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis?owner_id=all", strings.NewReader(`{"format":"txt"}`))
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.AddCookie(adminCookie)
	addClosureTestCSRF(apiReq, adminCookie)
	apiRR := httptest.NewRecorder()
	handler.ServeHTTP(apiRR, apiReq)
	if apiRR.Code != http.StatusOK {
		t.Fatalf("mailbox API export status = %d body=%s", apiRR.Code, apiRR.Body.String())
	}
	if got := apiRR.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("mailbox API export Cache-Control = %q, want no-store", got)
	}
	if !strings.Contains(apiRR.Body.String(), mailbox.Email) {
		t.Fatalf("mailbox API export body = %q, want %q", apiRR.Body.String(), mailbox.Email)
	}
}

func TestBindUnboundMailboxToOwnedAccount(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "bind-admin", "admin123")
	userCookie, user := registerTestUser(t, handler, "bind-user", "user123")
	_, otherUser := registerTestUser(t, handler, "bind-other", "other123")

	account, err := store.AddAccountForOwner(user.ID, "Bind account", "bind@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	otherAccount, err := store.AddAccountForOwner(otherUser.ID, "Other account", "other-bind@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(user.ID, "", "Legacy unbound", "legacy-bind@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+mailbox.ID+"/bind", strings.NewReader(fmt.Sprintf(`{"account_id":%q}`, account.ID)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(userCookie)
	addClosureTestCSRF(req, userCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("bind mailbox status = %d body=%s", rr.Code, rr.Body.String())
	}
	bound, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || bound.AccountID != account.ID {
		t.Fatalf("bound mailbox = %+v ok=%t, want account %q", bound, ok, account.ID)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+mailbox.ID+"/bind", strings.NewReader(fmt.Sprintf(`{"account_id":%q}`, otherAccount.ID)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(userCookie)
	addClosureTestCSRF(req, userCookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-owner bind status = %d body=%s, want 404", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+mailbox.ID+"/bind", strings.NewReader(fmt.Sprintf(`{"account_id":%q}`, account.ID)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(userCookie)
	addClosureTestCSRF(req, userCookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("idempotent bind status = %d body=%s, want 200", rr.Code, rr.Body.String())
	}

	otherMailbox, err := store.AddMailboxForOwner(otherUser.ID, "", "Other legacy unbound", "other-legacy-bind@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+otherMailbox.ID+"/bind", strings.NewReader(fmt.Sprintf(`{"account_id":%q}`, otherAccount.ID)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin cross-owner bind status = %d body=%s, want 200", rr.Code, rr.Body.String())
	}
	bound, ok = store.FindMailboxByID(otherMailbox.ID)
	if !ok || bound.AccountID != otherAccount.ID {
		t.Fatalf("admin-bound mailbox = %+v ok=%t, want account %q", bound, ok, otherAccount.ID)
	}

	legacyAccountBoundMailbox, err := store.AddMailboxForOwner("", account.ID, "Legacy account-bound", "legacy-account-bound@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+legacyAccountBoundMailbox.ID+"/bind", strings.NewReader(fmt.Sprintf(`{"account_id":%q}`, account.ID)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin legacy ownership repair status = %d body=%s", rr.Code, rr.Body.String())
	}
	bound, ok = store.FindMailboxByID(legacyAccountBoundMailbox.ID)
	if !ok || bound.AccountID != account.ID || bound.OwnerID != user.ID {
		t.Fatalf("admin-repaired mailbox = %+v ok=%t, want account %q and owner %q", bound, ok, account.ID, user.ID)
	}
}

func TestMailboxCodeAcceptsProjectAsKeywordAlias(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	mailbox, err := store.AddMailboxForOwner("", "", "Project alias", "project-alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := store.AddMessage(mailbox.ID, "Your ChatGPT code", "noreply@example.com", "Use 424242 to continue.", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "Your OpenAI code", "noreply@example.com", "Use 111111 to continue.", now); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+url.QueryEscape(mailbox.APIToken)+"&project=ChatGPT&cache=1&peek=1",
		nil,
	)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("project code status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "424242" {
		t.Fatalf("project code response = %+v, want ChatGPT code", body)
	}
}

func TestAppleAuthPendingStoreGetClonesSessionState(t *testing.T) {
	store := newAppleAuthPendingStore()
	pending, err := store.putForOwner(&appleAuthSession{
		AppleID:        "pending-clone@example.com",
		TwoFactorPhone: json.RawMessage(`{"id":"phone-1"}`),
		Cookies: []SessionCookie{{
			Name:  "session",
			Value: "original-cookie",
		}},
	}, "owner-pending-clone")
	if err != nil {
		t.Fatal(err)
	}

	got, ok := store.get(pending.ID)
	if !ok || got.Session == nil {
		t.Fatalf("pending = %+v, ok=%t, want stored session", got, ok)
	}
	got.Session.Cookies[0].Value = "mutated-cookie"
	got.Session.TwoFactorPhone[0] = '{'

	again, ok := store.get(pending.ID)
	if !ok || again.Session == nil {
		t.Fatalf("pending after mutation = %+v, ok=%t", again, ok)
	}
	if again.Session.Cookies[0].Value != "original-cookie" {
		t.Fatalf("stored cookie = %q, want original-cookie", again.Session.Cookies[0].Value)
	}
	if string(again.Session.TwoFactorPhone) != `{"id":"phone-1"}` {
		t.Fatalf("stored phone metadata = %q, want original JSON", again.Session.TwoFactorPhone)
	}
}

func TestLatestMailboxCodeForWaiterRejectsMailboxDisabledDuringWait(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "code-disabled", "code-disabled@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "OpenAI verification code", "noreply@example.com", "Use 123456 to continue.", time.Now()); err != nil {
		t.Fatal(err)
	}

	server := NewServer(Config{}, store, discardLogger()).(*Server)
	waiter := &mailboxCodeWaiter{
		mailboxID: mailbox.ID,
		after:     time.Now().Add(-time.Minute),
		keyword:   "OpenAI",
	}
	if _, code, ok := server.latestMailboxCodeForWaiter(waiter); !ok || code != "123456" {
		t.Fatalf("active mailbox code = %q, ok=%t, want 123456 true", code, ok)
	}

	disabled := false
	if _, err := store.SetMailboxStatus(mailbox.ID, &disabled, &disabled, StatusDisabled, "disabled during code wait"); err != nil {
		t.Fatal(err)
	}
	if _, code, ok := server.latestMailboxCodeForWaiter(waiter); ok {
		t.Fatalf("disabled mailbox returned code %q, want no code", code)
	}
}

func TestAppleProtocol2FAUpdatesPendingSessionAfterProviderFailure(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "pending-refresh-after-failure", "multi123")
	pending, err := handler.icloudProtocolLogins.putForOwner(&appleAuthSession{
		AppleID: "pending-refresh-after-failure@example.com",
		Scnt:    "stale-scnt",
	}, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	handler.icloudProtocolLogins.setLoginTarget(pending.ID, user.ID, "")
	handler.submitICloudProtocol2FA = func(ctx context.Context, pending appleAuthPending, code string) (ICloudSession, error) {
		if pending.Session == nil {
			t.Fatal("provider received nil pending session")
		}
		pending.Session.Scnt = "fresh-scnt-after-failure"
		return ICloudSession{}, errors.New("provider rejected this code")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/2fa", strings.NewReader(
		fmt.Sprintf(`{"pending_id":%q,"code":"123456"}`, pending.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("2FA status = %d body=%s, want 502", rr.Code, rr.Body.String())
	}

	refreshed, ok := handler.icloudProtocolLogins.get(pending.ID)
	if !ok || refreshed.Session == nil {
		t.Fatalf("pending after provider failure = %+v, ok=%t, want retained pending session", refreshed, ok)
	}
	if refreshed.Session.Scnt != "fresh-scnt-after-failure" {
		t.Fatalf("pending scnt = %q, want fresh-scnt-after-failure", refreshed.Session.Scnt)
	}
}

func TestMergeICloudSessionKeepsExplicitFailedCheckResult(t *testing.T) {
	checkedAt := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	existing := ICloudSession{
		LastCheckedAt:     checkedAt.Add(-time.Hour),
		LastCheckOK:       true,
		LastStatusMessage: "登录态正常",
	}
	incoming := ICloudSession{
		LastCheckedAt:     checkedAt,
		LastCheckOK:       false,
		LastStatusMessage: "登录态异常",
	}

	merged := mergeICloudSession(existing, incoming)
	if !merged.LastCheckedAt.Equal(checkedAt) || merged.LastCheckOK {
		t.Fatalf("merged check result = checked_at:%v ok:%t, want explicit failed result at %v", merged.LastCheckedAt, merged.LastCheckOK, checkedAt)
	}
	if merged.LastStatusMessage != incoming.LastStatusMessage {
		t.Fatalf("merged status message = %q, want %q", merged.LastStatusMessage, incoming.LastStatusMessage)
	}

	partial := mergeICloudSession(existing, ICloudSession{})
	if !partial.LastCheckedAt.Equal(existing.LastCheckedAt) || !partial.LastCheckOK {
		t.Fatalf("partial merge lost existing healthy result: checked_at:%v ok:%t", partial.LastCheckedAt, partial.LastCheckOK)
	}
}

func TestMergeICloudSessionAppliesAuthoritativeCapabilityDowngrade(t *testing.T) {
	existing := ICloudSession{
		IsICloudPlus:              true,
		CanCreateHME:              true,
		CapabilitiesAuthoritative: true,
	}
	incoming := ICloudSession{
		IsICloudPlus:              false,
		CanCreateHME:              false,
		CapabilitiesAuthoritative: true,
	}

	merged := mergeICloudSession(existing, incoming)
	if merged.IsICloudPlus || merged.CanCreateHME {
		t.Fatalf("authoritative capability downgrade was lost: %+v", merged)
	}
	if !merged.CapabilitiesAuthoritative {
		t.Fatal("authoritative capability marker was lost")
	}
}

func TestMergeICloudSessionPreservesNonAuthoritativeCapabilitySnapshot(t *testing.T) {
	existing := ICloudSession{
		IsICloudPlus:              true,
		CanCreateHME:              true,
		CapabilitiesAuthoritative: true,
	}
	incoming := ICloudSession{
		IsICloudPlus: false,
		CanCreateHME: false,
	}

	merged := mergeICloudSession(existing, incoming)
	if !merged.IsICloudPlus || !merged.CanCreateHME {
		t.Fatalf("non-authoritative partial session cleared capabilities: %+v", merged)
	}
}

func TestSaveICloudSessionDoesNotMergeDifferentExplicitAccounts(t *testing.T) {
	store := newTestStore(t)
	for _, session := range []ICloudSession{
		{OwnerID: "owner-same-apple", AccountID: "account-a", AppleID: "same@example.com"},
		{OwnerID: "owner-same-apple", AccountID: "account-b", AppleID: "same@example.com"},
	} {
		if err := store.SaveICloudSessionForOwner(session.OwnerID, session); err != nil {
			t.Fatal(err)
		}
	}

	sessions := store.ICloudSessionsForOwner("owner-same-apple")
	if len(sessions) != 2 {
		t.Fatalf("sessions = %+v, want two explicit accounts kept separate", sessions)
	}
}

func TestSessionForIMAPSaveRejectsAmbiguousAccountEmail(t *testing.T) {
	store := newTestStore(t)
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-ambiguous-imap-save"
	accountOne, err := store.AddAccountForOwner(ownerID, "One", "one@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	accountTwo, err := store.AddAccountForOwner(ownerID, "Two", "two@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []Account{accountOne, accountTwo} {
		session := testIMAPSession(ownerID, account.ID, "shared@icloud.com")
		session.AppleID = account.AppleID
		if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
			t.Fatal(err)
		}
	}

	_, err = server.sessionForIMAPSave(ownerID, "", "shared@icloud.com")
	if !isCodedError(err, "imap_account_ambiguous") {
		t.Fatalf("ambiguous IMAP save error = %#v, want imap_account_ambiguous", err)
	}
}

func TestLegacyOwnerSessionIsMigratedIntoOwnerScopedSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	data := []byte(`{
		"next_id": 1,
		"icloud_session": {
			"browser_key": "legacy-owner",
			"account_id": "legacy-account",
			"apple_id": "legacy@example.com",
			"cookies": [{"name": "session", "value": "cookie"}]
		}
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner("legacy-owner")
	if len(sessions) != 1 || sessions[0].AccountID != "legacy-account" {
		t.Fatalf("owner sessions = %+v, want migrated legacy owner session", sessions)
	}
	if store.SnapshotForOwner("legacy-owner").ICloudSession == nil {
		t.Fatal("owner snapshot lost migrated legacy session")
	}
	if store.Snapshot().ICloudSession != nil {
		t.Fatal("owner-scoped legacy session remained in global legacy slot")
	}
}

func TestLegacyGlobalSessionIsMigratedIntoTypedSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	data := []byte(`{
		"next_id": 1,
		"icloud_session": {
			"account_id": "global-account",
			"apple_id": "global@example.com",
			"cookies": [{"name": "session", "value": "cookie"}]
		}
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner("")
	if len(sessions) != 1 || sessions[0].AccountID != "global-account" {
		t.Fatalf("global sessions = %+v, want migrated typed session", sessions)
	}
	if store.Snapshot().ICloudSession != nil {
		t.Fatal("global legacy session remained in root slot after migration")
	}
}

func TestLegacyMigrationsRunTogether(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	data := []byte(`{
		"next_id": 3,
		"accounts": [{"id": "legacy-account", "browser_key": "legacy-owner", "apple_id": "legacy@example.com"}],
		"mailboxes": [{"id": "legacy-mailbox", "browser_key": "legacy-owner", "email": "legacy-alias@icloud.com"}],
		"icloud_session": {
			"browser_key": "legacy-owner",
			"account_id": "legacy-account",
			"apple_id": "legacy@example.com",
			"cookies": [{"name": "session", "value": "cookie"}]
		}
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	if len(state.ICloudSessions) != 1 || state.ICloudSession != nil {
		t.Fatalf("migrated sessions = %+v legacy=%+v", state.ICloudSessions, state.ICloudSession)
	}
	if len(state.Mailboxes) != 1 || state.Mailboxes[0].AccountID != "legacy-account" {
		t.Fatalf("migrated mailboxes = %+v", state.Mailboxes)
	}
}

func TestLegacyRootSessionMergesIntoBoundSession(t *testing.T) {
	store := newTestStore(t)
	ownerID := "legacy-root-merge"
	legacy := ICloudSession{
		OwnerID: ownerID,
		AppleID: "legacy-merge@example.com",
		DSID:    "legacy-dsid",
		Cookies: []SessionCookie{{Name: "legacy", Value: "cookie"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Host:    "www.icloud.com.cn",
			Cookies: []SessionCookie{{Name: "legacy", Value: "cookie"}},
		}},
	}
	store.mu.Lock()
	store.state.ICloudSession = &legacy
	store.mu.Unlock()

	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID: ownerID,
		AppleID: "legacy-merge@example.com",
		DSID:    "legacy-dsid",
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Host:   "appleid.apple.com",
			Scnt:   "scnt",
			APIKey: "api-key",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %+v, want legacy root merged into bound session", sessions)
	}
	got := sessions[0]
	if got.AccountID == "" {
		t.Fatalf("merged session lost bound account id: %+v", got)
	}
	if !hasLoginStateKind(got.LoginStates, LoginStateICloudWeb) || !hasLoginStateKind(got.LoginStates, LoginStateAppleAccount) {
		t.Fatalf("merged session lost one of the login states: %+v", got.LoginStates)
	}
}

func TestDeleteUserRemovesOwnedCreateSettings(t *testing.T) {
	store := newTestStore(t)
	_, err := store.CreateUser("admin-settings-cleanup", "admin123")
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateUser("user-settings-cleanup", "user123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveCreateSettingsForOwner(user.ID, CreateSettings{
		Label: "owned settings",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeleteUser(user.ID); err != nil {
		t.Fatal(err)
	}
	for _, settings := range store.Snapshot().CreateSettings {
		if settings.OwnerID == user.ID {
			t.Fatalf("owned create settings remain after user deletion: %+v", settings)
		}
	}
}

func TestCreateReportsEveryExplicitAccountWithoutSession(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	accountOne, err := store.AddAccountForOwner("owner-create-missing", "Ready", "ready@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	accountTwo, err := store.AddAccountForOwner("owner-create-missing", "Missing", "missing@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner("owner-create-missing", ICloudSession{
		AccountID: accountOne.ID,
		AppleID:   accountOne.AppleID,
	}); err != nil {
		t.Fatal(err)
	}
	handler.createMailboxForOwner = func(_ context.Context, ownerID, accountID, label, _ string) (Mailbox, ICloudRemoteMailbox, error) {
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, "created@icloud.com")
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{
			AnonymousID: "created-remote",
			Email:       mailbox.Email,
			IsActive:    true,
			Origin:      "APPLE_ACCOUNT",
		}, nil
	}

	mailboxes, _, failures, err := handler.createMailboxesForOwnerWithChannels(
		context.Background(),
		"owner-create-missing",
		[]mailboxCreateRequest{{AccountID: accountOne.ID}, {AccountID: accountTwo.ID}},
		"",
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(mailboxes) != 1 || mailboxes[0].AccountID != accountOne.ID {
		t.Fatalf("created mailboxes = %+v, want only ready account", mailboxes)
	}
	if len(failures) != 1 || failures[0].AccountID != accountTwo.ID || failures[0].AppleID != accountTwo.AppleID {
		t.Fatalf("missing-account failures = %+v, want account %s", failures, accountTwo.ID)
	}
}

func TestAutoMailboxCreateDoesNotFallbackAfterAppleAccountTransportFailure(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var completeAttempts atomic.Int32
	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			_, _ = w.Write([]byte(`{"emailAddress":"uncertain@icloud.com"}`))
		case "PUT /account/manage/email/private/add/complete":
			completeAttempts.Add(1)
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("test server does not support hijacking")
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
		case "GET /account/manage/email/private":
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		case "GET /account/manage/gs/ws/token":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "GET /account/manage/section/privacy":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html>privacy</html>`))
		case "GET /bootstrap/portal":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	var webCalls atomic.Int32
	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webCalls.Add(1)
		t.Fatalf("iCloud Web fallback was called after an uncertain Apple Account create: %s %s", r.Method, r.URL.Path)
	}))
	defer webServer.Close()

	now := time.Now()
	session := ICloudSession{
		OwnerID:            "owner-create-uncertain",
		AccountID:          "account-create-uncertain",
		AppleID:            "create-uncertain@example.com",
		DSID:               "create-uncertain-dsid",
		PremiumMailBaseURL: webServer.URL,
		Host:               "www.icloud.com",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "session", Value: "web-cookie", Domain: "127.0.0.1", Path: "/"}},
		LoginStates: []LoginState{
			{
				Kind:            LoginStateAppleAccount,
				Host:            "appleid.apple.com",
				Scnt:            "scnt",
				APIKey:          "apple-api-key",
				LastCheckedAt:   now,
				LastCheckOK:     true,
				ManageExpiresAt: now.Add(time.Hour),
			},
			{
				Kind:    LoginStateICloudWeb,
				Host:    "www.icloud.com",
				Cookies: []SessionCookie{{Name: "session", Value: "web-cookie", Domain: "127.0.0.1", Path: "/"}},
			},
		},
	}
	handler := NewServer(Config{}, newTestStore(t), discardLogger()).(*Server)
	remote, err := handler.createICloudMailboxRemoteWithChannel(
		context.Background(),
		session.OwnerID,
		session,
		"UNCERTAIN",
		"",
		mailboxCreateChannelAuto,
	)
	if err == nil {
		t.Fatal("auto create succeeded after Apple Account completion transport failure")
	}
	if completeAttempts.Load() == 0 {
		t.Fatal("Apple Account completion request was not attempted")
	}
	if webCalls.Load() != 0 {
		t.Fatalf("iCloud Web fallback calls = %d, want 0", webCalls.Load())
	}
	if remote.AnonymousID != "" || remote.Email != "" {
		t.Fatalf("uncertain create returned a usable remote mailbox: %+v", remote)
	}
}

func appleAccountReadyCreateSession() ICloudSession {
	now := time.Now()
	return ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Host:            "appleid.apple.com",
			Scnt:            "scnt",
			APIKey:          "apple-api-key",
			LastCheckedAt:   now,
			LastCheckOK:     true,
			ManageExpiresAt: now.Add(time.Hour),
		}},
	}
}

func TestAppleAccountCreateRecoversFromCompleteTransportFailureUsingMailboxList(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var completeAttempts atomic.Int32
	var listAttempts atomic.Int32
	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			_, _ = w.Write([]byte(`{"emailAddress":"recovered@icloud.com"}`))
		case "PUT /account/manage/email/private/add/complete":
			completeAttempts.Add(1)
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("test server does not support hijacking")
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
		case "GET /account/manage/email/private":
			listAttempts.Add(1)
			_, _ = w.Write([]byte(`{
				"success": true,
				"result": {
					"hmeEmails": [
						{"id":"recovered-id","emailAddress":"recovered@icloud.com","label":"LAB","isActive":true}
					]
				}
			}`))
		case "GET /account/manage/email/private/recovered-id.em":
			_, _ = w.Write([]byte(`{"emailAddress":"recovered@icloud.com","id":"recovered-id","label":"LAB","isActive":true}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	remote, _, err := (&ICloudClient{client: appleServer.Client()}).CreatePrivacyMailboxWithAppleAccount(
		context.Background(),
		appleAccountReadyCreateSession(),
		"",
		"LAB",
		"note",
	)
	if err != nil {
		t.Fatalf("create after complete transport failure = %v, want recovered mailbox", err)
	}
	if completeAttempts.Load() == 0 {
		t.Fatal("Apple Account completion request was not attempted")
	}
	if listAttempts.Load() == 0 {
		t.Fatal("Apple Account mailbox list was not used to confirm the completed mailbox")
	}
	if remote.Email != "recovered@icloud.com" || remote.AnonymousID != "recovered-id" {
		t.Fatalf("recovered mailbox = %+v, want recovered@icloud.com / recovered-id", remote)
	}
}

func TestAppleAccountCreateParsesWrappedCompleteResult(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			_, _ = w.Write([]byte(`{"success":true,"result":{"emailAddress":"wrapped@icloud.com"}}`))
		case "PUT /account/manage/email/private/add/complete":
			_, _ = w.Write([]byte(`{"success":true,"result":{"emailAddress":"wrapped@icloud.com","id":"wrapped-id","label":"LAB","note":"note","active":true}}`))
		case "GET /account/manage/email/private/wrapped-id.em":
			_, _ = w.Write([]byte(`{"success":true,"result":{"emailAddress":"wrapped@icloud.com","id":"wrapped-id","forwardToEmail":"main@example.com","active":true}}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	remote, _, err := (&ICloudClient{client: appleServer.Client()}).CreatePrivacyMailboxWithAppleAccount(
		context.Background(),
		appleAccountReadyCreateSession(),
		"",
		"LAB",
		"note",
	)
	if err != nil {
		t.Fatalf("wrapped complete create = %v", err)
	}
	if remote.Email != "wrapped@icloud.com" || remote.AnonymousID != "wrapped-id" {
		t.Fatalf("wrapped mailbox = %+v, want wrapped@icloud.com / wrapped-id", remote)
	}
	if remote.ForwardToEmail != "main@example.com" {
		t.Fatalf("wrapped mailbox forward = %q, want main@example.com", remote.ForwardToEmail)
	}
}

func TestAppleAccountCreateRetriesCompleteAfter401WithoutRegenerating(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var generateAttempts atomic.Int32
	var completeAttempts atomic.Int32
	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			generateAttempts.Add(1)
			_, _ = w.Write([]byte(`{"emailAddress":"retry-complete@icloud.com"}`))
		case "PUT /account/manage/email/private/add/complete":
			if completeAttempts.Add(1) == 1 {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("<html>unauthorized</html>"))
				return
			}
			_, _ = w.Write([]byte(`{"emailAddress":"retry-complete@icloud.com","id":"retry-id","label":"LAB","note":"note","active":true}`))
		case "GET /account/manage/gs/ws/token":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			_, _ = w.Write([]byte(`{"apiKey":"apple-api-key"}`))
		case "GET /account/manage/email/private/retry-id.em":
			_, _ = w.Write([]byte(`{"emailAddress":"retry-complete@icloud.com","id":"retry-id","active":true}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	remote, _, err := (&ICloudClient{client: appleServer.Client()}).CreatePrivacyMailboxWithAppleAccount(
		context.Background(),
		appleAccountReadyCreateSession(),
		"",
		"LAB",
		"note",
	)
	if err != nil {
		t.Fatalf("complete 401 retry create = %v", err)
	}
	if generateAttempts.Load() != 1 {
		t.Fatalf("generate attempts = %d, want 1 so the first candidate is not discarded", generateAttempts.Load())
	}
	if completeAttempts.Load() != 2 {
		t.Fatalf("complete attempts = %d, want 2 after a 401 rescue", completeAttempts.Load())
	}
	if remote.Email != "retry-complete@icloud.com" || remote.AnonymousID != "retry-id" {
		t.Fatalf("retried mailbox = %+v, want retry-complete@icloud.com / retry-id", remote)
	}
}

func TestRemoteDeleteIsIdempotentAfterPreviousSuccess(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-idempotent", ICloudRemoteMailbox{
		AnonymousID: "remote-idempotent",
		Origin:      "APPLE_ACCOUNT",
		Email:       "idempotent@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMailboxRemoteDeleteSucceeded(mailbox.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	mailbox, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox not found after remote delete state update")
	}
	called := false
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		called = true
		return errors.New("remote delete should not be repeated")
	}
	if err := handler.deleteRemoteMailboxForRequest(context.Background(), mailbox); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("remote delete was repeated after a recorded success")
	}
}

func TestRemoteDeleteRefreshesCurrentMailboxStateBeforeProvider(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-refresh", ICloudRemoteMailbox{
		AnonymousID: "remote-refresh",
		Origin:      "APPLE_ACCOUNT",
		Email:       "refresh@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMailboxRemoteDeleteSucceeded(mailbox.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	mailbox.RemoteDeleteStatus = ""
	called := false
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		called = true
		return errors.New("remote delete should not be repeated")
	}
	if err := handler.deleteRemoteMailboxForRequest(context.Background(), mailbox); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("remote delete used stale mailbox state after a recorded success")
	}
}

func TestRemoteDeleteTreatsBlankOriginAsLegacyICloudWeb(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-blank-origin"
	accountID := "account-blank-origin"
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"timestamp":1,"result":{}}`))
	}))
	defer ts.Close()
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AccountID:          accountID,
		AppleID:            "blank-origin@example.com",
		DSID:               "blank-origin-dsid",
		ClientID:           "blank-origin-client",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		PremiumMailBaseURL: ts.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Host:    "www.icloud.com.cn",
			Cookies: []SessionCookie{{Name: "session", Value: "cookie"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote(ownerID, accountID, ICloudRemoteMailbox{
		AnonymousID: "blank-origin-remote",
		Email:       "blank-origin@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(mailbox.RemoteOrigin) != "" {
		t.Fatalf("fixture RemoteOrigin = %q, want blank", mailbox.RemoteOrigin)
	}
	if err := handler.deleteICloudMailboxRemote(context.Background(), mailbox); err != nil {
		t.Fatalf("blank-origin remote delete error = %#v, want success via legacy iCloud web", err)
	}
	if got, want := strings.Join(paths, "\n"), "POST /v1/hme/deactivate\nPOST /v1/hme/delete"; got != want {
		t.Fatalf("blank-origin remote delete paths = %q, want %q", got, want)
	}
}

func TestDeleteMailboxRouteTreatsBlankOriginAsLegacyICloudWeb(t *testing.T) {
	var paths []string
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
	}))
	defer remoteServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "blank-origin-delete", "admin123")
	account, err := store.AddAccountForOwner("", "Blank origin", "blank-origin@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSession(ICloudSession{
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "blank-origin-dsid",
		ClientID:           "blank-origin-client",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		PremiumMailBaseURL: remoteServer.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote("", account.ID, ICloudRemoteMailbox{
		AnonymousID: "blank-origin-route-id",
		Email:       "blank-origin-route@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(mailbox.RemoteOrigin) != "" {
		t.Fatalf("fixture RemoteOrigin = %q, want blank", mailbox.RemoteOrigin)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/mailboxes/"+mailbox.ID+"?delete_remote=1", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", rr.Code, rr.Body.String())
	}
	if got, want := strings.Join(paths, "\n"), "POST /v1/hme/deactivate\nPOST /v1/hme/delete"; got != want {
		t.Fatalf("blank-origin route paths = %q, want %q", got, want)
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("local mailbox record remains after blank-origin remote delete")
	}
}

func TestAppleAccountRemoteDeletePersistsRefreshedStateWhenDeleteFails(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("scnt", "refreshed-token-scnt")
			http.SetCookie(w, &http.Cookie{Name: "refreshed-token-cookie", Value: "1", Path: "/"})
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "refreshed-token-scnt" {
				t.Fatalf("manage scnt = %q, want refreshed-token-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "refreshed-scnt")
			http.SetCookie(w, &http.Cookie{Name: "refreshed-cookie", Value: "1", Path: "/"})
			_, _ = w.Write([]byte(`{"apiKey":"refreshed-api-key"}`))
		case "DELETE /account/manage/email/private/delete-refresh/remove":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"temporary provider failure"}`))
		default:
			t.Fatalf("unexpected request = %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-delete-refresh"
	account, err := store.AddAccountForOwner(ownerID, "Delete refresh", "delete-refresh@example.com", "")
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
			Scnt:            "initial-scnt",
			APIKey:          "api-key",
			LastCheckedAt:   now.Add(-time.Hour),
			ManageExpiresAt: now.Add(-time.Minute),
			LastCheckOK:     true,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote(ownerID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "delete-refresh",
		Origin:      mailboxRemoteOriginAppleAccount,
		Email:       "delete-refresh@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	err = handler.deleteICloudMailboxRemote(context.Background(), mailbox)
	if err == nil {
		t.Fatal("deleteICloudMailboxRemote returned nil for provider failure")
	}
	session, ok := store.ICloudSessionForOwnerAccount(ownerID, account.ID)
	if !ok {
		t.Fatal("Apple Account session disappeared after failed remote delete")
	}
	state, ok := appleAccountLoginState(session)
	if !ok {
		t.Fatal("Apple Account login state disappeared after failed remote delete")
	}
	if state.Scnt != "refreshed-scnt" {
		t.Fatalf("saved scnt = %q, want refreshed-scnt", state.Scnt)
	}
	if state.APIKey != "refreshed-api-key" {
		t.Fatalf("saved api key = %q, want refreshed-api-key", state.APIKey)
	}
	var hasRefreshedCookie bool
	for _, cookie := range state.Cookies {
		if cookie.Name == "refreshed-cookie" && cookie.Value == "1" {
			hasRefreshedCookie = true
			break
		}
	}
	if !hasRefreshedCookie {
		t.Fatalf("saved cookies = %+v, want refreshed-cookie", state.Cookies)
	}
}

func TestRemoteDeleteSerializesConcurrentRequestsForSameMailbox(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-concurrent", ICloudRemoteMailbox{
		AnonymousID: "remote-concurrent",
		Origin:      "APPLE_ACCOUNT",
		Email:       "concurrent@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	saveTestAppleAccountSession(t, store, "", "account-concurrent", "concurrent@example.com")

	var calls atomic.Int32
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		if calls.Add(1) == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		return nil
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- handler.deleteRemoteMailboxForRequest(context.Background(), mailbox)
		}()
	}
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first remote delete did not start")
	}
	time.Sleep(150 * time.Millisecond)
	if got := calls.Load(); got > 1 {
		close(releaseFirst)
		wg.Wait()
		t.Fatalf("provider calls before first completed = %d, want 1", got)
	}
	close(releaseFirst)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}
}

func TestRemoteDeleteFailureReportsStatePersistenceError(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-persist-failure", ICloudRemoteMailbox{
		AnonymousID: "remote-persist-failure",
		Origin:      "APPLE_ACCOUNT",
		Email:       "persist-failure@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	saveTestAppleAccountSession(t, store, "", "account-persist-failure", "persist-failure@example.com")
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		store.path = badPath
		return errors.New("provider delete failed")
	}

	err = handler.deleteRemoteMailboxForRequest(context.Background(), mailbox)
	if !isCodedError(err, "mailbox_remote_delete_state_persist_failed") {
		t.Fatalf("remote delete error = %#v, want mailbox_remote_delete_state_persist_failed", err)
	}
	if strings.Contains(err.Error(), "provider delete failed") {
		t.Fatalf("remote delete error leaked provider detail: %q", err)
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); !ok {
		t.Fatal("mailbox was removed after provider and state persistence failures")
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after provider and state persistence failures")
	}
	if current.RemoteDeleteStatus != "unknown" || current.RemoteDeleteError == "" || strings.Contains(current.RemoteDeleteError, "provider delete failed") || !current.ICloudActive || current.Status != StatusAvailable {
		t.Fatalf("mailbox after provider and state persistence failures = %+v, want an uncertain reusable state without provider detail", current)
	}
}

func TestBeginRemoteDeleteRollsBackInMemoryStateWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-begin-persist-failure", ICloudRemoteMailbox{
		AnonymousID: "remote-begin-persist-failure",
		Origin:      "APPLE_ACCOUNT",
		Email:       "begin-persist-failure@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	err = store.BeginMailboxRemoteDelete(mailbox.ID, time.Now())
	if err == nil {
		t.Fatal("BeginMailboxRemoteDelete succeeded with an invalid state path")
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after persistence failure")
	}
	if current.RemoteDeleteStatus != "" || !current.RemoteDeleteAt.IsZero() || current.RemoteDeleteError != "" {
		t.Fatalf("remote delete state was left pending after persistence failure: %+v", current)
	}
}

func TestRemoteDeleteSuccessReportsStatePersistenceFailure(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-delete-success-persist", ICloudRemoteMailbox{
		AnonymousID: "remote-delete-success-persist",
		Origin:      "APPLE_ACCOUNT",
		Email:       "delete-success-persist@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	saveTestAppleAccountSession(t, store, "", "account-delete-success-persist", "delete-success-persist@example.com")
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		store.path = badPath
		return nil
	}

	err = handler.deleteRemoteMailboxForRequest(context.Background(), mailbox)
	if !isCodedError(err, "mailbox_remote_delete_state_persist_failed") {
		t.Fatalf("remote delete success error = %#v, want mailbox_remote_delete_state_persist_failed", err)
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after remote delete state persistence failure")
	}
	if current.RemoteDeleteStatus != "unknown" || !strings.Contains(current.RemoteDeleteError, "远端删除已成功") || !current.ICloudActive || current.Status != StatusAvailable {
		t.Fatalf("mailbox after successful remote delete persistence failure = %+v, want an uncertain state", current)
	}
}

func TestMarkRemoteDeleteFailedRollsBackInMemoryStateWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-mark-failed-persist", ICloudRemoteMailbox{
		AnonymousID: "remote-mark-failed-persist",
		Origin:      "APPLE_ACCOUNT",
		Email:       "mark-failed-persist@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginMailboxRemoteDelete(mailbox.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	err = store.MarkMailboxRemoteDeleteFailed(mailbox.ID, "provider delete failed", time.Now())
	if err == nil {
		t.Fatal("MarkMailboxRemoteDeleteFailed succeeded with an invalid state path")
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after failed remote-delete state persistence")
	}
	if current.RemoteDeleteStatus != "unknown" || !strings.Contains(current.RemoteDeleteError, "provider delete failed") || !current.ICloudActive || current.Status != StatusAvailable {
		t.Fatalf("mailbox after failed remote-delete state persistence = %+v, want an uncertain state", current)
	}
}

func TestMarkRemoteDeleteSucceededRollsBackInMemoryStateWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-mark-succeeded-persist", ICloudRemoteMailbox{
		AnonymousID: "remote-mark-succeeded-persist",
		Origin:      "APPLE_ACCOUNT",
		Email:       "mark-succeeded-persist@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginMailboxRemoteDelete(mailbox.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	err = store.MarkMailboxRemoteDeleteSucceeded(mailbox.ID, time.Now())
	if err == nil {
		t.Fatal("MarkMailboxRemoteDeleteSucceeded succeeded with an invalid state path")
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after successful remote-delete state persistence")
	}
	if current.RemoteDeleteStatus != "unknown" || !strings.Contains(current.RemoteDeleteError, "远端删除已成功") || !current.ICloudActive || current.Status != StatusAvailable {
		t.Fatalf("mailbox after successful remote-delete state persistence = %+v, want an uncertain state", current)
	}
}

func TestUnknownRemoteDeleteMailboxCannotBeClaimed(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-unknown-claim", ICloudRemoteMailbox{
		AnonymousID: "remote-unknown-claim",
		Origin:      "APPLE_ACCOUNT",
		Email:       "unknown-claim@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginMailboxRemoteDelete(mailbox.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Simulate a process interruption after the pending state was persisted.
	reloaded, err := NewFileStore(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	current, ok := reloaded.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing after reload")
	}
	if current.RemoteDeleteStatus != "unknown" {
		t.Fatalf("remote delete status after reload = %q, want unknown", current.RemoteDeleteStatus)
	}
	if _, err := reloaded.ClaimAvailableMailbox("should-not-claim"); !isCodedError(err, "no_available_mailbox") {
		t.Fatalf("claim unknown remote-delete mailbox error = %#v, want no_available_mailbox", err)
	}
}

func TestSetPathRollsBackWhenTargetStateCannotBePersisted(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwner("", "original", "original@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	originalPath := store.Path()
	originalState := store.Snapshot()

	target := newTestStore(t)
	targetPath := target.Path()
	if err := os.Mkdir(targetPath+".tmp", 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := store.SetPath(targetPath); err == nil {
		t.Fatal("SetPath succeeded although the target temporary path is a directory")
	}
	if store.Path() != originalPath {
		t.Fatalf("store path after failed SetPath = %q, want %q", store.Path(), originalPath)
	}
	current := store.Snapshot()
	if len(current.Accounts) != len(originalState.Accounts) || len(current.Accounts) != 1 || current.Accounts[0].ID != account.ID {
		t.Fatalf("state after failed SetPath = %+v, want original state", current)
	}
}

func TestDeleteMailboxRollsBackInMemoryStateWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("", "", "DELETE-PERSIST-FAILURE", "delete-persist-failure@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertMessage(mailbox.ID, "", "test", "subject", "from@example.com", "body", time.Now()); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	err = store.DeleteMailbox(mailbox.ID)
	if !isCodedError(err, "mailbox_delete_persist_failed") {
		t.Fatalf("DeleteMailbox error = %#v, want mailbox_delete_persist_failed", err)
	}
	_, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared from memory after persistence failure")
	}
	if messages := store.MessagesForMailbox(mailbox.ID); len(messages) != 1 {
		t.Fatalf("messages after persistence failure = %d, want 1", len(messages))
	}
}

func TestAddMailboxRollsBackInMemoryStateWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	_, err := store.AddMailboxForOwner("", "", "CREATE-PERSIST-FAILURE", "create-persist-failure@icloud.com")
	if !isCodedError(err, "mailbox_create_persist_failed") {
		t.Fatalf("AddMailboxForOwner error = %#v, want mailbox_create_persist_failed", err)
	}
	for _, mailbox := range store.Snapshot().Mailboxes {
		if strings.EqualFold(mailbox.Email, "create-persist-failure@icloud.com") {
			t.Fatal("mailbox remained in memory after mailbox persistence failure")
		}
	}
}

func TestUpsertMailboxFromRemoteRollsBackWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-upsert-persist", ICloudRemoteMailbox{
		AnonymousID: "upsert-persist-remote",
		Origin:      "ICLOUD_WEB",
		Email:       "upsert-persist@example.com",
		Label:       "Original",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	_, _, err = store.UpsertMailboxFromRemote("", "account-upsert-persist", ICloudRemoteMailbox{
		AnonymousID: "upsert-persist-remote",
		Origin:      "ICLOUD_WEB",
		Email:       mailbox.Email,
		Label:       "Updated",
		IsActive:    false,
	}, "")
	if !isCodedError(err, "mailbox_sync_persist_failed") {
		t.Fatalf("UpsertMailboxFromRemote error = %#v, want mailbox_sync_persist_failed", err)
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after upsert persistence failure")
	}
	if current.Label != "Original" || !current.ICloudActive {
		t.Fatalf("mailbox after upsert persistence failure = %+v, want original state", current)
	}
}

func TestMarkMailboxesRemoteMissingRollsBackWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-missing-persist", ICloudRemoteMailbox{
		AnonymousID: "missing-persist-remote",
		Origin:      "ICLOUD_WEB",
		Email:       "missing-persist@example.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	_, err = store.MarkMailboxesRemoteMissing("", "account-missing-persist", map[string]struct{}{}, time.Now())
	if !isCodedError(err, "mailbox_sync_persist_failed") {
		t.Fatalf("MarkMailboxesRemoteMissing error = %#v, want mailbox_sync_persist_failed", err)
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after remote missing persistence failure")
	}
	if !current.ICloudActive || current.Status == StatusDisabled || !current.RemoteMissingAt.IsZero() {
		t.Fatalf("mailbox after remote missing persistence failure = %+v, want original state", current)
	}
}

func TestMarkMailboxesRemoteMissingMarksAppleAccountMailboxes(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-missing-apple", ICloudRemoteMailbox{
		AnonymousID: "missing-apple-remote",
		Origin:      "APPLE_ACCOUNT",
		Email:       "missing-apple@example.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	checkedAt := time.Now()
	updated, err := store.MarkMailboxesRemoteMissing("", "account-missing-apple", map[string]struct{}{}, checkedAt)
	if err != nil {
		t.Fatal(err)
	}
	if updated != 1 {
		t.Fatalf("updated = %d, want 1", updated)
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox not found after remote missing update")
	}
	if current.ICloudActive || current.Status != StatusDisabled || current.RemoteMissingAt.IsZero() {
		t.Fatalf("mailbox after remote missing update = %+v, want disabled Apple Account missing state", current)
	}
	if !current.RemoteMissingAt.Equal(checkedAt) {
		t.Fatalf("remote missing timestamp = %v, want %v", current.RemoteMissingAt, checkedAt)
	}
}

func TestMarkMailboxesRemoteMissingForOriginDoesNotCrossProvider(t *testing.T) {
	store := newTestStore(t)
	webMailbox, err := store.AddMailboxForOwnerWithRemote("", "account-mixed-origin", ICloudRemoteMailbox{
		AnonymousID: "mixed-web-remote",
		Origin:      "ICLOUD_WEB",
		Email:       "mixed-web@example.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	appleMailbox, err := store.AddMailboxForOwnerWithRemote("", "account-mixed-origin", ICloudRemoteMailbox{
		AnonymousID: "mixed-apple-remote",
		Origin:      "APPLE_ACCOUNT",
		Email:       "mixed-apple@example.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	checkedAt := time.Now()
	updated, err := store.MarkMailboxesRemoteMissingForOrigin(
		"",
		"account-mixed-origin",
		"ICLOUD_WEB",
		map[string]struct{}{},
		checkedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if updated != 1 {
		t.Fatalf("updated = %d, want only the iCloud Web mailbox", updated)
	}

	currentWeb, ok := store.FindMailboxByID(webMailbox.ID)
	if !ok {
		t.Fatal("iCloud Web mailbox not found after remote missing update")
	}
	if currentWeb.ICloudActive || currentWeb.Status != StatusDisabled || currentWeb.RemoteMissingAt.IsZero() {
		t.Fatalf("iCloud Web mailbox = %+v, want disabled missing state", currentWeb)
	}
	currentApple, ok := store.FindMailboxByID(appleMailbox.ID)
	if !ok {
		t.Fatal("Apple Account mailbox not found after remote missing update")
	}
	if !currentApple.ICloudActive || currentApple.Status == StatusDisabled || !currentApple.RemoteMissingAt.IsZero() {
		t.Fatalf("Apple Account mailbox = %+v, want unchanged active state", currentApple)
	}
}

func TestICloudSessionsForAllOwnersResolvesAccountProxy(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwnerWithProxy("owner-all-sessions", "All Sessions", "all-sessions@example.com", "", "http://proxy.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner("owner-all-sessions", ICloudSession{
		OwnerID:            "owner-all-sessions",
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "all-sessions-dsid",
		PremiumMailBaseURL: "https://icloud.example",
		Cookies:            []SessionCookie{{Name: "session", Value: "all-sessions-cookie"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "session", Value: "all-sessions-cookie"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	sessions := store.ICloudSessionsForAllOwners()
	if len(sessions) != 1 {
		t.Fatalf("all-owner sessions = %d, want 1", len(sessions))
	}
	if sessions[0].ProxyURL != "http://proxy.example:8080" {
		t.Fatalf("all-owner session proxy = %q, want account proxy", sessions[0].ProxyURL)
	}
	if len(sessions[0].LoginStates) == 0 || sessions[0].LoginStates[0].ProxyURL != "http://proxy.example:8080" {
		t.Fatalf("all-owner login-state proxy = %+v, want account proxy", sessions[0].LoginStates)
	}
}

func TestUpsertMessageRollsBackWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("", "", "MESSAGE-PERSIST-FAILURE", "message-persist-failure@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	message, err := store.AddMessage(mailbox.ID, "old subject", "sender@example.com", "old body", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	_, _, err = store.UpsertMessage(mailbox.ID, message.ID, "icloud", "new subject", "new@example.com", "new body", time.Now())
	if !isCodedError(err, "message_persist_failed") {
		t.Fatalf("UpsertMessage error = %#v, want message_persist_failed", err)
	}
	messages := store.MessagesForMailbox(mailbox.ID)
	if len(messages) != 1 {
		t.Fatalf("messages after upsert persistence failure = %d, want 1", len(messages))
	}
	if messages[0].Subject != "old subject" || messages[0].From != "sender@example.com" || messages[0].Body != "old body" {
		t.Fatalf("message after upsert persistence failure = %+v, want original message", messages[0])
	}
}

func TestSetMailboxSyncCursorRollsBackWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("", "", "CURSOR-PERSIST-FAILURE", "cursor-persist-failure@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	_, err = store.SetMailboxSyncCursor(mailbox.ID, time.Now(), "7")
	if !isCodedError(err, "mailbox_sync_persist_failed") {
		t.Fatalf("SetMailboxSyncCursor error = %#v, want mailbox_sync_persist_failed", err)
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after cursor persistence failure")
	}
	if !current.LastSyncAt.IsZero() || current.LastSyncUID != "" {
		t.Fatalf("mailbox cursor after persistence failure = %+v, want empty cursor", current)
	}
}

func TestSetICloudIMAPSyncCursorRollsBackWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwner("", "IMAP cursor account", "imap-cursor@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	state := LoginState{
		Kind:            LoginStateICloudIMAP,
		IMAPEmail:       "imap-cursor@icloud.com",
		IMAPHost:        defaultICloudIMAPHost,
		IMAPPort:        defaultICloudIMAPPort,
		IMAPAppPassword: "app-password",
	}
	if err := store.SaveICloudSession(ICloudSession{
		AccountID:   account.ID,
		AppleID:     account.AppleID,
		LoginStates: []LoginState{state},
	}); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	_, err = store.SetICloudIMAPSyncCursor("", account.ID, imapStateKey(state), time.Now(), "9")
	if !isCodedError(err, "imap_cursor_persist_failed") {
		t.Fatalf("SetICloudIMAPSyncCursor error = %#v, want imap_cursor_persist_failed", err)
	}
	current, ok := store.ICloudSessionForOwnerAccount("", account.ID)
	if !ok {
		t.Fatal("session disappeared after IMAP cursor persistence failure")
	}
	imapState, ok := iCloudIMAPLoginState(current)
	if !ok {
		t.Fatal("IMAP login state disappeared after cursor persistence failure")
	}
	if !imapState.IMAPLastSyncAt.IsZero() || imapState.IMAPLastSyncUID != "" {
		t.Fatalf("IMAP cursor after persistence failure = %+v, want empty cursor", imapState)
	}
}

func TestSaveICloudSessionRollsBackWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwnerWithProxy("owner-session-persist", "Session account", "session-persist@example.com", "", "http://old-proxy:8080")
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	err = store.SaveICloudSessionForOwner("owner-session-persist", ICloudSession{
		AccountID: account.ID,
		AppleID:   account.AppleID,
		ProxyURL:  "http://new-proxy:8080",
		LoginStates: []LoginState{{
			Kind:     LoginStateAppleAccount,
			ProxyURL: "http://new-proxy:8080",
			Cookies:  []SessionCookie{{Name: "session", Value: "cookie"}},
		}},
	})
	if !isCodedError(err, "icloud_session_persist_failed") {
		t.Fatalf("SaveICloudSessionForOwner error = %#v, want icloud_session_persist_failed", err)
	}
	if _, ok := store.ICloudSessionForOwnerAccount("owner-session-persist", account.ID); ok {
		t.Fatal("session remained in memory after session persistence failure")
	}
	current, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared after session persistence failure")
	}
	if current.ProxyURL != "http://old-proxy:8080" {
		t.Fatalf("account proxy after session persistence failure = %q, want old proxy", current.ProxyURL)
	}
}

func TestSaveICloudSessionDoesNotAliasCallerNestedSlices(t *testing.T) {
	store := newTestStore(t)
	input := ICloudSession{
		AppleID: "alias-source@example.com",
		Cookies: []SessionCookie{{
			Name:  "session",
			Value: "original-cookie",
		}},
		LoginStates: []LoginState{{
			Kind:            LoginStateICloudIMAP,
			IMAPAppPassword: "original-password",
			Cookies: []SessionCookie{{
				Name:  "imap",
				Value: "original-imap-cookie",
			}},
		}},
	}
	if err := store.SaveICloudSession(input); err != nil {
		t.Fatal(err)
	}

	input.Cookies[0].Value = "caller-mutated-cookie"
	input.LoginStates[0].IMAPAppPassword = "caller-mutated-password"
	input.LoginStates[0].Cookies[0].Value = "caller-mutated-imap-cookie"

	stored, ok := store.ICloudSession()
	if !ok {
		t.Fatal("stored iCloud session disappeared after caller mutation")
	}
	if stored.Cookies[0].Value != "original-cookie" ||
		stored.LoginStates[0].IMAPAppPassword != "original-password" ||
		stored.LoginStates[0].Cookies[0].Value != "original-imap-cookie" {
		t.Fatalf("stored session was aliased to caller input: %+v", stored)
	}
}

func TestICloudSessionReadDoesNotMutateStoredNestedSlices(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwnerWithProxy(
		"owner-read-isolation",
		"Read isolation",
		"read-isolation@example.com",
		"",
		"http://proxy-new:8080",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner("owner-read-isolation", ICloudSession{
		AccountID: account.ID,
		AppleID:   account.AppleID,
		ProxyURL:  "http://proxy-old:8080",
		LoginStates: []LoginState{{
			Kind:     LoginStateICloudWeb,
			ProxyURL: "http://proxy-old:8080",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	for i := range store.state.ICloudSessions {
		if store.state.ICloudSessions[i].AccountID != account.ID {
			continue
		}
		store.state.ICloudSessions[i].ProxyURL = "http://proxy-old:8080"
		store.state.ICloudSessions[i].LoginStates[0].ProxyURL = "http://proxy-old:8080"
	}
	store.mu.Unlock()

	sessions := store.ICloudSessionsForOwner("owner-read-isolation")
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	if sessions[0].ProxyURL != "http://proxy-new:8080" ||
		sessions[0].LoginStates[0].ProxyURL != "http://proxy-new:8080" {
		t.Fatalf("read did not resolve configured proxy: %+v", sessions[0])
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	for _, stored := range store.state.ICloudSessions {
		if stored.AccountID != account.ID {
			continue
		}
		if stored.ProxyURL != "http://proxy-old:8080" ||
			stored.LoginStates[0].ProxyURL != "http://proxy-old:8080" {
			t.Fatalf("read mutated stored session: %+v", stored)
		}
		return
	}
	t.Fatal("stored session disappeared after read")
}

func TestMarkMailboxesAPIExportedRollsBackInMemoryStateWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("", "", "EXPORT-PERSIST-FAILURE", "export-persist-failure@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	_, err = store.MarkMailboxesAPIExported([]string{mailbox.ID}, time.Now())
	if !isCodedError(err, "mailbox_export_state_persist_failed") {
		t.Fatalf("MarkMailboxesAPIExported error = %#v, want mailbox_export_state_persist_failed", err)
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after export state persistence failure")
	}
	if !current.APIExportedAt.IsZero() {
		t.Fatalf("export state was left marked in memory after persistence failure: %+v", current)
	}
}

func TestMailboxAPIExportFailsBeforeSendingWhenStatePersistenceFails(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "export-handler-persist-failure", "admin123")
	mailbox := createTestMailboxWithCookie(t, handler, adminCookie, "EXPORT", "export-handler-persist-failure@icloud.com")

	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis", strings.NewReader(`{"format":"txt"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("API export persistence failure status = %d body=%s, want 500", rr.Code, rr.Body.String())
	}
	var response struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Code != "mailbox_export_state_persist_failed" {
		t.Fatalf("API export persistence failure code = %q, want mailbox_export_state_persist_failed", response.Code)
	}
	if strings.Contains(rr.Body.String(), mailbox.Email) {
		t.Fatalf("API export leaked file contents after persistence failure: %q", rr.Body.String())
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing after API export persistence failure")
	}
	if !current.APIExportedAt.IsZero() {
		t.Fatalf("mailbox was marked exported after failed API export: %+v", current)
	}
}

func TestSaveCreateSettingsRollsBackWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	const ownerID = "owner-settings-persist"
	if _, err := store.SaveCreateSettingsForOwner(ownerID, CreateSettings{
		Label:      "original",
		AccountIDs: []string{"account-original"},
	}); err != nil {
		t.Fatal(err)
	}
	original := store.CreateSettingsForOwner(ownerID)
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	_, err := store.SaveCreateSettingsForOwner(ownerID, CreateSettings{
		Label:      "updated",
		AccountIDs: []string{"account-updated"},
	})
	if !isCodedError(err, "create_settings_persist_failed") {
		t.Fatalf("SaveCreateSettingsForOwner error = %#v, want create_settings_persist_failed", err)
	}
	current := store.CreateSettingsForOwner(ownerID)
	if current.Label != original.Label || strings.Join(current.AccountIDs, ",") != strings.Join(original.AccountIDs, ",") {
		t.Fatalf("create settings after persistence failure = %+v, want original %+v", current, original)
	}
}

func TestClaimAvailableMailboxRollsBackWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("", "", "CLAIM-PERSIST-FAILURE", "claim-persist-failure@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	_, err = store.ClaimAvailableMailbox("claimed")
	if !isCodedError(err, "mailbox_claim_persist_failed") {
		t.Fatalf("ClaimAvailableMailbox error = %#v, want mailbox_claim_persist_failed", err)
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after claim persistence failure")
	}
	if current.Status != StatusAvailable || current.Note != mailbox.Note || current.ReceiveCount != mailbox.ReceiveCount {
		t.Fatalf("mailbox after claim persistence failure = %+v, want original %+v", current, mailbox)
	}
}

func TestSetMailboxStatusCannotResurrectRemoteDeletedMailbox(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-status-remote-deleted", ICloudRemoteMailbox{
		AnonymousID: "status-remote-deleted",
		Origin:      "ICLOUD_WEB",
		Email:       "status-remote-deleted@icloud.com",
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
		t.Fatal("mailbox disappeared after remote delete state update")
	}
	active := true
	_, err = store.SetMailboxStatus(mailbox.ID, &active, &active, StatusAvailable, "manual verify")
	if !isCodedError(err, "mailbox_remote_deleted") {
		t.Fatalf("SetMailboxStatus error = %#v, want mailbox_remote_deleted", err)
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after blocked status mutation")
	}
	if current != expected {
		t.Fatalf("mailbox changed after blocked status mutation: got=%+v want=%+v", current, expected)
	}
	if current.RemoteDeleteStatus != "succeeded" || current.Status != StatusDisabled || current.ICloudActive {
		t.Fatalf("mailbox after blocked status mutation = %+v", current)
	}
}

func TestMailboxVerifyWaitsForAccountOperationBeforeMutatingStatus(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "verify-gate", "verify-gate-password")
	account, err := store.AddAccountForOwner(user.ID, "Verify gate", "verify-gate@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote(user.ID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "verify-gate-remote",
		Origin:      "ICLOUD_WEB",
		Email:       "verify-gate@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+mailbox.ID+"/verify", nil)
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(rr, req)
		close(done)
	}()

	select {
	case <-done:
		releaseAccountOperation()
		t.Fatalf("mailbox verify completed while the account operation was held: status=%d body=%s", rr.Code, rr.Body.String())
	case <-time.After(100 * time.Millisecond):
	}

	if err := store.MarkMailboxRemoteDeleteSucceeded(mailbox.ID, time.Now()); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("mailbox verify did not finish after the account operation was released")
	}
	if rr.Code != http.StatusConflict {
		t.Fatalf("mailbox verify status = %d body=%s, want 409", rr.Code, rr.Body.String())
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after blocked verify")
	}
	if updated.Status != StatusDisabled || updated.ICloudActive {
		t.Fatalf("mailbox was resurrected by verify: %+v", updated)
	}
}

func TestManualMailboxCreateWaitsForAccountOperation(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "manual-create-gate", "multi123")
	account, err := store.AddAccountForOwner(user.ID, "Manual", "manual-create-gate@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/api/mailboxes", strings.NewReader(fmt.Sprintf(
			`{"account_id":%q,"label":"manual","email":"manual-create-gate@icloud.com"}`,
			account.ID,
		)))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		addClosureTestCSRF(req, cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		done <- rr
	}()

	select {
	case rr := <-done:
		releaseAccountOperation()
		t.Fatalf("manual mailbox create completed while the account operation was held: status=%d body=%s", rr.Code, rr.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	releaseAccountOperation()

	select {
	case rr := <-done:
		if rr.Code != http.StatusCreated {
			t.Fatalf("manual mailbox create status = %d body=%s, want 201", rr.Code, rr.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("manual mailbox create did not finish after the account operation was released")
	}
}

func TestSetMailboxStatusRollsBackWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("", "", "STATUS-PERSIST-FAILURE", "status-persist-failure@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath
	active := false

	_, err = store.SetMailboxStatus(mailbox.ID, &active, &active, StatusDisabled, "disabled")
	if !isCodedError(err, "mailbox_status_persist_failed") {
		t.Fatalf("SetMailboxStatus error = %#v, want mailbox_status_persist_failed", err)
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after status persistence failure")
	}
	if current != mailbox {
		t.Fatalf("mailbox after status persistence failure = %+v, want original %+v", current, mailbox)
	}
}

func TestAddMessageRollsBackWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("", "", "ADD-MESSAGE-PERSIST-FAILURE", "add-message-persist-failure@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	_, err = store.AddMessage(mailbox.ID, "subject", "from@example.com", "body", time.Now())
	if !isCodedError(err, "message_persist_failed") {
		t.Fatalf("AddMessage error = %#v, want message_persist_failed", err)
	}
	if messages := store.MessagesForMailbox(mailbox.ID); len(messages) != 0 {
		t.Fatalf("messages after AddMessage persistence failure = %d, want 0", len(messages))
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after AddMessage persistence failure")
	}
	if current.ReceiveCount != mailbox.ReceiveCount {
		t.Fatalf("mailbox receive count after AddMessage persistence failure = %d, want %d", current.ReceiveCount, mailbox.ReceiveCount)
	}
}

func TestSetMailboxLastCodeRollsBackWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("", "", "LAST-CODE-PERSIST-FAILURE", "last-code-persist-failure@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	message, err := store.AddMessage(mailbox.ID, "subject", "from@example.com", "body", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	_, err = store.SetMailboxLastCode(mailbox.ID, message.ID, time.Now())
	if !isCodedError(err, "mailbox_code_state_persist_failed") {
		t.Fatalf("SetMailboxLastCode error = %#v, want mailbox_code_state_persist_failed", err)
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after last code persistence failure")
	}
	if !current.LastCodeAt.IsZero() || current.LastCodeMessageID != "" {
		t.Fatalf("last code state after persistence failure = %+v, want empty state", current)
	}
}

func TestMailboxMutationHandlersReturnPersistenceFailuresAs500(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    func(string) string
		body    string
		wantErr string
	}{
		{
			name:    "verify",
			method:  http.MethodPost,
			path:    func(id string) string { return "/api/mailboxes/" + id + "/verify" },
			wantErr: "mailbox_status_persist_failed",
		},
		{
			name:    "disable",
			method:  http.MethodPost,
			path:    func(id string) string { return "/api/mailboxes/" + id + "/disable" },
			wantErr: "mailbox_status_persist_failed",
		},
		{
			name:    "status",
			method:  http.MethodPost,
			path:    func(id string) string { return "/api/mailboxes/" + id + "/status" },
			body:    `{"status":"disabled"}`,
			wantErr: "mailbox_status_persist_failed",
		},
		{
			name:    "message",
			method:  http.MethodPost,
			path:    func(id string) string { return "/api/mailboxes/" + id + "/messages" },
			body:    `{"subject":"subject","from":"from@example.com","body":"body"}`,
			wantErr: "message_persist_failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestStore(t)
			mailbox, err := store.AddMailboxForOwner("", "", "HANDLER-PERSIST-FAILURE", "handler-persist-failure@icloud.com")
			if err != nil {
				t.Fatal(err)
			}
			handler := NewServer(Config{}, store, discardLogger())
			adminCookie, _ := registerTestUser(t, handler, "handler-persist-"+tt.name, "admin123")

			badPath := filepath.Join(t.TempDir(), "state-dir")
			if err := os.MkdirAll(badPath, 0o755); err != nil {
				t.Fatal(err)
			}
			store.path = badPath

			req := httptest.NewRequest(tt.method, tt.path(mailbox.ID), strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(adminCookie)
			addClosureTestCSRF(req, adminCookie)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d body=%s, want 500", rr.Code, rr.Body.String())
			}
			var body struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Code != tt.wantErr {
				t.Fatalf("error code = %q body=%s, want %q", body.Code, rr.Body.String(), tt.wantErr)
			}
		})
	}
}

func TestClaimMailboxReturnsPersistenceFailureAs500(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("", "", "CLAIM-HANDLER-PERSIST-FAILURE", "claim-handler-persist-failure@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{APIKey: "global-key"}, store, discardLogger())
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/claim", strings.NewReader(`{"project":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer global-key")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("claim status = %d body=%s, want 500", rr.Code, rr.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "mailbox_claim_persist_failed" {
		t.Fatalf("claim error code = %q body=%s", body.Code, rr.Body.String())
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || current.Status != StatusAvailable {
		t.Fatalf("mailbox after failed claim = %+v ok=%v, want available", current, ok)
	}
}

func TestUserAndWebSessionMutationsRollBackWhenPersistenceFails(t *testing.T) {
	t.Run("create user", func(t *testing.T) {
		store := newTestStore(t)
		store.path = filepath.Join(t.TempDir(), "state-dir")
		if err := os.MkdirAll(store.path, 0o755); err != nil {
			t.Fatal(err)
		}

		if _, err := store.CreateUser("create-user", "password"); err == nil {
			t.Fatal("CreateUser succeeded with an invalid state path")
		}
		if users := store.Users(); len(users) != 0 {
			t.Fatalf("users after persistence failure = %+v, want none", users)
		}
	})

	t.Run("authenticate user", func(t *testing.T) {
		store := newTestStore(t)
		user, err := store.CreateUser("authenticate-user", "password")
		if err != nil {
			t.Fatal(err)
		}
		before, ok := store.UserByID(user.ID)
		if !ok {
			t.Fatal("created user not found")
		}
		store.path = filepath.Join(t.TempDir(), "state-dir")
		if err := os.MkdirAll(store.path, 0o755); err != nil {
			t.Fatal(err)
		}

		if _, err := store.AuthenticateUser(user.Username, "password"); err == nil {
			t.Fatal("AuthenticateUser succeeded with an invalid state path")
		}
		after, ok := store.UserByID(user.ID)
		if !ok {
			t.Fatal("user disappeared after authentication persistence failure")
		}
		if !after.LastLoginAt.Equal(before.LastLoginAt) || !after.UpdatedAt.Equal(before.UpdatedAt) {
			t.Fatalf("user after authentication persistence failure = %+v, want %+v", after, before)
		}
	})

	t.Run("delete user", func(t *testing.T) {
		store := newTestStore(t)
		user, err := store.CreateUser("delete-user", "password")
		if err != nil {
			t.Fatal(err)
		}
		account, err := store.AddAccountForOwner(user.ID, "owned", "owned@example.com", "")
		if err != nil {
			t.Fatal(err)
		}
		mailbox, err := store.AddMailboxForOwner(user.ID, account.ID, "owned mailbox", "owned-mailbox@icloud.com")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.AddMessage(mailbox.ID, "subject", "from@example.com", "body", time.Now()); err != nil {
			t.Fatal(err)
		}
		store.path = filepath.Join(t.TempDir(), "state-dir")
		if err := os.MkdirAll(store.path, 0o755); err != nil {
			t.Fatal(err)
		}

		if _, err := store.DeleteUser(user.ID); err == nil {
			t.Fatal("DeleteUser succeeded with an invalid state path")
		}
		if _, ok := store.UserByID(user.ID); !ok {
			t.Fatal("user disappeared after deletion persistence failure")
		}
		if _, ok := store.FindAccountByID(account.ID); !ok {
			t.Fatal("account disappeared after deletion persistence failure")
		}
		if _, ok := store.FindMailboxByID(mailbox.ID); !ok {
			t.Fatal("mailbox disappeared after deletion persistence failure")
		}
		if messages := store.MessagesForMailbox(mailbox.ID); len(messages) != 1 {
			t.Fatalf("messages after deletion persistence failure = %d, want 1", len(messages))
		}
	})

	t.Run("create web session", func(t *testing.T) {
		store := newTestStore(t)
		user, err := store.CreateUser("create-session-user", "password")
		if err != nil {
			t.Fatal(err)
		}
		store.path = filepath.Join(t.TempDir(), "state-dir")
		if err := os.MkdirAll(store.path, 0o755); err != nil {
			t.Fatal(err)
		}

		token, _, err := store.CreateWebSession(user.ID, false, time.Hour)
		if err == nil {
			t.Fatal("CreateWebSession succeeded with an invalid state path")
		}
		if _, _, ok := store.WebSessionByToken(token); ok {
			t.Fatal("web session remained after persistence failure")
		}
	})

	t.Run("delete web session", func(t *testing.T) {
		store := newTestStore(t)
		user, err := store.CreateUser("delete-session-user", "password")
		if err != nil {
			t.Fatal(err)
		}
		token, _, err := store.CreateWebSession(user.ID, false, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		store.path = filepath.Join(t.TempDir(), "state-dir")
		if err := os.MkdirAll(store.path, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := store.DeleteWebSession(token); err == nil {
			t.Fatal("DeleteWebSession succeeded with an invalid state path")
		}
		if _, _, ok := store.WebSessionByToken(token); !ok {
			t.Fatal("web session disappeared after persistence failure")
		}
	})
}

func TestNewServerProvidesLoggerWhenNil(t *testing.T) {
	store := newTestStore(t)
	server := NewServer(Config{}, store, nil).(*Server)
	if server.logger == nil {
		t.Fatal("NewServer left logger nil")
	}
}

func TestPersistedPendingRemoteDeleteBecomesUnknownAfterReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-crash-delete", ICloudRemoteMailbox{
		AnonymousID: "crash-delete-remote",
		Origin:      "APPLE_ACCOUNT",
		Email:       "crash-delete@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginMailboxRemoteDelete(mailbox.ID, time.Now()); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, reloaded, discardLogger()).(*Server)
	called := false
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		called = true
		return nil
	}
	current, ok := reloaded.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing after reload")
	}
	err = handler.deleteRemoteMailboxForRequest(context.Background(), current)
	if !isCodedError(err, "remote_delete_unknown") {
		t.Fatalf("reloaded pending delete error = %#v, want remote_delete_unknown", err)
	}
	if called {
		t.Fatal("reloaded pending delete was retried without remote confirmation")
	}
	current, ok = reloaded.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing after refusing unknown remote delete")
	}
	if current.RemoteDeleteStatus != "unknown" {
		t.Fatalf("remote delete status after reload = %q, want unknown", current.RemoteDeleteStatus)
	}
}

func TestRemoteSyncDoesNotResurrectConfirmedDeletedMailbox(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-no-resurrect", ICloudRemoteMailbox{
		AnonymousID: "no-resurrect-remote",
		Origin:      "ICLOUD_WEB",
		Email:       "no-resurrect@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMailboxRemoteDeleteSucceeded(mailbox.ID, time.Now()); err != nil {
		t.Fatal(err)
	}

	updated, created, err := store.UpsertMailboxFromRemote("", "account-no-resurrect", ICloudRemoteMailbox{
		AnonymousID: "no-resurrect-remote",
		Origin:      "ICLOUD_WEB",
		Email:       "no-resurrect@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("confirmed-deleted mailbox was recreated")
	}
	if updated.RemoteDeleteStatus != "succeeded" || updated.ICloudActive || updated.Status != StatusDisabled {
		t.Fatalf("confirmed-deleted mailbox was resurrected by sync: %+v", updated)
	}
}

func TestRemoteSyncPreservesUnresolvedRemoteDeleteStates(t *testing.T) {
	tests := []struct {
		name   string
		status string
		apply  func(*FileStore, string) error
	}{
		{
			name:   "pending",
			status: "pending",
			apply: func(store *FileStore, mailboxID string) error {
				return store.BeginMailboxRemoteDelete(mailboxID, time.Now())
			},
		},
		{
			name:   "unknown",
			status: "unknown",
			apply: func(store *FileStore, mailboxID string) error {
				return store.MarkMailboxRemoteDeleteUnknown(mailboxID, "transport uncertain", time.Now())
			},
		},
		{
			name:   "failed",
			status: "failed",
			apply: func(store *FileStore, mailboxID string) error {
				return store.MarkMailboxRemoteDeleteFailed(mailboxID, "provider rejected", time.Now())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestStore(t)
			mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-unresolved-delete", ICloudRemoteMailbox{
				AnonymousID: "unresolved-delete-" + tt.name,
				Origin:      "ICLOUD_WEB",
				Email:       "unresolved-" + tt.name + "@icloud.com",
				IsActive:    true,
			}, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := tt.apply(store, mailbox.ID); err != nil {
				t.Fatal(err)
			}
			before, ok := store.FindMailboxByID(mailbox.ID)
			if !ok {
				t.Fatal("mailbox missing before remote sync")
			}

			updated, created, err := store.UpsertMailboxFromRemote("", "account-unresolved-delete", ICloudRemoteMailbox{
				AnonymousID: before.RemoteAnonymousID,
				Origin:      "ICLOUD_WEB",
				Email:       before.Email,
				Label:       "refreshed-" + tt.name,
				IsActive:    true,
			}, "")
			if err != nil {
				t.Fatal(err)
			}
			if created {
				t.Fatal("unresolved-delete mailbox was recreated")
			}
			if updated.RemoteDeleteStatus != tt.status {
				t.Fatalf("remote delete status = %q, want %q", updated.RemoteDeleteStatus, tt.status)
			}
			if updated.RemoteDeleteError != before.RemoteDeleteError {
				t.Fatalf("remote delete error = %q, want preserved %q", updated.RemoteDeleteError, before.RemoteDeleteError)
			}
			if !updated.RemoteDeleteAt.Equal(before.RemoteDeleteAt) {
				t.Fatalf("remote delete timestamp changed from %v to %v", before.RemoteDeleteAt, updated.RemoteDeleteAt)
			}
			if updated.Label != "refreshed-"+tt.name {
				t.Fatalf("remote sync did not refresh label: %q", updated.Label)
			}
			if !updated.ICloudActive || updated.Status != StatusAvailable {
				t.Fatalf("remote sync changed active mailbox state: %+v", updated)
			}
		})
	}
}

func TestMailboxStatusWaitsForMailboxAccountBindingToSettle(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "status-binding", "status123")
	account, err := store.AddAccountForOwner(user.ID, "Bound account", "status-binding@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(user.ID, "", "binding mailbox", "status-binding@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	releaseUnbound, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, ""),
	)
	if err != nil {
		t.Fatal(err)
	}
	releaseBound, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, account.ID),
	)
	if err != nil {
		releaseUnbound()
		t.Fatal(err)
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(
			http.MethodPost,
			"/api/mailboxes/"+mailbox.ID+"/status",
			strings.NewReader(`{"status":"used"}`),
		)
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		addClosureTestCSRF(req, cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		done <- rr
	}()

	select {
	case rr := <-done:
		releaseBound()
		releaseUnbound()
		t.Fatalf("status mutation completed before mailbox binding settled: status=%d body=%s", rr.Code, rr.Body.String())
	case <-time.After(100 * time.Millisecond):
	}

	_, _, err = store.UpsertMailboxFromRemote(user.ID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "status-binding-remote",
		Origin:      "ICLOUD_WEB",
		Email:       "status-binding@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		releaseBound()
		releaseUnbound()
		t.Fatal(err)
	}
	releaseUnbound()

	select {
	case rr := <-done:
		releaseBound()
		t.Fatalf("status mutation bypassed the newly bound account gate: status=%d body=%s", rr.Code, rr.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	releaseBound()

	select {
	case rr := <-done:
		if rr.Code != http.StatusOK {
			t.Fatalf("status mutation status = %d body=%s", rr.Code, rr.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("status mutation did not finish after account gates were released")
	}

	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared")
	}
	if updated.AccountID != account.ID || updated.Status != StatusUsed {
		t.Fatalf("mailbox after binding/status mutation = %+v", updated)
	}
}

func TestMailboxStatusReportsMissingMailboxAfterGateWait(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "status-missing", "status123")
	account, err := store.AddAccountForOwner(user.ID, "Status missing", "status-missing@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(user.ID, account.ID, "status missing", "status-missing@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	release, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(
			http.MethodPost,
			"/api/mailboxes/"+mailbox.ID+"/status",
			strings.NewReader(`{"status":"used"}`),
		)
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		addClosureTestCSRF(req, cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		done <- rr
	}()
	select {
	case rr := <-done:
		release()
		t.Fatalf("status mutation completed while account gate was held: status=%d body=%s", rr.Code, rr.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	if err := store.DeleteMailbox(mailbox.ID); err != nil {
		release()
		t.Fatal(err)
	}
	release()

	select {
	case rr := <-done:
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status mutation status = %d body=%s, want 404", rr.Code, rr.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("status mutation did not finish after account gate release")
	}
}

func TestMailboxExportWaitsForMailboxAccountBindingToSettle(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "export-binding", "export123")
	account, err := store.AddAccountForOwner(user.ID, "Bound account", "export-binding@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(user.ID, "", "binding export", "export-binding@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	releaseUnbound, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, ""),
	)
	if err != nil {
		t.Fatal(err)
	}
	releaseBound, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, account.ID),
	)
	if err != nil {
		releaseUnbound()
		t.Fatal(err)
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(
			http.MethodPost,
			"/api/runtime/export-mailbox-apis",
			strings.NewReader(fmt.Sprintf(`{"format":"txt","ids":[%q]}`, mailbox.ID)),
		)
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		addClosureTestCSRF(req, cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		done <- rr
	}()

	select {
	case rr := <-done:
		releaseBound()
		releaseUnbound()
		t.Fatalf("mailbox export completed before mailbox binding settled: status=%d body=%s", rr.Code, rr.Body.String())
	case <-time.After(100 * time.Millisecond):
	}

	_, _, err = store.UpsertMailboxFromRemote(user.ID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "export-binding-remote",
		Origin:      "ICLOUD_WEB",
		Email:       "export-binding@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		releaseBound()
		releaseUnbound()
		t.Fatal(err)
	}
	releaseUnbound()

	select {
	case rr := <-done:
		releaseBound()
		t.Fatalf("mailbox export bypassed the newly bound account gate: status=%d body=%s", rr.Code, rr.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	releaseBound()

	select {
	case rr := <-done:
		if rr.Code != http.StatusOK {
			t.Fatalf("mailbox export status = %d body=%s", rr.Code, rr.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("mailbox export did not finish after account gates were released")
	}
}

func TestDeleteMailboxRouteCanConfirmUnknownRemoteDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-confirm-unknown", ICloudRemoteMailbox{
		AnonymousID: "confirm-unknown-remote",
		Origin:      "APPLE_ACCOUNT",
		Email:       "confirm-unknown@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	saveTestAppleAccountSession(t, store, "", "account-confirm-unknown", "confirm-unknown@example.com")
	if err := store.BeginMailboxRemoteDelete(mailbox.ID, time.Now()); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, reloaded, discardLogger()).(*Server)
	called := false
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		called = true
		return nil
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/mailboxes/"+mailbox.ID+"?delete_remote=1&confirm_unknown=1", nil)
	req.SetPathValue("id", mailbox.ID)
	rr := httptest.NewRecorder()
	handler.handleDeleteMailbox(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("confirmed unknown remote delete status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !called {
		t.Fatal("confirmed unknown remote delete did not call provider")
	}
	if _, ok := reloaded.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("mailbox remains after confirmed unknown remote delete")
	}
}

func TestBulkDeleteCanConfirmUnknownRemoteDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, 2)
	for i, email := range []string{"confirm-unknown-bulk-1@icloud.com", "confirm-unknown-bulk-2@icloud.com"} {
		mailbox, addErr := store.AddMailboxForOwnerWithRemote("", fmt.Sprintf("account-confirm-unknown-bulk-%d", i), ICloudRemoteMailbox{
			AnonymousID: fmt.Sprintf("confirm-unknown-bulk-remote-%d", i),
			Origin:      "APPLE_ACCOUNT",
			Email:       email,
			IsActive:    true,
		}, "")
		if addErr != nil {
			t.Fatal(addErr)
		}
		saveTestAppleAccountSession(t, store, "", fmt.Sprintf("account-confirm-unknown-bulk-%d", i), "confirm-unknown-bulk@example.com")
		if beginErr := store.BeginMailboxRemoteDelete(mailbox.ID, time.Now()); beginErr != nil {
			t.Fatal(beginErr)
		}
		ids = append(ids, mailbox.ID)
	}

	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, reloaded, discardLogger()).(*Server)
	var calls atomic.Int32
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		calls.Add(1)
		return nil
	}

	body := fmt.Sprintf(`{"ids":[%q,%q],"delete_remote":true,"confirm_unknown":true}`, ids[0], ids[1])
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/bulk-delete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.handleBulkDeleteMailboxes(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("confirmed unknown bulk delete status = %d body=%s", rr.Code, rr.Body.String())
	}
	if calls.Load() != int32(len(ids)) {
		t.Fatalf("confirmed unknown bulk delete provider calls = %d, want %d", calls.Load(), len(ids))
	}
	for _, id := range ids {
		if _, ok := reloaded.FindMailboxByID(id); ok {
			t.Fatalf("mailbox %s remains after confirmed unknown bulk delete", id)
		}
	}
}

func TestRemoteDeleteDoesNotTrustRemoteMissingMarkerAsProviderConfirmation(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-missing-marker", ICloudRemoteMailbox{
		AnonymousID: "missing-marker-remote",
		Origin:      "APPLE_ACCOUNT",
		Email:       "missing-marker@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	store.state.Mailboxes[0].RemoteMissingAt = time.Now()
	saveTestAppleAccountSession(t, store, "", "account-missing-marker", "missing-marker@example.com")
	called := false
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		called = true
		return nil
	}
	if err := handler.deleteRemoteMailboxForRequest(context.Background(), mailbox); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("remote delete skipped provider after seeing only a reconciliation missing marker")
	}
}

func TestLocalMailboxDeleteCannotBypassActiveRemoteDelete(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	oldTimeout := mailboxAccountOperationAcquireTimeout
	mailboxAccountOperationAcquireTimeout = 40 * time.Millisecond
	t.Cleanup(func() { mailboxAccountOperationAcquireTimeout = oldTimeout })
	adminCookie, admin := registerTestUser(t, handler, "delete-lock-admin", "admin123")
	mailbox, err := store.AddMailboxForOwnerWithRemote(admin.ID, "account-delete-lock", ICloudRemoteMailbox{
		AnonymousID: "delete-lock-remote",
		Origin:      "APPLE_ACCOUNT",
		Email:       "delete-lock@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	saveTestAppleAccountSession(t, store, admin.ID, "account-delete-lock", "delete-lock@example.com")

	remoteStarted := make(chan struct{})
	releaseRemote := make(chan struct{})
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		close(remoteStarted)
		<-releaseRemote
		return nil
	}
	remoteRR := httptest.NewRecorder()
	remoteReq := httptest.NewRequest(http.MethodDelete, "/api/mailboxes/"+mailbox.ID+"?delete_remote=1", nil)
	remoteReq.AddCookie(adminCookie)
	addClosureTestCSRF(remoteReq, adminCookie)
	remoteDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(remoteRR, remoteReq)
		close(remoteDone)
	}()
	select {
	case <-remoteStarted:
	case <-time.After(time.Second):
		t.Fatal("remote delete did not start")
	}

	localRR := httptest.NewRecorder()
	localReq := httptest.NewRequest(http.MethodDelete, "/api/mailboxes/"+mailbox.ID+"?delete_remote=0", nil)
	localReq.AddCookie(adminCookie)
	addClosureTestCSRF(localReq, adminCookie)
	localDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(localRR, localReq)
		close(localDone)
	}()
	select {
	case <-localDone:
	case <-time.After(time.Second):
		t.Fatal("local delete did not return while remote delete was active")
	}
	if localRR.Code != http.StatusConflict {
		t.Fatalf("local delete while remote active status = %d body=%s", localRR.Code, localRR.Body.String())
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); !ok {
		t.Fatal("local delete removed mailbox while remote delete was active")
	}

	close(releaseRemote)
	select {
	case <-remoteDone:
	case <-time.After(time.Second):
		t.Fatal("remote delete did not finish")
	}
	if remoteRR.Code != http.StatusOK {
		t.Fatalf("remote delete status = %d body=%s", remoteRR.Code, remoteRR.Body.String())
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("mailbox remains after remote delete completed")
	}
}

func TestBulkDeleteReportsFailureWhenEveryMailboxFails(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "bulk-delete-all-fail", "admin123")
	mailbox := createTestMailboxWithCookie(t, handler, adminCookie, "FAIL", "bulk-delete-fail@icloud.com")
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		return errors.New("provider delete failed")
	}

	body := fmt.Sprintf(`{"ids":[%q],"delete_remote":true}`, mailbox.ID)
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/bulk-delete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("all-failed bulk delete status = %d body=%s", rr.Code, rr.Body.String())
	}
	var response struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Deleted int    `json:"deleted"`
		Failed  int    `json:"failed"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Success || response.Message == "" || response.Deleted != 0 || response.Failed != 1 {
		t.Fatalf("all-failed bulk delete response = %+v", response)
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); !ok {
		t.Fatal("mailbox was removed after remote delete failure")
	}
}

func TestBulkDeleteReportsPartialFailureWithMultiStatus(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, admin := registerTestUser(t, handler, "bulk-delete-partial", "admin123")
	first, err := store.AddMailboxForOwnerWithRemote(admin.ID, "account-bulk-partial", ICloudRemoteMailbox{
		AnonymousID: "bulk-partial-1",
		Origin:      "APPLE_ACCOUNT",
		Email:       "bulk-delete-partial-first@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddMailboxForOwnerWithRemote(admin.ID, "account-bulk-partial", ICloudRemoteMailbox{
		AnonymousID: "bulk-partial-2",
		Origin:      "APPLE_ACCOUNT",
		Email:       "bulk-delete-partial-second@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	saveTestAppleAccountSession(t, store, admin.ID, "account-bulk-partial", "bulk-partial@example.com")
	handler.deleteRemoteMailbox = func(_ context.Context, mailbox Mailbox) error {
		if mailbox.ID == first.ID {
			return errors.New("provider delete failed")
		}
		return nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/bulk-delete", strings.NewReader(fmt.Sprintf(
		`{"ids":[%q,%q],"delete_remote":true}`, first.ID, second.ID,
	)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("partial bulk delete status = %d body=%s, want 207", rr.Code, rr.Body.String())
	}
	var response struct {
		Success bool `json:"success"`
		Deleted int  `json:"deleted"`
		Failed  int  `json:"failed"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Success || response.Deleted != 1 || response.Failed != 1 {
		t.Fatalf("partial bulk delete response = %+v, want success=false deleted=1 failed=1", response)
	}
	if _, ok := store.FindMailboxByID(first.ID); !ok {
		t.Fatal("failed mailbox was removed")
	}
	if _, ok := store.FindMailboxByID(second.ID); ok {
		t.Fatal("successful mailbox remains")
	}
}

func TestICloudMailboxSyncMarksMissingOnAuthoritativeEmptyRemoteList(t *testing.T) {
	store := newTestStore(t)
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("owner-empty-sync", "account-empty-sync", ICloudRemoteMailbox{
		AnonymousID: "remote-kept",
		Origin:      "ICLOUD_WEB",
		Email:       "kept-empty-sync@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/hme/list" {
			t.Errorf("path = %s, want /v2/hme/list", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": {"hmeEmails": []}
		}`))
	}))
	defer ts.Close()

	session := ICloudSession{
		OwnerID:            "owner-empty-sync",
		AccountID:          "account-empty-sync",
		AppleID:            "empty-sync@example.com",
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
		}},
	}
	if err := store.SaveICloudSessionForOwner("owner-empty-sync", session); err != nil {
		t.Fatal(err)
	}
	_, _, err = server.syncICloudMailboxesForSession(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil), "owner-empty-sync", session)
	if err != nil {
		t.Fatal(err)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after empty remote list")
	}
	if updated.ICloudActive || updated.RemoteMissingAt.IsZero() || updated.Status != StatusDisabled {
		t.Fatalf("mailbox was not marked missing after authoritative empty remote list: %+v", updated)
	}
}

func TestBulkDeleteDoesNotCountPreviouslyConfirmedRemoteDeleteAsNewRemoteDelete(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "bulk-delete-already-remote", "admin123")
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "", ICloudRemoteMailbox{
		AnonymousID: "already-remote-deleted",
		Origin:      "ICLOUD_WEB",
		Email:       "already-remote-deleted@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMailboxRemoteDeleteSucceeded(mailbox.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	providerCalls := 0
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		providerCalls++
		return errors.New("provider should not be called for succeeded state")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/bulk-delete", strings.NewReader(fmt.Sprintf(
		`{"ids":[%q],"delete_remote":true,"confirm_unknown":true}`, mailbox.ID,
	)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("bulk delete status = %d body=%s", rr.Code, rr.Body.String())
	}
	var response struct {
		Success       bool `json:"success"`
		Deleted       int  `json:"deleted"`
		RemoteDeleted int  `json:"remote_deleted"`
		Failed        int  `json:"failed"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Success || response.Deleted != 1 || response.RemoteDeleted != 0 || response.Failed != 0 {
		t.Fatalf("bulk delete response = %+v", response)
	}
	if providerCalls != 0 {
		t.Fatalf("provider calls = %d, want 0", providerCalls)
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("mailbox local record remains after deleting previously confirmed remote deletion")
	}
}

func TestICloudMailboxSyncSerializesWithRemoteDelete(t *testing.T) {
	store := newTestStore(t)
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-sync-delete-race"
	accountID := "account-sync-delete-race"
	mailbox, err := store.AddMailboxForOwnerWithRemote(ownerID, accountID, ICloudRemoteMailbox{
		AnonymousID: "remote-sync-delete-race",
		Origin:      "ICLOUD_WEB",
		Email:       "race@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	listStarted := make(chan struct{})
	releaseList := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("path = %s, want /v2/hme/list", r.URL.Path)
		}
		close(listStarted)
		<-releaseList
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": {"hmeEmails": [{
				"anonymousId": "remote-sync-delete-race",
				"hme": "race@icloud.com",
				"isActive": true
			}]}
		}`))
	}))
	defer ts.Close()

	server.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		return nil
	}
	session := ICloudSession{
		OwnerID:            ownerID,
		AccountID:          accountID,
		AppleID:            "sync-delete-race@example.com",
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}

	syncDone := make(chan error, 1)
	go func() {
		_, _, syncErr := server.syncICloudMailboxesForSession(
			context.Background(),
			httptest.NewRequest(http.MethodGet, "/", nil),
			ownerID,
			session,
		)
		syncDone <- syncErr
	}()
	select {
	case <-listStarted:
	case <-time.After(time.Second):
		t.Fatal("mailbox sync did not reach the remote list request")
	}

	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- server.deleteMailboxForRequest(context.Background(), mailbox.ID, true)
	}()
	select {
	case err := <-deleteDone:
		close(releaseList)
		t.Fatalf("remote delete completed while sync held the account operation: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseList)
	select {
	case err := <-syncDone:
		if err != nil {
			t.Fatalf("mailbox sync error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("mailbox sync did not finish")
	}
	select {
	case err := <-deleteDone:
		if err != nil {
			t.Fatalf("remote delete error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("remote delete did not finish after mailbox sync")
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("mailbox was recreated by stale sync after remote delete")
	}
}

func TestCreateICloudMailboxUsesSessionAfterGateWait(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-create-fresh-session"
	accountID := "account-create-fresh-session"
	requestSeen := make(chan string, 2)
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestSeen <- r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/hme/generate":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":"candidate@icloud.com"}}`))
		case "/v1/hme/reserve":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":{"anonymousId":"created-fresh-remote","hme":"created-fresh@icloud.com","label":"FRESH","active":true}}}`))
		default:
			t.Fatalf("unexpected create request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer remoteServer.Close()

	initial := ICloudSession{
		OwnerID:            ownerID,
		AccountID:          accountID,
		AppleID:            "create-fresh-session@example.com",
		DSID:               "create-fresh-session-dsid",
		ClientID:           "create-fresh-session-client",
		ClientBuildNumber:  "create-fresh-session-build",
		MasteringNumber:    "create-fresh-session-master",
		PremiumMailBaseURL: remoteServer.URL,
		IsICloudPlus:       true,
		CanCreateHME:       true,
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

	type createResult struct {
		mailbox Mailbox
		remote  ICloudRemoteMailbox
		err     error
	}
	done := make(chan createResult, 1)
	go func() {
		mailbox, remote, createErr := handler.createICloudMailboxForOwner(
			context.Background(),
			ownerID,
			accountID,
			"FRESH",
			"",
		)
		done <- createResult{mailbox: mailbox, remote: remote, err: createErr}
	}()

	select {
	case <-requestSeen:
		releaseAccountOperation()
		t.Fatal("iCloud mailbox create ran before the account gate was released")
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

	for i := 0; i < 2; i++ {
		select {
		case cookie := <-requestSeen:
			if !strings.Contains(cookie, "session=fresh-cookie") {
				t.Fatalf("create request cookie = %q, want fresh-cookie", cookie)
			}
		case <-time.After(time.Second):
			t.Fatal("iCloud mailbox create request was not sent")
		}
	}
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("iCloud mailbox create error = %v", result.err)
		}
		if result.remote.AnonymousID != "created-fresh-remote" || result.mailbox.Email != "created-fresh@icloud.com" {
			t.Fatalf("create result = mailbox:%+v remote:%+v", result.mailbox, result.remote)
		}
	case <-time.After(time.Second):
		t.Fatal("iCloud mailbox create did not finish")
	}
}

func TestICloudProtocolLoginStartWaitsForAccountOperationAndUsesFreshProxy(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "login-start-gate", "login-start-password")
	account, err := store.AddAccountForOwnerWithProxy(user.ID, "Login start", "login-start@example.com", "", "127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}

	seenProxy := make(chan string, 1)
	handler.startICloudProtocolLogin = func(
		ctx context.Context,
		appleID, password, defaultHost, clientID string,
		pendingStore *appleAuthPendingStore,
		twoFactorMethod, proxyURL, ownerID string,
	) (appleAuthStartResult, error) {
		seenProxy <- proxyURL
		return appleAuthStartResult{
			Session: ICloudSession{
				AppleID: account.AppleID,
			},
			Message: "login started",
		}, nil
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/start", strings.NewReader(fmt.Sprintf(
		`{"apple_id":%q,"password":"secret-password","account_id":%q}`,
		account.AppleID,
		account.ID,
	)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(rr, req)
		close(done)
	}()

	select {
	case <-seenProxy:
		releaseAccountOperation()
		t.Fatal("iCloud protocol login started before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := store.UpdateAccountProxyForOwner(user.ID, account.ID, "127.0.0.1:7891"); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case proxyURL := <-seenProxy:
		if proxyURL != "http://127.0.0.1:7891" {
			t.Fatalf("login proxy = %q, want fresh account proxy", proxyURL)
		}
	case <-time.After(time.Second):
		t.Fatal("iCloud protocol login did not start after the account gate was released")
	}
	select {
	case <-done:
		if rr.Code != http.StatusOK {
			t.Fatalf("iCloud protocol login status = %d body=%s", rr.Code, rr.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("iCloud protocol login request did not finish")
	}
}

func TestAppleAccountLoginStartWaitsForAccountOperationAndUsesFreshProxy(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "apple-login-start-gate", "apple-login-start-password")
	account, err := store.AddAccountForOwnerWithProxy(user.ID, "Apple login start", "apple-login-start@example.com", "", "127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}

	seenProxy := make(chan string, 1)
	handler.startAppleAccountLogin = func(
		ctx context.Context,
		appleID, password string,
		pendingStore *appleAuthPendingStore,
		twoFactorMethod, proxyURL, ownerID string,
	) (appleAuthStartResult, error) {
		seenProxy <- proxyURL
		return appleAuthStartResult{
			Session: ICloudSession{
				AppleID: account.AppleID,
			},
			Message: "login started",
		}, nil
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/apple-account/login/start", strings.NewReader(fmt.Sprintf(
		`{"apple_id":%q,"password":"secret-password","account_id":%q}`,
		account.AppleID,
		account.ID,
	)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(rr, req)
		close(done)
	}()

	select {
	case <-seenProxy:
		releaseAccountOperation()
		t.Fatal("Apple Account login started before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := store.UpdateAccountProxyForOwner(user.ID, account.ID, "127.0.0.1:7891"); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case proxyURL := <-seenProxy:
		if proxyURL != "http://127.0.0.1:7891" {
			t.Fatalf("Apple Account login proxy = %q, want fresh account proxy", proxyURL)
		}
	case <-time.After(time.Second):
		t.Fatal("Apple Account login did not start after the account gate was released")
	}
	select {
	case <-done:
		if rr.Code != http.StatusOK {
			t.Fatalf("Apple Account login status = %d body=%s", rr.Code, rr.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("Apple Account login request did not finish")
	}
}

func TestICloudProtocolLogin2FAWaitsForAccountOperationAndUsesFreshProxy(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "login-2fa-gate", "login-2fa-password")
	account, err := store.AddAccountForOwnerWithProxy(user.ID, "Login 2FA", "login-2fa@example.com", "", "127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := handler.icloudProtocolLogins.putForOwner(&appleAuthSession{
		AppleID:   account.AppleID,
		ProxyURL:  "http://127.0.0.1:7890",
		Scnt:      "pending-scnt",
		SessionID: "pending-session",
	}, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	handler.icloudProtocolLogins.setLoginTarget(pending.ID, user.ID, account.ID)

	seenProxy := make(chan string, 1)
	handler.submitICloudProtocol2FA = func(ctx context.Context, pending appleAuthPending, code string) (ICloudSession, error) {
		if pending.Session == nil {
			t.Fatal("2FA pending session is nil")
		}
		seenProxy <- pending.Session.ProxyURL
		return ICloudSession{AppleID: account.AppleID}, nil
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/2fa", strings.NewReader(fmt.Sprintf(
		`{"pending_id":%q,"code":"123456"}`,
		pending.ID,
	)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(rr, req)
		close(done)
	}()

	select {
	case <-seenProxy:
		releaseAccountOperation()
		t.Fatal("iCloud protocol 2FA started before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := store.UpdateAccountProxyForOwner(user.ID, account.ID, "127.0.0.1:7891"); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case proxyURL := <-seenProxy:
		if proxyURL != "http://127.0.0.1:7891" {
			t.Fatalf("iCloud protocol 2FA proxy = %q, want fresh account proxy", proxyURL)
		}
	case <-time.After(time.Second):
		t.Fatal("iCloud protocol 2FA did not start after the account gate was released")
	}
	select {
	case <-done:
		if rr.Code != http.StatusOK {
			t.Fatalf("iCloud protocol 2FA status = %d body=%s", rr.Code, rr.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("iCloud protocol 2FA request did not finish")
	}
}

func TestAppleAccountLogin2FAWaitsForAccountOperationAndUsesFreshProxy(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "apple-login-2fa-gate", "apple-login-2fa-password")
	account, err := store.AddAccountForOwnerWithProxy(user.ID, "Apple login 2FA", "apple-login-2fa@example.com", "", "127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := handler.appleAccountLogins.putForOwner(&appleAuthSession{
		AppleID:   account.AppleID,
		ProxyURL:  "http://127.0.0.1:7890",
		Scnt:      "pending-scnt",
		SessionID: "pending-session",
	}, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	handler.appleAccountLogins.setLoginTarget(pending.ID, user.ID, account.ID)

	seenProxy := make(chan string, 1)
	handler.submitAppleAccount2FA = func(ctx context.Context, pending appleAuthPending, code string, phoneNumber json.RawMessage) (ICloudSession, error) {
		if pending.Session == nil {
			t.Fatal("Apple Account 2FA pending session is nil")
		}
		seenProxy <- pending.Session.ProxyURL
		return ICloudSession{AppleID: account.AppleID}, nil
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/apple-account/login/2fa", strings.NewReader(fmt.Sprintf(
		`{"pending_id":%q,"code":"123456"}`,
		pending.ID,
	)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(rr, req)
		close(done)
	}()

	select {
	case <-seenProxy:
		releaseAccountOperation()
		t.Fatal("Apple Account 2FA started before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := store.UpdateAccountProxyForOwner(user.ID, account.ID, "127.0.0.1:7891"); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case proxyURL := <-seenProxy:
		if proxyURL != "http://127.0.0.1:7891" {
			t.Fatalf("Apple Account 2FA proxy = %q, want fresh account proxy", proxyURL)
		}
	case <-time.After(time.Second):
		t.Fatal("Apple Account 2FA did not start after the account gate was released")
	}
	select {
	case <-done:
		if rr.Code != http.StatusOK {
			t.Fatalf("Apple Account 2FA status = %d body=%s", rr.Code, rr.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("Apple Account 2FA request did not finish")
	}
}

func TestClaimMailboxSkipsBusyAccountAndClaimsNext(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{APIKey: "global-api-key"}, store, discardLogger()).(*Server)
	busyMailbox, err := store.AddMailboxForOwnerWithRemote("owner-claim-busy", "account-claim-busy", ICloudRemoteMailbox{
		AnonymousID: "claim-busy-remote",
		Origin:      "ICLOUD_WEB",
		Email:       "claim-busy@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	nextMailbox, err := store.AddMailboxForOwnerWithRemote("owner-claim-free", "account-claim-free", ICloudRemoteMailbox{
		AnonymousID: "claim-free-remote",
		Origin:      "ICLOUD_WEB",
		Email:       "claim-free@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	releaseBusy, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(busyMailbox.OwnerID, busyMailbox.AccountID),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseBusy()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/claim", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "global-api-key")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("claim status = %d body=%s", rr.Code, rr.Body.String())
	}
	var response struct {
		Success bool          `json:"success"`
		Mailbox publicMailbox `json:"mailbox"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Success || response.Mailbox.ID != nextMailbox.ID {
		t.Fatalf("claim response = %+v body=%s, want mailbox %s", response, rr.Body.String(), nextMailbox.ID)
	}
	busy, ok := store.FindMailboxByID(busyMailbox.ID)
	if !ok || busy.Status != StatusAvailable {
		t.Fatalf("busy mailbox = %+v ok=%t, want still available", busy, ok)
	}
	claimed, ok := store.FindMailboxByID(nextMailbox.ID)
	if !ok || claimed.Status != StatusUsed {
		t.Fatalf("free mailbox = %+v ok=%t, want used", claimed, ok)
	}
}

func TestClaimMailboxSkipsBusyAccountWhenNoOtherMailboxIsAvailable(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{APIKey: "global-api-key"}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("owner-claim-gate", "account-claim-gate", ICloudRemoteMailbox{
		AnonymousID: "claim-gate-remote",
		Origin:      "ICLOUD_WEB",
		Email:       "claim-gate@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(mailbox.OwnerID, mailbox.AccountID),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseAccountOperation()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/claim", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "global-api-key")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("claim status = %d body=%s, want 200 no-available response", rr.Code, rr.Body.String())
	}
	var response struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Success || response.Code != "no_available_mailbox" {
		t.Fatalf("claim response = %+v body=%s, want no_available_mailbox", response, rr.Body.String())
	}
	current, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || current.Status != StatusAvailable {
		t.Fatalf("busy mailbox = %+v ok=%t, want still available", current, ok)
	}
}

func TestICloudIMAPSyncSerializesWithRemoteDelete(t *testing.T) {
	store := newTestStore(t)
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-imap-delete-race"
	accountID := "account-imap-delete-race"
	mailbox, err := store.AddMailboxForOwnerWithRemote(ownerID, accountID, ICloudRemoteMailbox{
		AnonymousID: "remote-imap-delete-race",
		Origin:      "ICLOUD_WEB",
		Email:       "imap-race@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: accountID,
		AppleID:   "imap-delete-race@example.com",
		Cookies:   []SessionCookie{{Name: "session", Value: "cookie"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "session", Value: "cookie"}},
		}, {
			Kind:            LoginStateICloudIMAP,
			IMAPEmail:       "imap-delete-race@icloud.com",
			IMAPUsername:    "imap-delete-race@icloud.com",
			IMAPHost:        defaultICloudIMAPHost,
			IMAPPort:        defaultICloudIMAPPort,
			IMAPAppPassword: "app-password",
			SavedAt:         time.Now(),
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}

	syncStarted := make(chan struct{})
	releaseSync := make(chan struct{})
	server.syncCodeMailboxBatchWithCursor = func(context.Context, LoginState, []Mailbox, time.Time, string, int) (iCloudIMAPSyncResult, error) {
		close(syncStarted)
		<-releaseSync
		return iCloudIMAPSyncResult{}, nil
	}
	server.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		return nil
	}

	syncDone := make(chan error, 1)
	go func() {
		_, syncErr := server.syncMailboxCodeBatchForOwnerWithLimit(
			context.Background(),
			ownerID,
			[]Mailbox{mailbox},
			time.Time{},
			"",
			10,
		)
		syncDone <- syncErr
	}()
	select {
	case <-syncStarted:
	case <-time.After(time.Second):
		t.Fatal("IMAP sync did not reach the injected provider")
	}

	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- server.deleteMailboxForRequest(context.Background(), mailbox.ID, true)
	}()
	select {
	case err := <-deleteDone:
		close(releaseSync)
		t.Fatalf("remote delete completed while IMAP sync held the account operation: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseSync)
	select {
	case err := <-syncDone:
		if err != nil {
			t.Fatalf("IMAP sync error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("IMAP sync did not finish")
	}
	select {
	case err := <-deleteDone:
		if err != nil {
			t.Fatalf("remote delete error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("remote delete did not finish after IMAP sync")
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("mailbox was recreated by stale IMAP sync after remote delete")
	}
}

func TestSyncMailboxBatchRevalidatesMailboxAfterGateWait(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-sync-revalidate"
	accountID := "account-sync-revalidate"
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: accountID,
		AppleID:   "sync-revalidate@example.com",
		LoginStates: []LoginState{{
			Kind: LoginStateICloudWeb,
			Cookies: []SessionCookie{{
				Name:   "session",
				Value:  "sync-revalidate",
				Domain: "127.0.0.1",
				Path:   "/",
			}},
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "sync-revalidate", "sync-revalidate@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	providerCalled := make(chan struct{}, 1)
	handler.syncMailboxBatch = func(context.Context, ICloudSession, []Mailbox, time.Time, string, int) (map[string][]ICloudSyncedMessage, error) {
		providerCalled <- struct{}{}
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
			"OpenAI",
			10,
		)
	}()

	select {
	case <-providerCalled:
		releaseAccountOperation()
		t.Fatal("mailbox sync provider ran before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}
	if err := store.DeleteMailbox(mailbox.ID); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("mailbox sync error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("mailbox sync did not finish after the account gate was released")
	}
	select {
	case <-providerCalled:
		t.Fatal("mailbox sync provider received a mailbox deleted while it waited for the account gate")
	default:
	}
}

func TestSyncMailboxCodeBatchRevalidatesMailboxAfterGateWait(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-imap-sync-revalidate"
	accountID := "account-imap-sync-revalidate"
	session := testIMAPSession(ownerID, accountID, "imap-sync-revalidate@icloud.com")
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "imap-sync-revalidate", "imap-sync-revalidate.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	providerCalled := make(chan struct{}, 1)
	handler.syncCodeMailboxBatchWithCursor = func(context.Context, LoginState, []Mailbox, time.Time, string, int) (iCloudIMAPSyncResult, error) {
		providerCalled <- struct{}{}
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
	case <-providerCalled:
		releaseAccountOperation()
		t.Fatal("IMAP sync provider ran before the account gate was released")
	case <-time.After(100 * time.Millisecond):
	}
	if err := store.DeleteMailbox(mailbox.ID); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("IMAP sync error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("IMAP sync did not finish after the account gate was released")
	}
	select {
	case <-providerCalled:
		t.Fatal("IMAP sync provider received a mailbox deleted while it waited for the account gate")
	default:
	}
}

func TestUpsertMailboxFromRemoteRejectsRemoteIdentityCollision(t *testing.T) {
	store := newTestStore(t)
	existing, err := store.AddMailboxForOwnerWithRemote("owner-identity", "account-identity", ICloudRemoteMailbox{
		AnonymousID: "remote-old",
		Origin:      "ICLOUD_WEB",
		Email:       "identity-collision@icloud.com",
		Label:       "original",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = store.UpsertMailboxFromRemote("owner-identity", "account-identity", ICloudRemoteMailbox{
		AnonymousID: "remote-new",
		Origin:      "ICLOUD_WEB",
		Email:       existing.Email,
		Label:       "must-not-overwrite",
		IsActive:    true,
	}, "")
	if !isCodedError(err, "mailbox_remote_identity_conflict") {
		t.Fatalf("identity collision error = %#v, want mailbox_remote_identity_conflict", err)
	}
	unchanged, ok := store.FindMailboxByID(existing.ID)
	if !ok {
		t.Fatal("existing mailbox disappeared after identity collision")
	}
	if unchanged.RemoteAnonymousID != "remote-old" || unchanged.Label != "original" {
		t.Fatalf("existing mailbox changed after identity collision: %+v", unchanged)
	}
}

func TestAddMailboxForOwnerWithRemoteRejectsRemoteIdentityCollision(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.AddMailboxForOwnerWithRemote("owner-add-identity", "account-add-identity", ICloudRemoteMailbox{
		AnonymousID: "duplicate-remote-id",
		Origin:      "APPLE_ACCOUNT",
		Email:       "first-add-identity@icloud.com",
		IsActive:    true,
	}, ""); err != nil {
		t.Fatal(err)
	}
	_, err := store.AddMailboxForOwnerWithRemote("owner-add-identity", "account-add-identity", ICloudRemoteMailbox{
		AnonymousID: "duplicate-remote-id",
		Origin:      "APPLE_ACCOUNT",
		Email:       "second-add-identity@icloud.com",
		IsActive:    true,
	}, "")
	if !isCodedError(err, "mailbox_remote_identity_conflict") {
		t.Fatalf("duplicate remote identity error = %#v, want mailbox_remote_identity_conflict", err)
	}
	if got := len(store.Snapshot().Mailboxes); got != 1 {
		t.Fatalf("mailbox count after duplicate remote identity = %d, want 1", got)
	}
}

func TestCreateICloudMailboxDeletesFreshRemoteWhenLocalSaveFails(t *testing.T) {
	var paths []string
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/hme/generate":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":"duplicate-create@icloud.com"}}`))
		case "POST /v1/hme/reserve":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":{"anonymousId":"fresh-remote-id","hme":"duplicate-create@icloud.com","active":true}}}`))
		case "POST /v1/hme/deactivate", "POST /v1/hme/delete":
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer remoteServer.Close()

	store := newTestStore(t)
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	account, err := store.AddAccountForOwner("", "Create cleanup", "create-cleanup@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSession(ICloudSession{
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "create-cleanup-dsid",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		PremiumMailBaseURL: remoteServer.URL,
		Host:               "www.icloud.com",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", account.ID, "Existing", "duplicate-create@icloud.com"); err != nil {
		t.Fatal(err)
	}

	_, _, err = server.createICloudMailboxForOwner(context.Background(), "", account.ID, "New", "")
	if !isCodedError(err, "mailbox_exists") {
		t.Fatalf("create error = %#v, want mailbox_exists", err)
	}
	wantPaths := []string{
		"POST /v1/hme/generate",
		"POST /v1/hme/reserve",
		"POST /v1/hme/deactivate",
		"POST /v1/hme/delete",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("remote paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestMarkMailboxesAPIExportedCanBeScopedToOwner(t *testing.T) {
	store := newTestStore(t)
	ownerOne, err := store.AddMailboxForOwner("owner-one", "", "ONE", "owner-one-export@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	ownerTwo, err := store.AddMailboxForOwner("owner-two", "", "TWO", "owner-two-export@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	markedAt := time.Now()
	if count, err := store.MarkMailboxesAPIExportedForOwner("owner-one", []string{ownerOne.ID, ownerTwo.ID}, markedAt); err != nil {
		t.Fatal(err)
	} else if count != 1 {
		t.Fatalf("scoped exported count = %d, want 1", count)
	}
	updatedOne, _ := store.FindMailboxByID(ownerOne.ID)
	updatedTwo, _ := store.FindMailboxByID(ownerTwo.ID)
	if updatedOne.APIExportedAt.IsZero() || !updatedTwo.APIExportedAt.IsZero() {
		t.Fatalf("scoped export state = owner-one=%+v owner-two=%+v", updatedOne, updatedTwo)
	}
}

func TestAdminTargetedIMAPCheckReturnsTargetOwnerSession(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	handler.checkIMAPLogin = func(context.Context, string, string) error {
		return nil
	}
	adminCookie, _ := registerTestUser(t, handler, "admin-target-check", "admin123")
	_, user := registerTestUser(t, handler, "user-target-check", "user123")
	account, err := store.AddAccountForOwner(user.ID, "Target account", "target@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:   user.ID,
		AccountID: account.ID,
		AppleID:   account.AppleID,
		LoginStates: []LoginState{{
			Kind:            LoginStateICloudIMAP,
			IMAPEmail:       account.AppleID,
			IMAPAppPassword: "app-secret",
			LastCheckOK:     false,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/check?owner_id="+url.QueryEscape(user.ID), strings.NewReader(
		fmt.Sprintf(`{"account_id":%q}`, account.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("targeted check status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Sessions []publicICloudSession `json:"sessions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Sessions) != 1 || body.Sessions[0].AccountID != account.ID {
		t.Fatalf("targeted response sessions = %+v, want account %s", body.Sessions, account.ID)
	}
	if !body.Sessions[0].ICloudIMAPLoginOK {
		t.Fatalf("targeted response session not refreshed: %+v", body.Sessions[0])
	}
}

func TestAdminTargetedGlobalICloudCheckReturnsGlobalSession(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, admin := registerTestUser(t, handler, "admin-global-check", "admin123")
	adminAccount, err := store.AddAccountForOwner(admin.ID, "Admin account", "admin@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(admin.ID, ICloudSession{
		OwnerID:   admin.ID,
		AccountID: adminAccount.ID,
		AppleID:   adminAccount.AppleID,
	}); err != nil {
		t.Fatal(err)
	}
	account, err := store.AddAccountForOwner("", "Global account", "global@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.SaveICloudSessionForOwner("", ICloudSession{
		AccountID: account.ID,
		AppleID:   account.AppleID,
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "global-scnt",
			APIKey:          "global-api-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(10 * time.Minute),
			LastCheckOK:     true,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/session/check?owner_id=__global", strings.NewReader(
		fmt.Sprintf(`{"account_id":%q}`, account.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("global targeted check status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Sessions []publicICloudSession `json:"sessions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Sessions) != 1 || body.Sessions[0].AccountID != account.ID {
		t.Fatalf("global targeted response sessions = %+v, want account %s", body.Sessions, account.ID)
	}
}

func TestAdminEmptyICloudSessionCheckCoversAllOwners(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, admin := registerTestUser(t, handler, "admin-empty-session-check", "admin123")
	_, user := registerTestUser(t, handler, "user-empty-session-check", "user123")
	if err := store.SaveICloudSessionForOwner(admin.ID, testIMAPSession(admin.ID, "", "admin-empty-session-check@example.com")); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(user.ID, testIMAPSession(user.ID, "", "user-empty-session-check@example.com")); err != nil {
		t.Fatal(err)
	}

	called := make(map[string]int)
	record := func(ctx context.Context, email, appPassword string) error {
		called[email]++
		return nil
	}
	handler.checkIMAPLogin = record
	handler.checkIMAPLoginWithProxy = func(ctx context.Context, email, appPassword, proxyURL string) error {
		return record(ctx, email, appPassword)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/session/check?owner_id=all", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin empty session check status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Sessions     []publicICloudSession `json:"sessions"`
		CheckedCount int                   `json:"checked_count"`
		FailedCount  int                   `json:"failed_count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.CheckedCount != 2 || body.FailedCount != 0 {
		t.Fatalf("admin empty session check counts = %+v, want 2/0", body)
	}
	if len(body.Sessions) != 2 {
		t.Fatalf("admin empty session check sessions = %+v, want 2", body.Sessions)
	}
	if called["admin-empty-session-check@example.com"] != 1 || called["user-empty-session-check@example.com"] != 1 {
		t.Fatalf("admin empty session check calls = %+v, want both owners checked", called)
	}
	seen := map[string]bool{}
	for _, session := range body.Sessions {
		seen[session.AppleID] = true
	}
	if !seen["admin-empty-session-check@example.com"] || !seen["user-empty-session-check@example.com"] {
		t.Fatalf("admin empty session check response = %+v, want both owners", body.Sessions)
	}
}

func TestAdminEmptyIMAPLoginCheckCoversAllOwners(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, admin := registerTestUser(t, handler, "admin-empty-imap-check", "admin123")
	_, user := registerTestUser(t, handler, "user-empty-imap-check", "user123")
	if err := store.SaveICloudSessionForOwner(admin.ID, testIMAPSession(admin.ID, "", "admin-empty-imap-check@example.com")); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(user.ID, testIMAPSession(user.ID, "", "user-empty-imap-check@example.com")); err != nil {
		t.Fatal(err)
	}

	called := make(map[string]int)
	record := func(ctx context.Context, email, appPassword string) error {
		called[email]++
		return nil
	}
	handler.checkIMAPLogin = record
	handler.checkIMAPLoginWithProxy = func(ctx context.Context, email, appPassword, proxyURL string) error {
		return record(ctx, email, appPassword)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/check?owner_id=all", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin empty IMAP check status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Sessions     []publicICloudSession `json:"sessions"`
		CheckedCount int                   `json:"checked_count"`
		FailedCount  int                   `json:"failed_count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.CheckedCount != 2 || body.FailedCount != 0 {
		t.Fatalf("admin empty IMAP check counts = %+v, want 2/0", body)
	}
	if len(body.Sessions) != 2 {
		t.Fatalf("admin empty IMAP check sessions = %+v, want 2", body.Sessions)
	}
	if called["admin-empty-imap-check@example.com"] != 1 || called["user-empty-imap-check@example.com"] != 1 {
		t.Fatalf("admin empty IMAP check calls = %+v, want both owners checked", called)
	}
	seen := map[string]bool{}
	for _, session := range body.Sessions {
		seen[session.AppleID] = true
	}
	if !seen["admin-empty-imap-check@example.com"] || !seen["user-empty-imap-check@example.com"] {
		t.Fatalf("admin empty IMAP check response = %+v, want both owners", body.Sessions)
	}
}

func TestAddMailboxForOwnerWithRemotePersistsRemoteIdentity(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwnerWithRemote("owner-remote", "account-remote", ICloudRemoteMailbox{
		AnonymousID: "anonymous-123",
		Origin:      "APPLE_ACCOUNT",
		Email:       "Alias@icloud.com",
		Label:       "Remote alias",
		Note:        "remote note",
		IsActive:    true,
	}, "fallback note")
	if err != nil {
		t.Fatal(err)
	}
	if mailbox.RemoteAnonymousID != "anonymous-123" || mailbox.RemoteOrigin != "APPLE_ACCOUNT" {
		t.Fatalf("remote identity = %+v", mailbox)
	}
	if mailbox.Note != "remote note" || !mailbox.ICloudActive || mailbox.Status != StatusAvailable {
		t.Fatalf("remote mailbox state = %+v", mailbox)
	}
}

func TestMarkMailboxesRemoteMissingDisablesManagedMailbox(t *testing.T) {
	store := newTestStore(t)
	keep, err := store.AddMailboxForOwnerWithRemote("owner-sync", "account-sync", ICloudRemoteMailbox{
		AnonymousID: "keep-id",
		Origin:      "ICLOUD_WEB",
		Email:       "keep@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	missing, err := store.AddMailboxForOwnerWithRemote("owner-sync", "account-sync", ICloudRemoteMailbox{
		AnonymousID: "missing-id",
		Origin:      "ICLOUD_WEB",
		Email:       "missing@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	checkedAt := time.Now()
	count, err := store.MarkMailboxesRemoteMissing("owner-sync", "account-sync", map[string]struct{}{
		keep.Email: {},
	}, checkedAt)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("missing count = %d, want 1", count)
	}
	updated, ok := store.FindMailboxByID(missing.ID)
	if !ok {
		t.Fatal("missing mailbox not found")
	}
	if updated.ICloudActive || updated.Status != StatusDisabled || updated.RemoteMissingAt.IsZero() {
		t.Fatalf("missing mailbox state = %+v", updated)
	}
}

func TestAccountProxyForOwnerAppleID(t *testing.T) {
	store := newTestStore(t)
	_, err := store.AddAccountForOwnerWithProxy("owner-login", "Apple", "Login@Example.com", "", "http://127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}
	proxy, ok := store.AccountProxyForOwnerAppleID("owner-login", "login@example.com")
	if !ok || proxy != "http://127.0.0.1:7890" {
		t.Fatalf("proxy = %q, ok=%t", proxy, ok)
	}
}

func TestSessionForMailboxDoesNotFallbackAcrossBoundAccount(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	if err := store.SaveICloudSessionForOwner("owner-bound", ICloudSession{
		AccountID: "account-a",
		AppleID:   "a@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	mailbox := Mailbox{OwnerID: "owner-bound", AccountID: "account-b", Email: "b@icloud.com"}
	if _, ok := handler.sessionForMailbox(mailbox.OwnerID, mailbox.AccountID); ok {
		t.Fatal("session lookup fell back to a different bound account")
	}
}

func TestSessionForMailboxDoesNotGuessForUnboundMailboxWithMultipleAccounts(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	for _, session := range []ICloudSession{
		{OwnerID: "owner-unbound", AccountID: "account-a", AppleID: "a@example.com"},
		{OwnerID: "owner-unbound", AccountID: "account-b", AppleID: "b@example.com"},
	} {
		if err := store.SaveICloudSessionForOwner(session.OwnerID, session); err != nil {
			t.Fatal(err)
		}
	}
	mailbox := Mailbox{OwnerID: "owner-unbound", Email: "legacy@icloud.com"}
	if _, ok := handler.sessionForMailbox(mailbox.OwnerID, mailbox.AccountID); ok {
		t.Fatal("unbound mailbox was assigned to an arbitrary account")
	}
}

func TestAdminGlobalAccountKeepsGlobalDataOwner(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	admin, err := store.CreateUser("admin-owner", "admin123")
	if err != nil {
		t.Fatal(err)
	}
	account, err := store.AddAccountForOwner("", "Global Apple", "global@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := handler.dataOwnerIDForAccount(admin.ID, account.ID); got != "" {
		t.Fatalf("global account data owner = %q, want empty global owner", got)
	}
	session := ICloudSession{AccountID: account.ID}
	if got := handler.dataOwnerIDForSession(admin.ID, session); got != "" {
		t.Fatalf("global session data owner = %q, want empty global owner", got)
	}
}

func TestAdminManageDataIncludesAllSavedSessions(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "manage-sessions", "admin123")
	if err := store.SaveICloudSessionForOwner("", ICloudSession{
		AccountID: "global-account",
		AppleID:   "global@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner("owner-session", ICloudSession{
		AccountID: "owner-account",
		AppleID:   "owner@example.com",
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/manage/data", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("manage data status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		ICloudSessions []publicICloudSession `json:"icloud_sessions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.ICloudSessions) != 2 {
		t.Fatalf("manage sessions = %+v, want 2 sessions", body.ICloudSessions)
	}
}

func TestAppleAccountOnlySessionCountsAsSavedInManagementSummary(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	_, user := registerTestUser(t, handler, "apple-summary", "admin123")
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID: user.ID,
		AppleID: "apple-summary@example.com",
		LoginStates: []LoginState{{
			Kind:    LoginStateAppleAccount,
			Scnt:    "scnt",
			APIKey:  "api-key",
			Cookies: []SessionCookie{{Name: "aid", Value: "cookie"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	summaries := handler.publicUserSummaries(store.Users(), store.Snapshot())
	for _, summary := range summaries {
		if summary.OwnerID == user.ID {
			if !summary.ICloudSessionSaved {
				t.Fatalf("Apple Account-only session was not counted: %+v", summary)
			}
			return
		}
	}
	t.Fatalf("summary for user %q not found: %+v", user.ID, summaries)
}

func TestAppleAccountOnlySessionMarksAccountActive(t *testing.T) {
	store := newTestStore(t)
	_, user := registerTestUser(t, NewServer(Config{}, store, discardLogger()), "apple-account-status", "admin123")
	account, err := store.AddAccountForOwner(user.ID, "Apple Account", "apple-account-status@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:   user.ID,
		AccountID: account.ID,
		AppleID:   account.AppleID,
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Scnt:   "scnt",
			APIKey: "api-key",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	updated, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatalf("account %q not found", account.ID)
	}
	if updated.ICloudStatus != ICloudStatusActive {
		t.Fatalf("Apple Account-only account status = %q, want %q", updated.ICloudStatus, ICloudStatusActive)
	}
}

func TestNestedWebCookiesMarkAccountActive(t *testing.T) {
	store := newTestStore(t)
	_, user := registerTestUser(t, NewServer(Config{}, store, discardLogger()), "nested-web-status", "admin123")
	account, err := store.AddAccountForOwner(user.ID, "iCloud Web", "nested-web-status@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:      user.ID,
		AccountID:    account.ID,
		AppleID:      account.AppleID,
		IsICloudPlus: true,
		CanCreateHME: true,
		LoginStates: []LoginState{{
			Kind: LoginStateICloudWeb,
			Cookies: []SessionCookie{{
				Name:  "session",
				Value: "cookie-value",
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	updated, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatalf("account %q not found", account.ID)
	}
	if updated.ICloudStatus != ICloudStatusActive {
		t.Fatalf("nested web account status = %q, want %q", updated.ICloudStatus, ICloudStatusActive)
	}
}

func TestHealthRecognizesAppleAccountCreateSession(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{APIKey: "global-api-key"}, store, discardLogger())
	if err := store.SaveICloudSession(ICloudSession{
		AppleID: "apple-health@example.com",
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Scnt:   "scnt",
			APIKey: "api-key",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Authorization", "Bearer global-api-key")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("health status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		ICloudActive bool `json:"icloud_active"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.ICloudActive {
		t.Fatalf("Apple Account create session was reported inactive: %s", rr.Body.String())
	}
}

func TestHealthReportsProviderUnavailableWithoutFailingService(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{APIKey: "global-api-key"}, store, discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Authorization", "Bearer global-api-key")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("health status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success      bool `json:"success"`
		APIActive    bool `json:"api_active"`
		ICloudActive bool `json:"icloud_active"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || !body.APIActive || body.ICloudActive {
		t.Fatalf("health body = %s, want service healthy with inactive iCloud provider", rr.Body.String())
	}
}

func TestHealthAllowsUnauthenticatedLivenessWhenAPIKeyConfigured(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{APIKey: "global-api-key"}, store, discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unauthenticated health status = %d body=%s, want 200 for container liveness", rr.Code, rr.Body.String())
	}
	var body struct {
		Success   bool `json:"success"`
		APIActive bool `json:"api_active"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || !body.APIActive {
		t.Fatalf("unauthenticated health body = %s, want success with configured API key", rr.Body.String())
	}
}

func TestICloudClientListPrivacyMailboxesAcceptsNestedWebCookies(t *testing.T) {
	var gotCookie string
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/hme/list" {
			t.Fatalf("list request = %s %s", r.Method, r.URL.Path)
		}
		gotCookie = r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"timestamp":1,"result":{"hmeEmails":[]}}`))
	}))
	defer remoteServer.Close()

	_, err := NewICloudClient().ListPrivacyMailboxes(t.Context(), ICloudSession{
		PremiumMailBaseURL: remoteServer.URL,
		DSID:               "dsid",
		LoginStates: []LoginState{{
			Kind: LoginStateICloudWeb,
			Cookies: []SessionCookie{{
				Name:   "session",
				Value:  "cookie-value",
				Domain: "127.0.0.1",
				Path:   "/",
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotCookie != "session=cookie-value" {
		t.Fatalf("nested web cookie header = %q, want session=cookie-value", gotCookie)
	}
}

func TestGlobalSessionReadDeduplicatesLegacyAndMigratedCopies(t *testing.T) {
	store := newTestStore(t)
	store.state.ICloudSession = &ICloudSession{
		AccountID: "global-account",
		AppleID:   "global@example.com",
		Cookies:   []SessionCookie{{Name: "legacy", Value: "cookie"}},
	}
	store.state.ICloudSessions = []ICloudSession{{
		AccountID: "global-account",
		AppleID:   "global@example.com",
		LoginStates: []LoginState{{
			Kind: LoginStateAppleAccount,
			Scnt: "scnt",
		}},
	}}

	sessions := store.ICloudSessionsForOwner("")
	if len(sessions) != 1 {
		t.Fatalf("global sessions = %+v, want one merged session", sessions)
	}
	if len(sessions[0].Cookies) != 1 || len(sessions[0].LoginStates) != 1 {
		t.Fatalf("merged global session lost state: %+v", sessions[0])
	}
}

func TestSaveGlobalSessionUsesTypedSessionsOnly(t *testing.T) {
	store := newTestStore(t)
	store.state.ICloudSession = &ICloudSession{
		AccountID: "global-account",
		AppleID:   "legacy@example.com",
		Cookies:   []SessionCookie{{Name: "legacy", Value: "cookie"}},
	}
	store.state.ICloudSessions = []ICloudSession{{
		AccountID: "global-account",
		AppleID:   "legacy@example.com",
		LoginStates: []LoginState{{
			Kind: LoginStateAppleAccount,
			Scnt: "stale-scnt",
		}},
	}}

	if err := store.SaveICloudSessionForOwner("", ICloudSession{
		AccountID: "global-account",
		AppleID:   "fresh@example.com",
		Cookies:   []SessionCookie{{Name: "fresh", Value: "cookie"}},
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Scnt:   "fresh-scnt",
			APIKey: "fresh-api",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	state := store.Snapshot()
	if state.ICloudSession != nil {
		t.Fatalf("global save left legacy root session behind: %+v", state.ICloudSession)
	}
	sessions := store.ICloudSessionsForOwner("")
	if len(sessions) != 1 {
		t.Fatalf("global sessions = %+v, want one typed session", sessions)
	}
	got := sessions[0]
	if got.AppleID != "fresh@example.com" || len(got.Cookies) != 1 || got.Cookies[0].Value != "cookie" {
		t.Fatalf("global save did not keep the fresh typed session: %+v", got)
	}
	if len(got.LoginStates) != 1 || got.LoginStates[0].Scnt != "fresh-scnt" || got.LoginStates[0].APIKey != "fresh-api" {
		t.Fatalf("global save kept stale login state: %+v", got)
	}
}

func TestAdminManagementSessionsDeduplicateLegacyAndMigratedCopies(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "manage-dedupe", "admin123")
	store.state.ICloudSession = &ICloudSession{
		AccountID: "global-account",
		AppleID:   "global@example.com",
		Cookies:   []SessionCookie{{Name: "legacy", Value: "cookie"}},
	}
	store.state.ICloudSessions = []ICloudSession{{
		AccountID: "global-account",
		AppleID:   "global@example.com",
		LoginStates: []LoginState{{
			Kind: LoginStateAppleAccount,
			Scnt: "scnt",
		}},
	}}

	req := httptest.NewRequest(http.MethodGet, "/api/manage/data", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("manage data status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		ICloudSessions []publicICloudSession `json:"icloud_sessions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.ICloudSessions) != 1 {
		t.Fatalf("management sessions = %+v, want one merged session", body.ICloudSessions)
	}
}

func TestAdminCanSaveCreateSettingsForExistingGlobalAccount(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, adminUser := registerTestUser(t, handler, "settings-global", "admin123")
	account, err := store.AddAccountForOwner("", "Global Apple", "global@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	body, err := json.Marshal(map[string]any{"account_ids": []string{account.ID}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/create-settings?owner_id=__global", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("global account settings status = %d body=%s", rr.Code, rr.Body.String())
	}
	saved := store.CreateSettingsForOwner(adminUser.ID)
	if len(saved.AccountIDs) != 1 || saved.AccountIDs[0] != account.ID {
		t.Fatalf("saved settings = %+v", saved)
	}
}

func TestAdminCanCreateMailboxForUserOwnedAccount(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "create-admin", "admin123")
	_, user := registerTestUser(t, handler, "create-user", "user123")
	account, err := store.AddAccountForOwner(user.ID, "User Apple", "user@example.com", "")
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

	var gotOwnerID, gotAccountID string
	handler.createMailboxForOwner = func(_ context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		gotOwnerID = ownerID
		gotAccountID = accountID
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, "created-for-user@icloud.com")
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{
			Email:    mailbox.Email,
			Label:    mailbox.Label,
			IsActive: true,
			Origin:   "APPLE_ACCOUNT",
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create?owner_id="+url.QueryEscape(user.ID), strings.NewReader(
		fmt.Sprintf(`{"account_ids":[%q],"label":"USER","note":"test"}`, account.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("admin create status = %d body=%s", rr.Code, rr.Body.String())
	}
	if gotOwnerID != user.ID || gotAccountID != account.ID {
		t.Fatalf("create owner/account = %q/%q, want %q/%q", gotOwnerID, gotAccountID, user.ID, account.ID)
	}
}

func TestAdminCanSyncUserOwnedAccount(t *testing.T) {
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/hme/list" {
			t.Fatalf("sync request = %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"timestamp":1,"result":{"hmeEmails":[{"anonymousId":"remote-1","hme":"synced-for-user@icloud.com","isActive":true}]}}`))
	}))
	defer remoteServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "sync-admin", "admin123")
	_, user := registerTestUser(t, handler, "sync-user", "user123")
	account, err := store.AddAccountForOwner(user.ID, "User Apple", "user@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		PremiumMailBaseURL: remoteServer.URL,
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/sync?owner_id="+url.QueryEscape(user.ID), strings.NewReader(
		fmt.Sprintf(`{"account_id":%q}`, account.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin sync status = %d body=%s", rr.Code, rr.Body.String())
	}
	mailbox, ok := store.FindMailboxByEmail("synced-for-user@icloud.com")
	if !ok {
		t.Fatal("synced mailbox not found")
	}
	if mailbox.OwnerID != user.ID || mailbox.AccountID != account.ID {
		t.Fatalf("synced mailbox owner/account = %q/%q, want %q/%q", mailbox.OwnerID, mailbox.AccountID, user.ID, account.ID)
	}
}

func TestAdminCanStartSchedulerForUserOwnedAccount(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "scheduler-admin", "admin123")
	_, user := registerTestUser(t, handler, "scheduler-user", "user123")
	account, err := store.AddAccountForOwner(user.ID, "User Apple", "user@example.com", "")
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
	handler.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		<-ctx.Done()
		return Mailbox{}, ICloudRemoteMailbox{}, ctx.Err()
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/start?owner_id="+url.QueryEscape(user.ID), strings.NewReader(
		fmt.Sprintf(`{"account_ids":[%q],"interval_seconds":3600}`, account.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin scheduler start status = %d body=%s", rr.Code, rr.Body.String())
	}

	stopReq := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/stop", strings.NewReader(`{}`))
	stopReq.Header.Set("Content-Type", "application/json")
	stopReq.AddCookie(adminCookie)
	addClosureTestCSRF(stopReq, adminCookie)
	stopRR := httptest.NewRecorder()
	handler.ServeHTTP(stopRR, stopReq)
	if stopRR.Code != http.StatusOK {
		t.Fatalf("admin scheduler stop status = %d body=%s", stopRR.Code, stopRR.Body.String())
	}
}

func TestMailboxCreateRejectsUnknownAccountID(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "unknown-account", "admin123")

	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes", strings.NewReader(`{"account_id":"missing-account","label":"invalid","email":"invalid@icloud.com"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown account mailbox create status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "account_not_found" {
		t.Fatalf("unknown account mailbox create code = %q", body.Code)
	}
}

func TestMailboxGroupsUseFilteredRows(t *testing.T) {
	accounts := mailboxAccountMap([]Account{
		{ID: "account-a", Label: "A", AppleID: "a@example.com"},
		{ID: "account-b", Label: "B", AppleID: "b@example.com"},
	})
	mailboxes := []Mailbox{
		{ID: "a-1", AccountID: "account-a", Email: "a1@icloud.com"},
		{ID: "b-1", AccountID: "account-b", Email: "b1@icloud.com"},
	}
	filtered := filterMailboxesForList(mailboxes, accounts, url.Values{"account_key": []string{"account-a"}})
	groups := publicMailboxGroups(filtered, accounts)
	if len(groups) != 1 || groups[0].AccountID != "account-a" || groups[0].Count != 1 {
		t.Fatalf("groups = %+v", groups)
	}
}

func TestPendingStoreBindsOwner(t *testing.T) {
	store := newAppleAuthPendingStore()
	pending, err := store.putForOwner(&appleAuthSession{AppleID: "owner@example.com"}, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := store.get(pending.ID)
	if !ok || got.OwnerID != "owner-a" {
		t.Fatalf("pending = %+v, ok=%t", got, ok)
	}
}

func TestPendingLoginProxyUsesLatestAccountConfiguration(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwnerWithProxy("owner-proxy-refresh", "Apple", "proxy-refresh@example.com", "", "http://proxy-one:8080")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateAccountProxyForOwner("owner-proxy-refresh", account.ID, "http://proxy-two:8080"); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	pending := appleAuthPending{
		OwnerID: "owner-proxy-refresh",
		Session: &appleAuthSession{
			AppleID:  "proxy-refresh@example.com",
			ProxyURL: "http://proxy-one:8080",
		},
	}
	updated := handler.pendingLoginWithCurrentProxy(pending)
	if updated.Session == nil || updated.Session.ProxyURL != "http://proxy-two:8080" {
		t.Fatalf("pending proxy = %+v, want latest account proxy", updated.Session)
	}
}

func TestPendingLoginProxyKeepsExplicitProxyWhenNoAccountExists(t *testing.T) {
	handler := NewServer(Config{}, newTestStore(t), discardLogger()).(*Server)
	pending := appleAuthPending{
		OwnerID: "owner-proxy-new",
		Session: &appleAuthSession{
			AppleID:  "new-proxy@example.com",
			ProxyURL: "http://proxy-one:8080",
		},
	}
	updated := handler.pendingLoginWithCurrentProxy(pending)
	if updated.Session == nil || updated.Session.ProxyURL != "http://proxy-one:8080" {
		t.Fatalf("pending proxy = %+v, want explicit proxy when account is not persisted yet", updated.Session)
	}
}

func TestPendingLoginProxyKeepsExplicitProxyOverClearedAccount(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.AddAccountForOwner("owner-proxy-explicit", "Apple", "explicit@example.com", ""); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	pending := appleAuthPending{
		OwnerID:       "owner-proxy-explicit",
		ProxyExplicit: true,
		Session: &appleAuthSession{
			AppleID:  "explicit@example.com",
			ProxyURL: "http://proxy-explicit:8080",
		},
	}
	updated := handler.pendingLoginWithCurrentProxy(pending)
	if updated.Session == nil || updated.Session.ProxyURL != "http://proxy-explicit:8080" {
		t.Fatalf("pending proxy = %+v, want explicit proxy over cleared account", updated.Session)
	}
}

func TestPendingLoginProxyClearsStaleProxyForBlankLogin(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.AddAccountForOwnerWithProxy("owner-proxy-blank", "Apple", "blank@example.com", "", ""); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	pending := appleAuthPending{
		OwnerID: "owner-proxy-blank",
		Session: &appleAuthSession{
			AppleID:  "blank@example.com",
			ProxyURL: "http://proxy-stale:8080",
		},
	}
	updated := handler.pendingLoginWithCurrentProxy(pending)
	if updated.Session == nil || updated.Session.ProxyURL != "" {
		t.Fatalf("pending proxy = %+v, want blank account proxy to clear stale pending proxy", updated.Session)
	}
}

func TestSavePendingICloudSessionPersistsExplicitProxy(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwner("owner-proxy-persist", "Apple", "persist@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	err = handler.savePendingICloudSession(appleAuthPending{
		OwnerID:       "owner-proxy-persist",
		ProxyExplicit: true,
	}, ICloudSession{
		OwnerID:   "owner-proxy-persist",
		AccountID: account.ID,
		AppleID:   account.AppleID,
		ProxyURL:  "http://proxy-persist:8080",
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, ok := store.FindAccountByID(account.ID)
	if !ok || updated.ProxyURL != "http://proxy-persist:8080" {
		t.Fatalf("account after explicit pending proxy save = %+v ok=%t", updated, ok)
	}
}

func TestAppleAccount2FAPersistenceFailureKeepsPendingLogin(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	authTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /verify/trusteddevice/securitycode", "GET /2sv/trust":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected auth request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer authTS.Close()

	manageTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("scnt", "fresh-scnt")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		default:
			t.Fatalf("unexpected manage request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer manageTS.Close()
	appleAccountManageBaseURL = manageTS.URL

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "apple-account-2fa-persist", "admin123")
	pending, err := handler.appleAccountLogins.putForOwner(&appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: authTS.URL,
			Host: "appleid.apple.com",
		},
		AppleID:   "2fa-persist@example.com",
		ClientID:  appleAccountManageOAuthClientID,
		FrameID:   "unit",
		UserAgent: appleAccountManageUserAgent,
		Scnt:      "pending-scnt",
		SessionID: "pending-session",
	}, user.ID)
	if err != nil {
		t.Fatal(err)
	}

	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	req := httptest.NewRequest(http.MethodPost, "/api/apple-account/login/2fa", strings.NewReader(`{"pending_id":"`+pending.ID+`","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("2FA status = %d body=%s, want 500", rr.Code, rr.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "icloud_session_persist_failed" {
		t.Fatalf("2FA error code = %q body=%s, want icloud_session_persist_failed", body.Code, rr.Body.String())
	}
	if _, ok := handler.appleAccountLogins.get(pending.ID); !ok {
		t.Fatal("pending Apple Account login was deleted before session persistence succeeded")
	}
	if sessions := store.ICloudSessionsForOwner(user.ID); len(sessions) != 0 {
		t.Fatalf("sessions after failed persistence = %+v, want none", sessions)
	}
}

func TestDeletePrivacyMailboxWithAppleAccountUsesRemoveEndpoint(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	var gotMethod, gotPath, gotAPIKey string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAPIKey = r.Method, r.URL.Path, r.Header.Get("X-Apple-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	updated, err := client.DeletePrivacyMailboxWithAppleAccount(context.Background(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt",
			APIKey:          "api-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(10 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "anonymous-123")
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/account/manage/email/private/anonymous-123/remove" || gotAPIKey != "api-key" {
		t.Fatalf("request = %s %s api=%q", gotMethod, gotPath, gotAPIKey)
	}
	if _, ok := appleAccountLoginState(updated); !ok {
		t.Fatal("updated session lost Apple Account state")
	}
}

func TestRemoteDeleteFailureIsRecorded(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("owner-delete", "account-delete", ICloudRemoteMailbox{
		AnonymousID: "remote-delete-failed",
		Origin:      "APPLE_ACCOUNT",
		Email:       "alias@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner("owner-delete", ICloudSession{
		OwnerID:   "owner-delete",
		AccountID: "account-delete",
		AppleID:   "alias@example.com",
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			APIKey:          "api-key",
			Scnt:            "scnt",
			LastCheckedAt:   time.Now(),
			ManageExpiresAt: time.Now().Add(10 * time.Minute),
			LastCheckOK:     true,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		return errors.New("remote delete failed")
	}
	err = handler.deleteRemoteMailboxForRequest(context.Background(), mailbox)
	if err == nil {
		t.Fatal("expected remote deletion error")
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox not found after failed remote deletion")
	}
	if updated.RemoteDeleteStatus != "failed" || updated.RemoteDeleteError == "" || strings.Contains(updated.RemoteDeleteError, "remote delete failed") || !updated.ICloudActive || updated.Status != StatusAvailable {
		t.Fatalf("delete failure state = %+v", updated)
	}
}

func TestRemoteDeleteTransportFailureIsRecordedAsUnknown(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("owner-delete-transport", "account-delete-transport", ICloudRemoteMailbox{
		AnonymousID: "remote-delete-transport",
		Origin:      "APPLE_ACCOUNT",
		Email:       "transport@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner("owner-delete-transport", ICloudSession{
		OwnerID:   "owner-delete-transport",
		AccountID: "account-delete-transport",
		AppleID:   "transport@example.com",
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			APIKey:          "api-key",
			Scnt:            "scnt",
			LastCheckedAt:   time.Now(),
			ManageExpiresAt: time.Now().Add(10 * time.Minute),
			LastCheckOK:     true,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		return context.DeadlineExceeded
	}

	err = handler.deleteRemoteMailboxForRequest(context.Background(), mailbox)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("remote delete error = %#v, want context deadline exceeded", err)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox not found after indeterminate remote deletion")
	}
	if updated.RemoteDeleteStatus != "unknown" ||
		updated.RemoteDeleteError == "" ||
		strings.Contains(updated.RemoteDeleteError, context.DeadlineExceeded.Error()) ||
		!updated.ICloudActive ||
		updated.Status != StatusAvailable {
		t.Fatalf("indeterminate remote deletion state leaked transport detail = %+v", updated)
	}
}

func TestLocalMailboxDeleteDoesNotBypassUncertainRemoteDelete(t *testing.T) {
	for _, status := range []string{"pending", "unknown", "failed"} {
		t.Run(status, func(t *testing.T) {
			store := newTestStore(t)
			handler := NewServer(Config{}, store, discardLogger()).(*Server)
			mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-delete-guard", ICloudRemoteMailbox{
				AnonymousID: "remote-delete-guard-" + status,
				Origin:      "APPLE_ACCOUNT",
				Email:       "delete-guard-" + status + "@icloud.com",
				IsActive:    true,
			}, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := store.BeginMailboxRemoteDelete(mailbox.ID, time.Now()); err != nil {
				t.Fatal(err)
			}
			if status == "unknown" {
				if err := store.MarkMailboxRemoteDeleteUnknown(mailbox.ID, "远端结果未知", time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if status == "failed" {
				if err := store.MarkMailboxRemoteDeleteFailed(mailbox.ID, "远端删除失败", time.Now()); err != nil {
					t.Fatal(err)
				}
			}

			err = handler.deleteMailboxForRequestWithOptions(context.Background(), mailbox.ID, false, false)
			wantCode := "remote_delete_unknown"
			if status == "pending" {
				wantCode = "remote_delete_in_progress"
			} else if status == "failed" {
				wantCode = "remote_delete_failed"
			}
			if !isCodedError(err, wantCode) {
				t.Fatalf("local delete error = %#v, want %s", err, wantCode)
			}
			if _, ok := store.FindMailboxByID(mailbox.ID); !ok {
				t.Fatal("local mailbox was deleted despite uncertain remote state")
			}
		})
	}
}

func TestCompletedRemoteDeleteWarningStillRemovesLocalMailbox(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-delete-warning", ICloudRemoteMailbox{
		AnonymousID: "remote-delete-warning",
		Origin:      "APPLE_ACCOUNT",
		Email:       "delete-warning@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	saveTestAppleAccountSession(t, store, "", "account-delete-warning", "delete-warning@example.com")
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		return remoteDeleteCompletedWarning{err: errCode(
			"icloud_session_persist_after_mailbox_delete",
			"远端邮箱已删除，但刷新后的 Apple Account 登录态写入失败",
			true,
		)}
	}

	if err := handler.deleteMailboxForRequest(context.Background(), mailbox.ID, true); err != nil {
		t.Fatalf("delete with completed remote warning = %#v, want local deletion to complete", err)
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("local mailbox remains after completed remote deletion warning")
	}
}

func TestCreatedRemoteCleanupTreatsCompletedDeleteWarningAsSuccess(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		return remoteDeleteCompletedWarning{err: errors.New("session state persistence warning")}
	}

	err := handler.cleanupCreatedRemoteMailbox(context.Background(), "owner-cleanup-warning", "account-cleanup-warning", ICloudRemoteMailbox{
		AnonymousID: "remote-cleanup-warning",
		Origin:      "APPLE_ACCOUNT",
		Email:       "cleanup-warning@icloud.com",
		IsActive:    true,
	})
	if err != nil {
		t.Fatalf("cleanup error = %#v, want completed remote warning to be treated as success", err)
	}
}

func TestCreatedRemoteCleanupUsesIndependentContextAfterRequestCancel(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	called := make(chan error, 1)
	handler.deleteRemoteMailbox = func(ctx context.Context, _ Mailbox) error {
		called <- ctx.Err()
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := handler.cleanupCreatedRemoteMailbox(ctx, "owner-cleanup-canceled", "account-cleanup-canceled", ICloudRemoteMailbox{
		AnonymousID: "remote-cleanup-canceled",
		Origin:      "APPLE_ACCOUNT",
		Email:       "cleanup-canceled@icloud.com",
		IsActive:    true,
	})
	if err != nil {
		t.Fatalf("cleanup error = %#v, want canceled request not to cancel rollback", err)
	}
	select {
	case got := <-called:
		if got != nil {
			t.Fatalf("cleanup context error = %v, want nil", got)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup provider was not called")
	}
}

func TestMailboxAPIExportPostAcceptsSelectedIDsWithoutURLEncoding(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "post-export", "admin123")
	first := createTestMailboxWithCookie(t, handler, adminCookie, "ONE", "post-one@icloud.com")
	second := createTestMailboxWithCookie(t, handler, adminCookie, "TWO", "post-two@icloud.com")

	body, err := json.Marshal(map[string]any{
		"format": "jsonl",
		"ids":    []string{first.ID, second.ID},
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
	if rr.Code != http.StatusOK {
		t.Fatalf("POST export status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "post-one@icloud.com") || !strings.Contains(rr.Body.String(), "post-two@icloud.com") {
		t.Fatalf("POST export body = %q", rr.Body.String())
	}
	for _, id := range []string{first.ID, second.ID} {
		mailbox, ok := store.FindMailboxByID(id)
		if !ok || mailbox.APIExportedAt.IsZero() {
			t.Fatalf("mailbox %s was not marked exported: %+v ok=%t", id, mailbox, ok)
		}
	}
}

type failingMailboxExportResponseWriter struct {
	header http.Header
	status int
}

func (w *failingMailboxExportResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failingMailboxExportResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *failingMailboxExportResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("client disconnected")
}

func TestMailboxAPIExportDoesNotMarkWhenResponseWriteFails(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwner("", "", "EXPORT-FAIL", "export-fail@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis", strings.NewReader(`{"format":"txt"}`))
	req.Header.Set("Content-Type", "application/json")
	writer := &failingMailboxExportResponseWriter{}
	handler.writeMailboxTextExport(writer, req, mailboxExportAPI)

	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox disappeared after failed export response")
	}
	if !updated.APIExportedAt.IsZero() {
		t.Fatalf("mailbox was marked after failed response write: %+v", updated)
	}
}

func TestMailboxAPIExportRollbackPreservesExistingExportState(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	first, err := store.AddMailboxForOwner("", "", "EXPORT-KEEP", "export-keep@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddMailboxForOwner("", "", "EXPORT-NEW", "export-new@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	previousExportedAt := time.Date(2024, time.March, 4, 5, 6, 7, 0, time.UTC)
	if _, err := store.MarkMailboxesAPIExported([]string{first.ID}, previousExportedAt); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis", strings.NewReader(`{"format":"txt","ids":["`+first.ID+`","`+second.ID+`"]}`))
	req.Header.Set("Content-Type", "application/json")
	writer := &failingMailboxExportResponseWriter{}
	handler.writeMailboxTextExport(writer, req, mailboxExportAPI)

	updatedFirst, ok := store.FindMailboxByID(first.ID)
	if !ok {
		t.Fatal("first mailbox disappeared after failed export response")
	}
	if !updatedFirst.APIExportedAt.Equal(previousExportedAt) {
		t.Fatalf("first mailbox export timestamp was not restored: got %v want %v", updatedFirst.APIExportedAt, previousExportedAt)
	}
	updatedSecond, ok := store.FindMailboxByID(second.ID)
	if !ok {
		t.Fatal("second mailbox disappeared after failed export response")
	}
	if !updatedSecond.APIExportedAt.IsZero() {
		t.Fatalf("second mailbox export timestamp should stay empty: %+v", updatedSecond)
	}
}

func TestMailboxListFiltersGlobalOwnerSentinel(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "global-list-sentinel", "admin123")
	globalAccount, err := store.AddAccountForOwner("", "Global Apple", "global-list@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	userAccount, err := store.AddAccountForOwner("global-list-user", "User Apple", "user-list@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	globalMailbox, err := store.AddMailboxForOwner("", globalAccount.ID, "GLOBAL", "global-list@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("global-list-user", userAccount.ID, "USER", "user-list@icloud.com"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/mailboxes?owner_id=__global", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("global mailbox list status = %d body=%s", rr.Code, rr.Body.String())
	}
	var response struct {
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Mailboxes) != 1 || response.Mailboxes[0].ID != globalMailbox.ID {
		t.Fatalf("global mailbox list = %+v, want only global mailbox %q", response.Mailboxes, globalMailbox.ID)
	}
}

func TestICloudClientAppleAccountMailboxListKeepsTopLevelPaginationMetadata(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("cursor") == "page-2" {
			_, _ = w.Write([]byte(`{
				"hasMore": false,
				"result": {
					"hmeEmails": [
						{"id":"apple-page-2","emailAddress":"page-2@icloud.com","isActive":true}
					]
				}
			}`))
			return
		}
		_, _ = w.Write([]byte(`{
			"hasMore": true,
			"nextCursor": "page-2",
			"result": {
				"hmeEmails": [
					{"id":"apple-page-1","emailAddress":"page-1@icloud.com","isActive":true}
				]
			}
		}`))
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	client := &ICloudClient{client: server.Client()}
	remotes, err := client.ListPrivacyMailboxesForOrigin(context.Background(), ICloudSession{}, mailboxRemoteOriginAppleAccount)
	if err == nil {
		t.Fatal("expected Apple Account session error")
	}
	if !isCodedError(err, "apple_account_session_missing") {
		t.Fatalf("missing session error = %#v, want apple_account_session_missing", err)
	}
	remotes, err = client.ListPrivacyMailboxesForOrigin(
		context.Background(),
		ICloudSession{LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Scnt:   "scnt",
			APIKey: "api-key",
		}}},
		mailboxRemoteOriginAppleAccount,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(remotes) != 2 || remotes[0].Email != "page-1@icloud.com" || remotes[1].Email != "page-2@icloud.com" {
		t.Fatalf("remotes = %+v, want both paginated Apple Account records", remotes)
	}
	if len(paths) != 2 || paths[0] != "/account/manage/email/private" || paths[1] != "/account/manage/email/private?cursor=page-2" {
		t.Fatalf("request paths = %+v, want first page and cursor page", paths)
	}
}

func TestICloudClientAppleAccountMailboxListReturnsRefreshedSessionState(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account/manage/email/private" {
			t.Fatalf("request path = %q, want Apple Account mailbox list", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("scnt", "refreshed-scnt")
		_, _ = w.Write([]byte(`{
			"result": {
				"hmeEmails": [
					{"id":"apple-refresh-1","emailAddress":"refreshed-list@icloud.com","isActive":true}
				]
			}
		}`))
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	remotes, updated, err := (&ICloudClient{client: server.Client()}).ListPrivacyMailboxesForOriginWithSession(
		context.Background(),
		ICloudSession{LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Scnt:   "old-scnt",
			APIKey: "api-key",
		}}},
		mailboxRemoteOriginAppleAccount,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(remotes) != 1 || remotes[0].Email != "refreshed-list@icloud.com" {
		t.Fatalf("remotes = %+v, want one refreshed mailbox", remotes)
	}
	state, ok := appleAccountLoginState(updated)
	if !ok || state.Scnt != "refreshed-scnt" {
		t.Fatalf("updated Apple Account state = %+v, want refreshed scnt", state)
	}
}

func TestICloudClientAppleAccountMailboxListUsesFallbackAPIKey(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	const fallbackAPIKey = "configured-api-key"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account/manage/email/private" {
			t.Fatalf("Apple Account list path = %q, want /account/manage/email/private", r.URL.Path)
		}
		if got := r.Header.Get("X-Apple-Api-Key"); got != fallbackAPIKey {
			t.Fatalf("Apple Account list api key = %q, want configured fallback key", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": {
				"hmeEmails": [
					{"anonymousId":"fallback-list-1","hme":"fallback-list@icloud.com","isActive":true}
				]
			}
		}`))
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	remotes, updated, err := (&ICloudClient{client: server.Client()}).ListPrivacyMailboxesForOriginWithSessionAndAPIKey(
		context.Background(),
		ICloudSession{LoginStates: []LoginState{{
			Kind: LoginStateAppleAccount,
			Scnt: "scnt",
		}}},
		mailboxRemoteOriginAppleAccount,
		fallbackAPIKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(remotes) != 1 || remotes[0].Email != "fallback-list@icloud.com" {
		t.Fatalf("remotes = %+v, want one fallback-key mailbox", remotes)
	}
	state, ok := appleAccountLoginState(updated)
	if !ok || state.APIKey != fallbackAPIKey {
		t.Fatalf("updated Apple Account state = %+v, want fallback api key persisted in returned session", state)
	}
}

func TestICloudWebMailboxCreateMarksTransientReserveFailureUncertain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/hme/generate":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":"candidate@icloud.com"}}`))
		case "/v1/hme/reserve":
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("test server does not support connection hijacking")
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := (&ICloudClient{client: server.Client()}).CreatePrivacyMailbox(
		context.Background(),
		ICloudSession{
			DSID:               "web-dsid",
			PremiumMailBaseURL: server.URL,
			IsICloudPlus:       true,
			CanCreateHME:       true,
			Cookies:            []SessionCookie{{Name: "session", Value: "web-cookie"}},
		},
		"label",
		"note",
	)
	if !isCodedError(err, "icloud_create_uncertain") {
		t.Fatalf("CreatePrivacyMailbox error = %v, want icloud_create_uncertain", err)
	}
}

func TestICloudWebMailboxCreateMarksReserveServerFailureUncertain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/hme/generate":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":"candidate@icloud.com"}}`))
		case "/v1/hme/reserve":
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := (&ICloudClient{client: server.Client()}).CreatePrivacyMailbox(
		context.Background(),
		ICloudSession{
			DSID:               "web-dsid",
			PremiumMailBaseURL: server.URL,
			IsICloudPlus:       true,
			CanCreateHME:       true,
			Cookies:            []SessionCookie{{Name: "session", Value: "web-cookie"}},
		},
		"label",
		"note",
	)
	if !isCodedError(err, "icloud_create_uncertain") {
		t.Fatalf("CreatePrivacyMailbox error = %v, want icloud_create_uncertain", err)
	}
}

func TestAppleAccountMailboxCreateUsesAnonymousIDForRemoteIdentity(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var detailPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			_, _ = w.Write([]byte(`{"emailAddress":"candidate@icloud.com"}`))
		case "PUT /account/manage/email/private/add/complete":
			_, _ = w.Write([]byte(`{"emailAddress":"created@icloud.com","id":"opaque-id","anonymousId":"anonymous-id","active":true}`))
		case "GET /account/manage/email/private/opaque-id.em",
			"GET /account/manage/email/private/anonymous-id.em":
			detailPath = r.URL.Path
			_, _ = w.Write([]byte(`{"emailAddress":"created@icloud.com","id":"detail-id","anonymousId":"anonymous-id","active":true}`))
		default:
			t.Fatalf("unexpected Apple Account create request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	remote, _, err := (&ICloudClient{client: server.Client()}).createPrivacyMailboxWithAppleAccountState(
		context.Background(),
		ICloudSession{},
		LoginState{
			Kind:    LoginStateAppleAccount,
			APIKey:  "api-key",
			Scnt:    "scnt",
			Cookies: []SessionCookie{{Name: "session", Value: "cookie"}},
		},
		"",
		"label",
		"note",
	)
	if err != nil {
		t.Fatalf("createPrivacyMailboxWithAppleAccountState error = %v", err)
	}
	if remote.AnonymousID != "anonymous-id" {
		t.Fatalf("remote anonymous ID = %q, want anonymous-id", remote.AnonymousID)
	}
	if detailPath != "/account/manage/email/private/anonymous-id.em" {
		t.Fatalf("detail path = %q, want anonymous-id path", detailPath)
	}
}

func TestSyncICloudMailboxesUsesAppleAccountMailboxList(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var gotMethod, gotPath string
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if r.Method != http.MethodGet || r.URL.Path != "/account/manage/email/private" {
			t.Fatalf("sync request = %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("scnt", "sync-refreshed-scnt")
		_, _ = w.Write([]byte(`{
			"success": true,
			"timestamp": 1,
			"result": {
				"hmeEmails": [
					{"anonymousId":"apple-remote-1","hme":"apple.sync@icloud.com","label":"APPLE","note":"note","forwardToEmail":"main@example.com","isActive":true,"origin":"ON_DEMAND"}
				]
			}
		}`))
	}))
	defer remoteServer.Close()
	appleAccountManageBaseURL = remoteServer.URL

	store := newTestStore(t)
	handler := NewServer(Config{AppleAccountAPIKey: "api-key"}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "sync-apple-account-only", "sync123")
	account, err := store.AddAccountForOwner(user.ID, "Apple Account only", "apple-account-only@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:   user.ID,
		AccountID: account.ID,
		AppleID:   account.AppleID,
		LoginStates: []LoginState{{
			Kind:    LoginStateAppleAccount,
			Scnt:    "scnt",
			Cookies: []SessionCookie{{Name: "session", Value: "apple-account-only"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAccountMailboxCreateReconciliationRequiredForOrigin(
		user.ID,
		account.ID,
		mailboxRemoteOriginAppleAccount,
		"待同步远端列表确认",
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/sync", strings.NewReader(fmt.Sprintf(`{"account_id":%q}`, account.ID)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Apple Account-only mailbox sync status = %d body=%s, want 200", rr.Code, rr.Body.String())
	}
	if gotMethod != http.MethodGet || gotPath != "/account/manage/email/private" {
		t.Fatalf("sync request = %s %s, want GET /account/manage/email/private", gotMethod, gotPath)
	}
	mailbox, ok := store.FindMailboxByEmail("apple.sync@icloud.com")
	if !ok {
		t.Fatal("synced Apple Account mailbox not found")
	}
	if mailbox.OwnerID != user.ID || mailbox.AccountID != account.ID {
		t.Fatalf("synced mailbox owner/account = %q/%q, want %q/%q", mailbox.OwnerID, mailbox.AccountID, user.ID, account.ID)
	}
	if mailbox.RemoteAnonymousID != "apple-remote-1" || mailbox.RemoteOrigin != "APPLE_ACCOUNT" {
		t.Fatalf("synced mailbox remote identity = %+v, want Apple Account remote info", mailbox)
	}
	account, ok = store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared after Apple Account sync")
	}
	if account.MailboxCreateReconciliationRequired {
		t.Fatalf("account reconciliation state = %+v, want cleared after authoritative Apple Account sync", account)
	}
	syncedSession, ok := store.ICloudSessionForOwnerAccount(user.ID, account.ID)
	if !ok {
		t.Fatal("Apple Account session disappeared after mailbox sync")
	}
	syncedState, ok := appleAccountLoginState(syncedSession)
	if !ok || syncedState.Scnt != "sync-refreshed-scnt" {
		t.Fatalf("Apple Account session after sync = %+v, want refreshed scnt", syncedState)
	}
}

func TestICloudWebMailboxSyncClearsICloudWebReconciliationState(t *testing.T) {
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("iCloud Web list path = %q, want /v2/hme/list", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": {
				"hmeEmails": []
			}
		}`))
	}))
	defer remoteServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-icloud-web-reconciliation"
	account, err := store.AddAccountForOwner(ownerID, "iCloud Web reconciliation", "icloud-web-reconciliation@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	session := ICloudSession{
		OwnerID:            ownerID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "icloud-web-reconciliation-dsid",
		PremiumMailBaseURL: remoteServer.URL,
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "session", Value: "cookie"}},
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAccountMailboxCreateReconciliationRequiredForOrigin(
		ownerID,
		account.ID,
		mailboxRemoteOriginICloudWeb,
		"待同步旧接口远端列表确认",
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}

	if _, _, err := handler.syncICloudMailboxesForSession(
		context.Background(),
		httptest.NewRequest(http.MethodGet, "/", nil),
		ownerID,
		session,
	); err != nil {
		t.Fatal(err)
	}
	account, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared after iCloud Web sync")
	}
	if account.MailboxCreateReconciliationRequired {
		t.Fatalf("account reconciliation state = %+v, want cleared after iCloud Web sync", account)
	}
}

func TestICloudWebMailboxSyncClearsAppleAccountReconciliationState(t *testing.T) {
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("iCloud Web list path = %q, want /v2/hme/list", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": {
				"hmeEmails": [
					{"anonymousId":"web-unlock-1","hme":"web-unlock@icloud.com","isActive":true}
				]
			}
		}`))
	}))
	defer remoteServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-web-clears-apple-lock"
	account, err := store.AddAccountForOwner(ownerID, "Web clears Apple lock", "web-clears-apple-lock@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	session := ICloudSession{
		OwnerID:            ownerID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "web-clears-apple-lock-dsid",
		PremiumMailBaseURL: remoteServer.URL,
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "session", Value: "cookie"}},
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAccountMailboxCreateReconciliationRequiredForOrigin(
		ownerID,
		account.ID,
		mailboxRemoteOriginAppleAccount,
		"新接口创建结果不确定",
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}

	if _, _, err := handler.syncICloudMailboxesForSession(
		context.Background(),
		httptest.NewRequest(http.MethodGet, "/", nil),
		ownerID,
		session,
	); err != nil {
		t.Fatal(err)
	}
	account, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared after iCloud Web sync")
	}
	if account.MailboxCreateReconciliationRequired {
		t.Fatalf("account reconciliation state = %+v, want cleared after complete iCloud Web list", account)
	}
}

func TestAppleAccountIncompleteListDoesNotMarkMissingWhenICloudWebSucceeds(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "GET /account/manage/section/privacy":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html>privacy</html>`))
		case "GET /bootstrap/portal":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("iCloud Web list path = %q, want /v2/hme/list", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": {
				"hmeEmails": [
					{"anonymousId":"web-keep-1","hme":"web-keep@icloud.com","isActive":true}
				]
			}
		}`))
	}))
	defer webServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-apple-incomplete-web-ok"
	account, err := store.AddAccountForOwner(ownerID, "Apple incomplete web ok", "apple-incomplete-web-ok@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	appleMailbox, err := store.AddMailboxForOwnerWithRemote(ownerID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "keep-apple",
		Origin:      mailboxRemoteOriginAppleAccount,
		Email:       "keep-apple@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	session := ICloudSession{
		OwnerID:            ownerID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "apple-incomplete-web-ok-dsid",
		PremiumMailBaseURL: webServer.URL,
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "web-cookie"}},
		LoginStates: []LoginState{
			{
				Kind:            LoginStateAppleAccount,
				Scnt:            "scnt",
				APIKey:          "api-key",
				LastCheckedAt:   now,
				ManageExpiresAt: now.Add(time.Hour),
				LastCheckOK:     true,
			},
			{
				Kind:    LoginStateICloudWeb,
				Cookies: []SessionCookie{{Name: "session", Value: "web-cookie"}},
			},
		},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAccountMailboxCreateReconciliationRequiredForOrigin(
		ownerID,
		account.ID,
		mailboxRemoteOriginAppleAccount,
		"新接口创建结果不确定",
		now,
	); err != nil {
		t.Fatal(err)
	}

	result, _, err := handler.syncICloudMailboxesForSession(
		context.Background(),
		httptest.NewRequest(http.MethodGet, "/", nil),
		ownerID,
		session,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Error != "" {
		t.Fatalf("sync error = %q, want empty when iCloud Web list succeeded", result.Error)
	}
	if result.Warning == "" {
		t.Fatal("expected warning when Apple Account list stayed incomplete")
	}
	if result.RemoteMissing != 0 {
		t.Fatalf("remote missing = %d, want 0 when Apple Account list was incomplete", result.RemoteMissing)
	}
	current, ok := store.FindMailboxByID(appleMailbox.ID)
	if !ok {
		t.Fatal("Apple Account mailbox disappeared after incomplete Apple list")
	}
	if !current.RemoteMissingAt.IsZero() || current.Status == StatusDisabled {
		t.Fatalf("Apple Account mailbox marked missing from incomplete list: %+v", current)
	}
	account, ok = store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared after mixed-source sync")
	}
	if account.MailboxCreateReconciliationRequired {
		t.Fatalf("account reconciliation state = %+v, want cleared after complete iCloud Web list", account)
	}
}

func TestAppleAccountMailboxListWarmsAndRetriesMissingHMEEmails(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var listCalls, privacyCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			listCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if listCalls.Load() == 1 {
				_, _ = w.Write([]byte(`{"success":true,"result":{"forwardToEmails":[]}}`))
				return
			}
			_, _ = w.Write([]byte(`{
				"success": true,
				"result": {
					"hmeEmails": [
						{"id":"warmed-1","emailAddress":"warmed-list@icloud.com","isActive":true}
					]
				}
			}`))
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("scnt", "token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "GET /account/manage/section/privacy":
			privacyCalls.Add(1)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html>privacy</html>`))
		case "GET /bootstrap/portal":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	now := time.Now()
	remotes, _, err := (&ICloudClient{client: server.Client()}).ListPrivacyMailboxesForOriginWithSession(
		context.Background(),
		ICloudSession{LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt",
			APIKey:          "api-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(time.Hour),
			LastCheckOK:     true,
		}}},
		mailboxRemoteOriginAppleAccount,
	)
	if err != nil {
		t.Fatal(err)
	}
	if listCalls.Load() != 2 {
		t.Fatalf("Apple Account list calls = %d, want 2 after missing hmeEmails retry", listCalls.Load())
	}
	if privacyCalls.Load() == 0 {
		t.Fatal("privacy page was not warmed before retrying the incomplete Apple Account list")
	}
	if len(remotes) != 1 || remotes[0].Email != "warmed-list@icloud.com" {
		t.Fatalf("remotes = %+v, want warmed Apple Account mailbox", remotes)
	}
}

func TestAppleAccountIncompleteListRetriesAfterManageRefreshFailure(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var listCalls, privacyCalls, tokenCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			listCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if listCalls.Load() == 1 {
				_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
				return
			}
			_, _ = w.Write([]byte(`{
				"success": true,
				"result": {
					"hmeEmails": [
						{"id":"refresh-fail-1","emailAddress":"refresh-fail-retry@icloud.com","isActive":true}
					]
				}
			}`))
		case "GET /account/manage/gs/ws/token":
			tokenCalls.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "GET /account/manage/section/privacy":
			privacyCalls.Add(1)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html>privacy</html>`))
		case "GET /bootstrap/portal":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	now := time.Now()
	remotes, _, err := (&ICloudClient{client: server.Client()}).ListPrivacyMailboxesForOriginWithSession(
		context.Background(),
		ICloudSession{LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt",
			APIKey:          "api-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(time.Hour),
			LastCheckOK:     true,
		}}},
		mailboxRemoteOriginAppleAccount,
	)
	if err != nil {
		t.Fatalf("incomplete list after refresh failure err = %#v, want warmed retry to succeed", err)
	}
	if tokenCalls.Load() == 0 {
		t.Fatal("manage token refresh was not attempted after missing hmeEmails")
	}
	if listCalls.Load() != 2 {
		t.Fatalf("Apple Account list calls = %d, want 2 after refresh failure", listCalls.Load())
	}
	if privacyCalls.Load() == 0 {
		t.Fatal("privacy page was not warmed after manage refresh failure")
	}
	if len(remotes) != 1 || remotes[0].Email != "refresh-fail-retry@icloud.com" {
		t.Fatalf("remotes = %+v, want mailbox from list retry after refresh failure", remotes)
	}
}

func TestAppleAccountIncompleteListKeepsIncompleteWhenRefreshFailsAndRetryStaysIncomplete(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var listCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			listCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		case "GET /account/manage/gs/ws/token":
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "GET /account/manage/section/privacy":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html>privacy</html>`))
		case "GET /bootstrap/portal":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	now := time.Now()
	_, _, err := (&ICloudClient{client: server.Client()}).ListPrivacyMailboxesForOriginWithSession(
		context.Background(),
		ICloudSession{LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt",
			APIKey:          "api-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(time.Hour),
			LastCheckOK:     true,
		}}},
		mailboxRemoteOriginAppleAccount,
	)
	if !isCodedError(err, "apple_account_mailbox_list_incomplete") {
		t.Fatalf("err = %#v, want apple_account_mailbox_list_incomplete rather than refresh 401", err)
	}
	if listCalls.Load() != 2 {
		t.Fatalf("Apple Account list calls = %d, want 2 after refresh failure", listCalls.Load())
	}
}

func TestAppleAccountIncompleteListPersistsRefreshedManageStateWhenWebSucceeds(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("scnt", "incomplete-list-scnt")
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		case "GET /account/manage/gs/ws/token":
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "GET /account/manage/section/privacy":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html>privacy</html>`))
		case "GET /bootstrap/portal":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("iCloud Web list path = %q, want /v2/hme/list", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": {
				"hmeEmails": [
					{"anonymousId":"persist-web-1","hme":"persist-web@icloud.com","isActive":true}
				]
			}
		}`))
	}))
	defer webServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-apple-incomplete-persist"
	account, err := store.AddAccountForOwner(ownerID, "Apple incomplete persist", "apple-incomplete-persist@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	session := ICloudSession{
		OwnerID:            ownerID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "apple-incomplete-persist-dsid",
		PremiumMailBaseURL: webServer.URL,
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "web-cookie"}},
		LoginStates: []LoginState{
			{
				Kind:               LoginStateAppleAccount,
				Scnt:               "stale-scnt",
				APIKey:             "api-key",
				LastCheckedAt:      now,
				ManageExpiresAt:    now.Add(time.Hour),
				LastCheckOK:        false,
				KeepAliveFailCount: 2,
			},
			{
				Kind:    LoginStateICloudWeb,
				Cookies: []SessionCookie{{Name: "session", Value: "web-cookie"}},
			},
		},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}

	if _, _, err := handler.syncICloudMailboxesForSession(
		context.Background(),
		httptest.NewRequest(http.MethodGet, "/", nil),
		ownerID,
		session,
	); err != nil {
		t.Fatal(err)
	}
	saved, ok := store.ICloudSessionForOwnerAccount(ownerID, account.ID)
	if !ok {
		t.Fatal("session disappeared after dual-source sync")
	}
	state, ok := appleAccountLoginState(saved)
	if !ok {
		t.Fatal("Apple Account login state missing after dual-source sync")
	}
	if state.Scnt != "incomplete-list-scnt" {
		t.Fatalf("saved Apple Account scnt = %q, want incomplete-list-scnt from failed list response", state.Scnt)
	}
	if state.LastCheckOK || state.KeepAliveFailCount != 2 {
		t.Fatalf("saved Apple Account keepalive = ok=%v fail=%d, want previous keepalive failure preserved", state.LastCheckOK, state.KeepAliveFailCount)
	}
}

func TestAppleAccountOnlyMailboxSyncFailsWhenListStaysIncomplete(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var listCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			listCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "GET /account/manage/section/privacy":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html>privacy</html>`))
		case "GET /bootstrap/portal":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	appleAccountManageBaseURL = server.URL

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-apple-incomplete-only"
	account, err := store.AddAccountForOwner(ownerID, "Apple incomplete only", "apple-incomplete-only@example.com", "")
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
			ManageExpiresAt: now.Add(time.Hour),
			LastCheckOK:     true,
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAccountMailboxCreateReconciliationRequiredForOrigin(
		ownerID,
		account.ID,
		mailboxRemoteOriginAppleAccount,
		"新接口创建结果不确定",
		now,
	); err != nil {
		t.Fatal(err)
	}

	_, _, err = handler.syncICloudMailboxesForSession(
		context.Background(),
		httptest.NewRequest(http.MethodGet, "/", nil),
		ownerID,
		session,
	)
	if !isCodedError(err, "apple_account_mailbox_list_incomplete") {
		t.Fatalf("Apple Account-only incomplete sync error = %#v, want apple_account_mailbox_list_incomplete", err)
	}
	if listCalls.Load() < 2 {
		t.Fatalf("Apple Account list calls = %d, want a warmup retry", listCalls.Load())
	}
	account, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared after incomplete Apple Account sync")
	}
	if !account.MailboxCreateReconciliationRequired {
		t.Fatal("incomplete Apple Account-only list cleared the create lock")
	}
}

func TestMailboxCreateReconciliationStaysWhenNoOriginListCompletes(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "GET /account/manage/section/privacy":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html>privacy</html>`))
		case "GET /bootstrap/portal":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("iCloud Web list path = %q, want /v2/hme/list", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":{"forwardToEmails":[]}}`))
	}))
	defer webServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-both-lists-incomplete"
	account, err := store.AddAccountForOwner(ownerID, "Both incomplete", "both-incomplete@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	session := ICloudSession{
		OwnerID:            ownerID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "both-incomplete-dsid",
		PremiumMailBaseURL: webServer.URL,
		Host:               "www.icloud.com",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "session", Value: "web-cookie"}},
		LoginStates: []LoginState{
			{
				Kind:            LoginStateAppleAccount,
				Scnt:            "scnt",
				APIKey:          "api-key",
				LastCheckedAt:   now,
				ManageExpiresAt: now.Add(time.Hour),
				LastCheckOK:     true,
			},
			{
				Kind:    LoginStateICloudWeb,
				Cookies: []SessionCookie{{Name: "session", Value: "web-cookie"}},
			},
		},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAccountMailboxCreateReconciliationRequiredForOrigin(
		ownerID,
		account.ID,
		mailboxRemoteOriginAppleAccount,
		"新接口创建结果不确定",
		now,
	); err != nil {
		t.Fatal(err)
	}

	if _, _, err := handler.syncICloudMailboxesForSession(
		context.Background(),
		httptest.NewRequest(http.MethodGet, "/", nil),
		ownerID,
		session,
	); err == nil {
		t.Fatal("sync succeeded with no complete Hide My Email list")
	}
	account, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared after incomplete dual-source sync")
	}
	if !account.MailboxCreateReconciliationRequired {
		t.Fatal("incomplete lists cleared the create lock")
	}
	_, _, err = handler.createICloudMailboxForOwner(context.Background(), ownerID, account.ID, "LOCKED", "")
	if !isCodedError(err, "mailbox_create_reconciliation_required") {
		t.Fatalf("create error = %#v, want mailbox_create_reconciliation_required", err)
	}
}

func TestIncompleteDualSourceSyncKeepsBothProviderErrors(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "GET /account/manage/section/privacy":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html>privacy</html>`))
		case "GET /bootstrap/portal":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("iCloud Web list path = %q, want /v2/hme/list", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":{"forwardToEmails":[]}}`))
	}))
	defer webServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-both-list-errors"
	account, err := store.AddAccountForOwner(ownerID, "Both list errors", "both-list-errors@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	session := ICloudSession{
		OwnerID:            ownerID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "both-list-errors-dsid",
		PremiumMailBaseURL: webServer.URL,
		Host:               "www.icloud.com",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "session", Value: "web-cookie"}},
		LoginStates: []LoginState{
			{
				Kind:            LoginStateAppleAccount,
				Scnt:            "scnt",
				APIKey:          "api-key",
				LastCheckedAt:   now,
				ManageExpiresAt: now.Add(time.Hour),
				LastCheckOK:     true,
			},
			{
				Kind:    LoginStateICloudWeb,
				Cookies: []SessionCookie{{Name: "session", Value: "web-cookie"}},
			},
		},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}

	result, _, syncErr := handler.syncICloudMailboxesForSession(
		context.Background(),
		httptest.NewRequest(http.MethodGet, "/", nil),
		ownerID,
		session,
	)
	if syncErr == nil {
		t.Fatal("sync succeeded with no complete Hide My Email list")
	}
	if !strings.Contains(result.Error, string(mailboxCreateChannelAppleAccount)+"：") {
		t.Fatalf("sync error = %q, want apple_account source prefix", result.Error)
	}
	if !strings.Contains(result.Error, string(mailboxCreateChannelICloudWeb)+"：") {
		t.Fatalf("sync error = %q, want icloud_web source prefix", result.Error)
	}
	if !strings.Contains(result.Error, "Apple Account 隐私邮箱列表响应缺少 hmeEmails") {
		t.Fatalf("sync error = %q, want Apple Account incomplete-list detail", result.Error)
	}
	if !strings.Contains(result.Error, "iCloud 隐私邮箱列表响应缺少 hmeEmails") {
		t.Fatalf("sync error = %q, want iCloud Web incomplete-list detail", result.Error)
	}
}

func TestAutoMailboxCreateFallsBackWhenAppleAccountAuthFailedBeforeGenerate(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var addCalls, webCalls atomic.Int32
	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "POST /account/manage/email/private/add":
			addCalls.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/hme/generate":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":"fallback-candidate@icloud.com"}}`))
		case "/v1/hme/reserve":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":{"anonymousId":"web-fallback-1","hme":"fallback-created@icloud.com","label":"FALLBACK","isActive":true}}}`))
		default:
			t.Fatalf("unexpected iCloud Web request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer webServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-auto-fallback-auth"
	account, err := store.AddAccountForOwner(ownerID, "Auto fallback", "auto-fallback@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	session := ICloudSession{
		OwnerID:            ownerID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "auto-fallback-dsid",
		PremiumMailBaseURL: webServer.URL,
		Host:               "www.icloud.com",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "session", Value: "web-cookie"}},
		LoginStates: []LoginState{
			{
				Kind:            LoginStateAppleAccount,
				Scnt:            "scnt",
				APIKey:          "api-key",
				LastCheckedAt:   now,
				ManageExpiresAt: now.Add(time.Hour),
				LastCheckOK:     true,
			},
			{
				Kind:    LoginStateICloudWeb,
				Cookies: []SessionCookie{{Name: "session", Value: "web-cookie"}},
			},
		},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}

	mailbox, remote, err := handler.createICloudMailboxForOwner(context.Background(), ownerID, account.ID, "FALLBACK", "")
	if err != nil {
		t.Fatal(err)
	}
	if addCalls.Load() != 0 {
		t.Fatalf("Apple Account generate calls = %d, want 0 when list unauthorized", addCalls.Load())
	}
	if webCalls.Load() == 0 {
		t.Fatal("iCloud Web fallback was not used after Apple Account auth failure")
	}
	if remote.Email != "fallback-created@icloud.com" || remote.AnonymousID != "web-fallback-1" || remote.Origin != mailboxRemoteOriginICloudWeb {
		t.Fatalf("fallback remote = %+v, want iCloud Web mailbox", remote)
	}
	if mailbox.Email != "fallback-created@icloud.com" {
		t.Fatalf("fallback mailbox = %+v, want locally saved iCloud Web mailbox", mailbox)
	}
}

func TestAutoMailboxCreateLockOriginUsesWebAfterFallbackUncertain(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "POST /account/manage/email/private/add":
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/hme/generate":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":"web-uncertain@icloud.com"}}`))
		case "/v1/hme/reserve":
			http.Error(w, "upstream closed", http.StatusBadGateway)
		default:
			t.Fatalf("unexpected iCloud Web request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer webServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-auto-lock-web-origin"
	account, err := store.AddAccountForOwner(ownerID, "Auto lock web origin", "auto-lock-web-origin@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "auto-lock-web-origin-dsid",
		PremiumMailBaseURL: webServer.URL,
		Host:               "www.icloud.com",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "session", Value: "web-cookie"}},
		LoginStates: []LoginState{
			{
				Kind:            LoginStateAppleAccount,
				Scnt:            "scnt",
				APIKey:          "api-key",
				LastCheckedAt:   now,
				ManageExpiresAt: now.Add(time.Hour),
				LastCheckOK:     true,
			},
			{
				Kind:    LoginStateICloudWeb,
				Cookies: []SessionCookie{{Name: "session", Value: "web-cookie"}},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	_, _, failures, createErr := handler.createMailboxesForOwnerWithChannels(
		context.Background(),
		ownerID,
		[]mailboxCreateRequest{{AccountID: account.ID, Channel: mailboxCreateChannelAuto}},
		"LOCK",
		"",
	)
	if createErr == nil && len(failures) == 0 {
		t.Fatal("auto create after web reserve failure succeeded, want uncertain lock")
	}
	account, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared after auto create fallback uncertain")
	}
	if !account.MailboxCreateReconciliationRequired {
		t.Fatal("auto create after web reserve failure did not set the reconciliation lock")
	}
	if account.MailboxCreateReconciliationOrigin != mailboxRemoteOriginICloudWeb {
		t.Fatalf("reconciliation origin = %q, want %q after auto fallback hit uncertain iCloud Web create", account.MailboxCreateReconciliationOrigin, mailboxRemoteOriginICloudWeb)
	}
}

func TestMailboxSchedulerAutoFallbackUncertainUsesReconciliationEvent(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "POST /account/manage/email/private/add":
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/hme/generate":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":"scheduler-web-uncertain@icloud.com"}}`))
		case "/v1/hme/reserve":
			http.Error(w, "upstream closed", http.StatusBadGateway)
		default:
			t.Fatalf("unexpected iCloud Web request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer webServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-scheduler-auto-uncertain"
	account, err := store.AddAccountForOwner(ownerID, "Scheduler auto uncertain", "scheduler-auto-uncertain@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "scheduler-auto-uncertain-dsid",
		PremiumMailBaseURL: webServer.URL,
		Host:               "www.icloud.com",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "session", Value: "web-cookie"}},
		LoginStates: []LoginState{
			{
				Kind:            LoginStateAppleAccount,
				Scnt:            "scnt",
				APIKey:          "api-key",
				LastCheckedAt:   now,
				ManageExpiresAt: now.Add(time.Hour),
				LastCheckOK:     true,
			},
			{
				Kind:    LoginStateICloudWeb,
				Cookies: []SessionCookie{{Name: "session", Value: "web-cookie"}},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	handler.runMailboxSchedulerBatch(context.Background(), ownerID, job, mailboxSchedulerConfig{
		AccountIDs:    []string{account.ID},
		Label:         "SCH",
		BatchSize:     1,
		RoundInterval: 0,
	}, 1)
	state, events := job.snapshot()
	account, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared after scheduler auto fallback uncertain")
	}
	if !account.MailboxCreateReconciliationRequired {
		t.Fatal("scheduler auto fallback uncertain did not set the reconciliation lock")
	}
	if account.MailboxCreateReconciliationOrigin != mailboxRemoteOriginICloudWeb {
		t.Fatalf("reconciliation origin = %q, want %q", account.MailboxCreateReconciliationOrigin, mailboxRemoteOriginICloudWeb)
	}
	if state.Success != 0 || state.Failed != 1 {
		t.Fatalf("scheduler state = %+v, want success=0 failed=1", state)
	}
	var sawReconciliation, sawExhausted, sawSwitch bool
	for _, event := range events {
		if event.Type == "failed" && strings.Contains(event.Message, "远端结果不确定") && strings.Contains(event.Message, "已停止自动切换接口") {
			sawReconciliation = true
			if !strings.Contains(event.Message, "旧接口") {
				t.Fatalf("reconciliation event used wrong channel: %q", event.Message)
			}
			if strings.Contains(event.Message, "新接口") {
				t.Fatalf("reconciliation event still blamed the new interface: %q", event.Message)
			}
		}
		if strings.Contains(event.Message, "该账号本轮已无可用接口") {
			sawExhausted = true
		}
		if event.Type == "channel_failed" && strings.Contains(event.Message, "切换旧接口继续尝试") {
			sawSwitch = true
		}
	}
	if !sawReconciliation || sawExhausted || sawSwitch {
		t.Fatalf("events did not keep auto-fallback uncertain as reconciliation: recon=%v exhausted=%v switch=%v events=%+v", sawReconciliation, sawExhausted, sawSwitch, events)
	}
}

func TestMailboxSchedulerAutoFallsBackInSameRequestWhenAppleAuthFailsBeforeGenerate(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var addCalls, webGenerateCalls atomic.Int32
	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "POST /account/manage/email/private/add":
			addCalls.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/hme/generate":
			n := webGenerateCalls.Add(1)
			if n > 1 {
				http.Error(w, "too many generate calls", http.StatusTooManyRequests)
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":"scheduler-fallback@icloud.com"}}`))
		case "/v1/hme/reserve":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":{"anonymousId":"scheduler-web-1","hme":"scheduler-fallback@icloud.com","label":"SCH","isActive":true}}}`))
		case "/v1/hme/deactivate":
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		default:
			t.Fatalf("unexpected iCloud Web request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer webServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-scheduler-auto-fallback"
	account, err := store.AddAccountForOwner(ownerID, "Scheduler auto fallback", "scheduler-auto-fallback@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "scheduler-auto-fallback-dsid",
		PremiumMailBaseURL: webServer.URL,
		Host:               "www.icloud.com",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "session", Value: "web-cookie"}},
		LoginStates: []LoginState{
			{
				Kind:            LoginStateAppleAccount,
				Scnt:            "scnt",
				APIKey:          "api-key",
				LastCheckedAt:   now,
				ManageExpiresAt: now.Add(time.Hour),
				LastCheckOK:     true,
			},
			{
				Kind:    LoginStateICloudWeb,
				Cookies: []SessionCookie{{Name: "session", Value: "web-cookie"}},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	cfg := mailboxSchedulerConfig{
		AccountIDs:    []string{account.ID},
		Label:         "SCH",
		BatchSize:     1,
		RoundInterval: 0,
	}
	handler.runMailboxSchedulerBatch(context.Background(), ownerID, job, cfg, 1)
	state, events := job.snapshot()
	if addCalls.Load() != 0 {
		t.Fatalf("Apple Account generate calls = %d, want 0 when list unauthorized", addCalls.Load())
	}
	if webGenerateCalls.Load() == 0 {
		t.Fatal("scheduler auto create did not fall back to iCloud Web in the same request")
	}
	var firstCreateEvent string
	for i := len(events) - 1; i >= 0; i-- {
		switch events[i].Type {
		case "created", "channel_failed", "failed":
			firstCreateEvent = events[i].Type
		}
		if firstCreateEvent != "" {
			break
		}
	}
	if firstCreateEvent != "created" {
		t.Fatalf("first scheduler create event = %q, want created from same-request iCloud Web fallback", firstCreateEvent)
	}
	if state.Success < 1 {
		t.Fatalf("scheduler state = %+v, want at least one success after same-request fallback", state)
	}
}

func TestSyncICloudMailboxesHTTPClearsLockAndLogsAppleListWarning(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "GET /account/manage/section/privacy":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html>privacy</html>`))
		case "GET /bootstrap/portal":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/hme/list":
			_, _ = w.Write([]byte(`{
				"success": true,
				"result": {
					"hmeEmails": [
						{"anonymousId":"http-web-listed","hme":"http-web-listed@icloud.com","isActive":true}
					]
				}
			}`))
		case "/v1/hme/generate":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":"http-web-created@icloud.com"}}`))
		case "/v1/hme/reserve":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":{"anonymousId":"http-web-created","hme":"http-web-created@icloud.com","label":"AFTER","isActive":true}}}`))
		default:
			t.Fatalf("unexpected iCloud Web request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer webServer.Close()

	var logBuf bytes.Buffer
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, slog.New(slog.NewTextHandler(&logBuf, nil))).(*Server)
	cookie, user := registerTestUser(t, handler, "http-sync-lock", "sync123")
	account, err := store.AddAccountForOwner(user.ID, "HTTP sync lock", "http-sync-lock@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "http-sync-lock-dsid",
		PremiumMailBaseURL: webServer.URL,
		Host:               "www.icloud.com",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "session", Value: "http-sync-cookie", Domain: "127.0.0.1", Path: "/"}},
		LoginStates: []LoginState{
			{
				Kind:            LoginStateAppleAccount,
				Scnt:            "http-sync-scnt",
				APIKey:          "http-sync-api-key",
				LastCheckedAt:   now,
				ManageExpiresAt: now.Add(time.Hour),
				LastCheckOK:     true,
			},
			{
				Kind:    LoginStateICloudWeb,
				Cookies: []SessionCookie{{Name: "session", Value: "http-sync-cookie", Domain: "127.0.0.1", Path: "/"}},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAccountMailboxCreateReconciliationRequiredForOrigin(
		user.ID,
		account.ID,
		mailboxRemoteOriginAppleAccount,
		"新接口创建结果不确定",
		now,
	); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/sync", strings.NewReader(`{"account_id":"`+account.ID+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("HTTP sync status = %d body=%s, want 200", rr.Code, rr.Body.String())
	}
	var response struct {
		Success bool `json:"success"`
		Partial bool `json:"partial"`
		Failed  int  `json:"failed"`
		Results []struct {
			Error   string `json:"error"`
			Warning string `json:"warning"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Success || response.Partial || response.Failed != 0 {
		t.Fatalf("HTTP sync response = %+v, want success with iCloud Web list as authority", response)
	}
	if len(response.Results) != 1 || response.Results[0].Error != "" || response.Results[0].Warning == "" {
		t.Fatalf("HTTP sync results = %+v, want warning without failing the whole sync", response.Results)
	}
	account, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared after HTTP sync")
	}
	if account.MailboxCreateReconciliationRequired {
		t.Fatalf("account reconciliation state = %+v, want cleared after HTTP sync with complete iCloud Web list", account)
	}
	logs := logBuf.String()
	if !strings.Contains(logs, "iCloud mailbox list failed") {
		t.Fatalf("docker-level list warning missing from logs: %q", logs)
	}
	if !strings.Contains(logs, "缺少 hmeEmails") {
		t.Fatalf("Apple Account incomplete-list detail missing from logs: %q", logs)
	}
	if strings.Contains(logs, "http-web-listed@icloud.com") {
		t.Fatalf("mailbox address leaked into sync warning logs: %q", logs)
	}

	createReq := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(`{"account_id":"`+account.ID+`","label":"AFTER","create_channel":"icloud_web"}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.AddCookie(cookie)
	addClosureTestCSRF(createReq, cookie)
	createRR := httptest.NewRecorder()
	handler.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create after HTTP sync status = %d body=%s, want 201", createRR.Code, createRR.Body.String())
	}
	var createBody struct {
		Code      string `json:"code"`
		Created   int    `json:"created"`
		Mailboxes []struct {
			Email string `json:"email"`
		} `json:"mailboxes"`
	}
	if err := json.Unmarshal(createRR.Body.Bytes(), &createBody); err != nil {
		t.Fatal(err)
	}
	if createBody.Code == "mailbox_create_reconciliation_required" {
		t.Fatal("create after HTTP sync was still blocked by the reconciliation lock")
	}
	if createBody.Created != 1 || len(createBody.Mailboxes) != 1 || createBody.Mailboxes[0].Email != "http-web-created@icloud.com" {
		t.Fatalf("create after HTTP sync body = %+v, want one iCloud Web mailbox", createBody)
	}
}

func TestSyncICloudMailboxesHTTPDoesNotLogMailboxAddressesOnIncompleteWarning(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	appleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"success": true,
				"result": {
					"hmeEmails": [
						{"anonymousId":"dup-1","hme":"dup-listed@icloud.com","isActive":true},
						{"anonymousId":"dup-2","hme":"dup-listed@icloud.com","isActive":true}
					]
				}
			}`))
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "GET /account/manage/section/privacy":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html>privacy</html>`))
		case "GET /bootstrap/portal":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			t.Fatalf("unexpected Apple Account request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer appleServer.Close()
	appleAccountManageBaseURL = appleServer.URL

	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("iCloud Web list path = %q, want /v2/hme/list", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"result": {
				"hmeEmails": [
					{"anonymousId":"safe-web-listed","hme":"safe-web-listed@icloud.com","isActive":true}
				]
			}
		}`))
	}))
	defer webServer.Close()

	var logBuf bytes.Buffer
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, slog.New(slog.NewTextHandler(&logBuf, nil))).(*Server)
	cookie, user := registerTestUser(t, handler, "http-sync-dup", "sync123")
	account, err := store.AddAccountForOwner(user.ID, "HTTP sync dup", "http-sync-dup@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "http-sync-dup-dsid",
		PremiumMailBaseURL: webServer.URL,
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "http-sync-dup-cookie", Domain: "127.0.0.1", Path: "/"}},
		LoginStates: []LoginState{
			{
				Kind:            LoginStateAppleAccount,
				Scnt:            "http-sync-dup-scnt",
				APIKey:          "http-sync-dup-api-key",
				LastCheckedAt:   now,
				ManageExpiresAt: now.Add(time.Hour),
				LastCheckOK:     true,
			},
			{
				Kind:    LoginStateICloudWeb,
				Cookies: []SessionCookie{{Name: "session", Value: "http-sync-dup-cookie", Domain: "127.0.0.1", Path: "/"}},
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
		t.Fatalf("HTTP sync status = %d body=%s, want 200", rr.Code, rr.Body.String())
	}
	var response struct {
		Results []struct {
			Warning string `json:"warning"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Results) != 1 || response.Results[0].Warning == "" {
		t.Fatalf("HTTP sync results = %+v, want warning", response.Results)
	}
	if strings.Contains(response.Results[0].Warning, "dup-listed@icloud.com") {
		t.Fatalf("mailbox address leaked into sync warning: %q", response.Results[0].Warning)
	}
	logs := logBuf.String()
	if !strings.Contains(logs, "iCloud mailbox list failed") {
		t.Fatalf("docker-level list warning missing from logs: %q", logs)
	}
	if strings.Contains(logs, "dup-listed@icloud.com") {
		t.Fatalf("mailbox address leaked into sync warning logs: %q", logs)
	}
	if strings.Contains(logs, "safe-web-listed@icloud.com") {
		t.Fatalf("web mailbox address leaked into sync warning logs: %q", logs)
	}
}

func TestMailboxExportRevalidatesSelectedMailboxAfterAccountGateWait(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "export-revalidate", "multi123")
	account, err := store.AddAccountForOwner(user.ID, "Export", "export-revalidate@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(user.ID, account.ID, "export-revalidate", "export-revalidate@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/api/runtime/export-mailbox-apis", strings.NewReader(fmt.Sprintf(
			`{"format":"txt","ids":[%q]}`, mailbox.ID,
		)))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		addClosureTestCSRF(req, cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		done <- rr
	}()

	select {
	case rr := <-done:
		releaseAccountOperation()
		t.Fatalf("mailbox export completed while the account operation was held: status=%d body=%s", rr.Code, rr.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	if err := store.DeleteMailbox(mailbox.ID); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case rr := <-done:
		if rr.Code != http.StatusConflict {
			t.Fatalf("mailbox export status = %d body=%s, want 409", rr.Code, rr.Body.String())
		}
		var body struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Code != "mailbox_selection_changed" {
			t.Fatalf("mailbox export code = %q, want mailbox_selection_changed", body.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("mailbox export did not finish after the account operation was released")
	}
}

func TestMailboxRemoteDeleteGateIsReleasedAfterLastRequest(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwnerWithRemote("", "account-delete-gate", ICloudRemoteMailbox{
		AnonymousID: "delete-gate-remote",
		Origin:      "APPLE_ACCOUNT",
		Email:       "delete-gate@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	saveTestAppleAccountSession(t, store, "", "account-delete-gate", "delete-gate@example.com")
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		return nil
	}

	if err := handler.deleteRemoteMailboxForRequest(context.Background(), mailbox); err != nil {
		t.Fatal(err)
	}
	handler.mailboxRemoteDeleteMu.Lock()
	defer handler.mailboxRemoteDeleteMu.Unlock()
	if len(handler.mailboxRemoteDeleteGates) != 0 {
		t.Fatalf("remote delete gates = %d, want zero after last request", len(handler.mailboxRemoteDeleteGates))
	}
}

func TestCleanRemoteMailboxSerializesWithRemoteDelete(t *testing.T) {
	moveStarted := make(chan struct{})
	releaseMove := make(chan struct{})
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/mailws2/v1/geqs/query":
			_, _ = w.Write([]byte(`{"domainObjects":[{"identifier":"31","name":"INBOX","messageCount":1},{"identifier":"53","name":"Deleted Messages","messageCount":0}]}`))
		case "/mailws2/v1/message/list":
			_, _ = w.Write([]byte(`{"domainObjects":[{"uid":7,"identifier":"msg-inbox-block","mboxRef":{"id":"31"}}]}`))
		case "/mailws2/v1/email/set":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"batchUpdate"`) {
				t.Fatalf("unexpected email/set body: %s", body)
			}
			select {
			case <-moveStarted:
			default:
				close(moveStarted)
			}
			<-releaseMove
			_, _ = w.Write([]byte(`{"updated":{"msg-inbox-block":{"modseq":4}}}`))
		default:
			t.Fatalf("unexpected cleanup request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer remoteServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "cleanup-delete-race", "admin123")
	account, err := store.AddAccountForOwner("", "Cleanup delete race", "cleanup-delete-race@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSession(ICloudSession{
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "cleanup-delete-race-dsid",
		MailGatewayBaseURL: remoteServer.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote("", account.ID, ICloudRemoteMailbox{
		AnonymousID: "cleanup-delete-race",
		Origin:      "ICLOUD_WEB",
		Email:       "cleanup-delete-race@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertMessage(mailbox.ID, "icloud:INBOX:7", "icloud", "code", "sender@example.com", "Use 123456 to continue", time.Now()); err != nil {
		t.Fatal(err)
	}

	cleanupDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+mailbox.ID+"/remote-clean", strings.NewReader(`{"move_synced":true,"empty_trash":false}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(adminCookie)
		addClosureTestCSRF(req, adminCookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		cleanupDone <- rr
	}()
	select {
	case <-moveStarted:
	case <-time.After(2 * time.Second):
		select {
		case rr := <-cleanupDone:
			t.Fatalf("remote cleanup ended before provider call: status=%d body=%s", rr.Code, rr.Body.String())
		default:
			t.Fatal("remote cleanup did not reach the provider")
		}
	}

	deleteStarted := make(chan struct{}, 1)
	handler.deleteRemoteMailbox = func(context.Context, Mailbox) error {
		deleteStarted <- struct{}{}
		return nil
	}
	deleteCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	deleteErr := handler.deleteMailboxForRequest(deleteCtx, mailbox.ID, true)

	close(releaseMove)
	select {
	case rr := <-cleanupDone:
		if rr.Code != http.StatusOK {
			t.Fatalf("cleanup status = %d body=%s", rr.Code, rr.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("remote cleanup did not finish after provider release")
	}
	if deleteErr == nil {
		t.Fatal("remote delete unexpectedly completed while mailbox cleanup was in progress")
	}
	select {
	case <-deleteStarted:
		t.Fatal("remote delete started while mailbox cleanup was in progress")
	default:
	}
}

func TestCleanRemoteMailboxRevalidatesMailboxAfterAccountGateWait(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "clean-revalidate", "multi123")
	account, err := store.AddAccountForOwner(user.ID, "Clean", "clean-revalidate@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "provider must not be called for deleted mailbox", http.StatusInternalServerError)
	}))
	defer remoteServer.Close()
	mailbox, err := store.AddMailboxForOwnerWithRemote(user.ID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "clean-revalidate-remote",
		Origin:      "ICLOUD_WEB",
		Email:       "clean-revalidate@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		AccountID:          account.ID,
		AppleID:            "clean-revalidate@example.com",
		PremiumMailBaseURL: remoteServer.URL,
		DSID:               "clean-revalidate-dsid",
		Cookies:            []SessionCookie{{Name: "session", Value: "clean-revalidate", Domain: "127.0.0.1", Path: "/"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "session", Value: "clean-revalidate", Domain: "127.0.0.1", Path: "/"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+mailbox.ID+"/remote-clean", strings.NewReader(`{"move_synced":true}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		addClosureTestCSRF(req, cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		done <- rr
	}()

	select {
	case rr := <-done:
		releaseAccountOperation()
		t.Fatalf("remote cleanup completed while the account operation was held: status=%d body=%s", rr.Code, rr.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	if err := store.DeleteMailbox(mailbox.ID); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case rr := <-done:
		if rr.Code != http.StatusNotFound {
			t.Fatalf("remote cleanup status = %d body=%s, want 404", rr.Code, rr.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("remote cleanup did not finish after the account operation was released")
	}
	if requests != 0 {
		t.Fatalf("provider requests = %d, want 0 after mailbox deletion", requests)
	}
}

func TestCleanRemoteMailboxWaitsForMailboxAccountBindingToSettle(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "clean-binding", "multi123")
	account, err := store.AddAccountForOwner(user.ID, "Clean binding", "clean-binding@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	requestSeen := make(chan struct{}, 1)
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestSeen <- struct{}{}
		http.Error(w, "provider request observed", http.StatusInternalServerError)
	}))
	defer remoteServer.Close()
	mailbox, err := store.AddMailboxForOwner(user.ID, "", "clean binding", "clean-binding@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		AccountID:          account.ID,
		AppleID:            "clean-binding@example.com",
		PremiumMailBaseURL: remoteServer.URL,
		DSID:               "clean-binding-dsid",
		Cookies:            []SessionCookie{{Name: "session", Value: "clean-binding", Domain: "127.0.0.1", Path: "/"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "session", Value: "clean-binding", Domain: "127.0.0.1", Path: "/"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	releaseUnbound, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, ""),
	)
	if err != nil {
		t.Fatal(err)
	}
	releaseBound, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, account.ID),
	)
	if err != nil {
		releaseUnbound()
		t.Fatal(err)
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(
			http.MethodPost,
			"/api/mailboxes/"+mailbox.ID+"/remote-clean",
			strings.NewReader(`{"move_synced":true}`),
		)
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		addClosureTestCSRF(req, cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		done <- rr
	}()

	select {
	case rr := <-done:
		releaseBound()
		releaseUnbound()
		t.Fatalf("remote cleanup completed before mailbox binding settled: status=%d body=%s", rr.Code, rr.Body.String())
	case <-time.After(100 * time.Millisecond):
	}

	_, _, err = store.UpsertMailboxFromRemote(user.ID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "clean-binding-remote",
		Origin:      "ICLOUD_WEB",
		Email:       "clean-binding@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		releaseBound()
		releaseUnbound()
		t.Fatal(err)
	}
	releaseUnbound()

	select {
	case rr := <-done:
		releaseBound()
		t.Fatalf("remote cleanup bypassed the newly bound account gate: status=%d body=%s", rr.Code, rr.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	releaseBound()

	select {
	case rr := <-done:
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("remote cleanup status = %d body=%s, want provider failure after gates release", rr.Code, rr.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("remote cleanup did not finish after account gates were released")
	}
	select {
	case <-requestSeen:
	case <-time.After(time.Second):
		t.Fatal("remote cleanup provider was not called after gates were released")
	}
}

func TestCleanRemoteMailboxesRevalidatesMailboxAfterAccountGateWait(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "clean-bulk-revalidate", "multi123")
	account, err := store.AddAccountForOwner(user.ID, "Clean bulk", "clean-bulk-revalidate@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "provider must not be called for deleted mailbox", http.StatusInternalServerError)
	}))
	defer remoteServer.Close()
	mailbox, err := store.AddMailboxForOwnerWithRemote(user.ID, account.ID, ICloudRemoteMailbox{
		AnonymousID: "clean-bulk-revalidate-remote",
		Origin:      "ICLOUD_WEB",
		Email:       "clean-bulk-revalidate@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		AccountID:          account.ID,
		AppleID:            "clean-bulk-revalidate@example.com",
		PremiumMailBaseURL: remoteServer.URL,
		DSID:               "clean-bulk-revalidate-dsid",
		Cookies:            []SessionCookie{{Name: "session", Value: "clean-bulk-revalidate", Domain: "127.0.0.1", Path: "/"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "session", Value: "clean-bulk-revalidate", Domain: "127.0.0.1", Path: "/"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(user.ID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/remote-clean", strings.NewReader(fmt.Sprintf(
			`{"account_id":%q,"move_synced":true}`,
			account.ID,
		)))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		addClosureTestCSRF(req, cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		done <- rr
	}()

	select {
	case rr := <-done:
		releaseAccountOperation()
		t.Fatalf("bulk remote cleanup completed while the account operation was held: status=%d body=%s", rr.Code, rr.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	if err := store.DeleteMailbox(mailbox.ID); err != nil {
		releaseAccountOperation()
		t.Fatal(err)
	}
	releaseAccountOperation()

	select {
	case rr := <-done:
		if rr.Code != http.StatusOK {
			t.Fatalf("bulk remote cleanup status = %d body=%s, want 200", rr.Code, rr.Body.String())
		}
		var body struct {
			Success         bool `json:"success"`
			Mailboxes       int  `json:"mailboxes"`
			FailedMailboxes int  `json:"failed_mailboxes"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if !body.Success || body.Mailboxes != 0 || body.FailedMailboxes != 0 {
			t.Fatalf("bulk remote cleanup body = %+v, want no-op success", body)
		}
	case <-time.After(time.Second):
		t.Fatal("bulk remote cleanup did not finish after the account operation was released")
	}
	if requests != 0 {
		t.Fatalf("provider requests = %d, want 0 after mailbox deletion", requests)
	}
}

func TestCleanRemoteMailboxesDoesNotCountMailboxWhenEmptyTrashFails(t *testing.T) {
	var emptyTrashFailed bool
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/mailws2/v1/geqs/query":
			_, _ = w.Write([]byte(`{"domainObjects":[{"identifier":"31","name":"INBOX","messageCount":1},{"identifier":"53","name":"Deleted Messages","messageCount":1}]}`))
		case "/mailws2/v1/message/list":
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), `"value":"31"`) {
				_, _ = w.Write([]byte(`{"domainObjects":[{"uid":7,"identifier":"msg-inbox","mboxRef":{"id":"31"}}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"domainObjects":[{"uid":8,"identifier":"msg-trash","mboxRef":{"id":"53"}}]}`))
		case "/mailws2/v1/email/set":
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), `"batchUpdate"`) {
				_, _ = w.Write([]byte(`{"updated":{"msg-inbox":{"modseq":4}}}`))
				return
			}
			if strings.Contains(string(body), `"destroy"`) {
				emptyTrashFailed = true
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte(`trash cleanup failed`))
				return
			}
			t.Fatalf("unexpected email/set body: %s", body)
		default:
			t.Fatalf("unexpected cleanup request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer remoteServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "cleanup-count", "admin123")
	account, err := store.AddAccountForOwner("", "Cleanup account", "cleanup@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSession(ICloudSession{
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "cleanup-dsid",
		ClientID:           "cleanup-client",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		MailGatewayBaseURL: remoteServer.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote("", account.ID, ICloudRemoteMailbox{
		AnonymousID: "cleanup-mailbox",
		Origin:      "ICLOUD_WEB",
		Email:       "cleanup@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.UpsertMessage(mailbox.ID, "icloud:INBOX:7", "icloud", "code", "sender@example.com", "body", time.Now()); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/remote-clean?owner_id=all", strings.NewReader(`{"move_synced":true,"empty_trash":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("cleanup status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success         bool   `json:"success"`
		Message         string `json:"message"`
		Mailboxes       int    `json:"mailboxes"`
		FailedMailboxes int    `json:"failed_mailboxes"`
		Failures        []struct {
			ID      string `json:"id"`
			Email   string `json:"email"`
			Message string `json:"message"`
		} `json:"failures"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !emptyTrashFailed {
		t.Fatal("empty trash failure was not exercised")
	}
	if body.Mailboxes != 0 || body.FailedMailboxes != 1 {
		t.Fatalf("cleanup summary = %+v, want zero handled and one failed mailbox", body)
	}
	if body.Success || strings.TrimSpace(body.Message) == "" {
		t.Fatalf("cleanup failure response = %+v, want success=false with a message", body)
	}
	if len(body.Failures) != 1 ||
		body.Failures[0].ID != mailbox.ID ||
		body.Failures[0].Email != mailbox.Email ||
		strings.TrimSpace(body.Failures[0].Message) == "" {
		t.Fatalf("cleanup failure details = %+v, want the failed mailbox identity and reason", body.Failures)
	}
}

func TestCleanRemoteMailboxesTargetsUnboundTabOnly(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "cleanup-unbound", "admin123")
	account, err := store.AddAccountForOwner("", "Bound cleanup account", "cleanup-unbound@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwnerWithRemote("", account.ID, ICloudRemoteMailbox{
		AnonymousID: "cleanup-bound-mailbox",
		Origin:      "ICLOUD_WEB",
		Email:       "cleanup-bound@icloud.com",
		IsActive:    true,
	}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwnerWithRemote("", "", ICloudRemoteMailbox{
		AnonymousID: "cleanup-unbound-mailbox",
		Origin:      "ICLOUD_WEB",
		Email:       "cleanup-unbound@icloud.com",
		IsActive:    false,
	}, ""); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/remote-clean?owner_id=all", strings.NewReader(`{"account_id":"unbound","move_synced":true,"empty_trash":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unbound cleanup status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success         bool                    `json:"success"`
		Mailboxes       int                     `json:"mailboxes"`
		FailedMailboxes int                     `json:"failed_mailboxes"`
		Cleanup         ICloudMailCleanupResult `json:"cleanup"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Mailboxes != 0 || body.FailedMailboxes != 0 || body.Cleanup.Skipped != 1 {
		t.Fatalf("unbound cleanup summary = %+v, want only the disabled unbound mailbox skipped", body)
	}
}

func TestCleanRemoteMailboxesEmptiesTrashAfterMovingAllMailboxesForAccount(t *testing.T) {
	var (
		mu     sync.Mutex
		events []string
	)
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/mailws2/v1/geqs/query":
			_, _ = w.Write([]byte(`{"domainObjects":[{"identifier":"31","name":"INBOX","messageCount":2},{"identifier":"53","name":"Deleted Messages","messageCount":1}]}`))
		case "/mailws2/v1/message/list":
			body, _ := io.ReadAll(r.Body)
			switch {
			case strings.Contains(string(body), `"value":"31"`) && strings.Contains(string(body), `"value":[7]`):
				_, _ = w.Write([]byte(`{"domainObjects":[{"uid":7,"identifier":"msg-inbox-7","mboxRef":{"id":"31"}}]}`))
			case strings.Contains(string(body), `"value":"31"`) && strings.Contains(string(body), `"value":[8]`):
				_, _ = w.Write([]byte(`{"domainObjects":[{"uid":8,"identifier":"msg-inbox-8","mboxRef":{"id":"31"}}]}`))
			default:
				_, _ = w.Write([]byte(`{"domainObjects":[{"uid":9,"identifier":"msg-trash","mboxRef":{"id":"53"}}]}`))
			}
		case "/mailws2/v1/email/set":
			body, _ := io.ReadAll(r.Body)
			text := string(body)
			switch {
			case strings.Contains(text, `"batchUpdate"`) && strings.Contains(text, "msg-inbox-7"):
				mu.Lock()
				events = append(events, "move-7")
				mu.Unlock()
				_, _ = w.Write([]byte(`{"updated":{"msg-inbox-7":{"modseq":4}}}`))
			case strings.Contains(text, `"batchUpdate"`) && strings.Contains(text, "msg-inbox-8"):
				mu.Lock()
				events = append(events, "move-8")
				mu.Unlock()
				_, _ = w.Write([]byte(`{"updated":{"msg-inbox-8":{"modseq":5}}}`))
			case strings.Contains(text, `"destroy"`):
				mu.Lock()
				events = append(events, "empty-trash")
				mu.Unlock()
				_, _ = w.Write([]byte(`{"destroyed":["msg-trash"]}`))
			default:
				t.Errorf("unexpected email/set body: %s", body)
				http.Error(w, "unexpected email/set body", http.StatusBadRequest)
			}
		default:
			t.Errorf("unexpected cleanup request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected cleanup request", http.StatusNotFound)
		}
	}))
	defer remoteServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "cleanup-order", "admin123")
	account, err := store.AddAccountForOwner("", "Cleanup order account", "cleanup-order@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSession(ICloudSession{
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "cleanup-order-dsid",
		ClientID:           "cleanup-order-client",
		ClientBuildNumber:  "build",
		MailGatewayBaseURL: remoteServer.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
	}); err != nil {
		t.Fatal(err)
	}
	for index, remoteID := range []string{"7", "8"} {
		mailbox, err := store.AddMailboxForOwnerWithRemote("", account.ID, ICloudRemoteMailbox{
			AnonymousID: "cleanup-order-" + remoteID,
			Origin:      "ICLOUD_WEB",
			Email:       "cleanup-order-" + remoteID + "@icloud.com",
			IsActive:    true,
		}, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.UpsertMessage(mailbox.ID, "icloud:INBOX:"+remoteID, "icloud", "code", "sender@example.com", "Use 123456 to continue", time.Now().Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/remote-clean?owner_id=all", strings.NewReader(`{"move_synced":true,"empty_trash":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("cleanup status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Mailboxes       int `json:"mailboxes"`
		FailedMailboxes int `json:"failed_mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Mailboxes != 2 || body.FailedMailboxes != 0 {
		t.Fatalf("cleanup summary = %+v, want two handled and zero failed mailboxes", body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 3 || events[0] != "move-7" || events[1] != "move-8" || events[2] != "empty-trash" {
		t.Fatalf("cleanup event order = %#v, want all mailbox moves before empty-trash", events)
	}
}

func TestMergeLoginStatesPreservesCookiesForPartialStateUpdate(t *testing.T) {
	existing := []LoginState{{
		Kind: LoginStateAppleAccount,
		Scnt: "existing-scnt",
		Cookies: []SessionCookie{{
			Name:   "aid",
			Value:  "existing-cookie",
			Domain: "appleid.apple.com",
			Path:   "/",
		}},
	}}
	incoming := []LoginState{{
		Kind: LoginStateAppleAccount,
		Scnt: "updated-scnt",
	}}

	got := mergeLoginStates(existing, incoming)
	if len(got) != 1 || got[0].Scnt != "updated-scnt" {
		t.Fatalf("merged login states = %+v", got)
	}
	if len(got[0].Cookies) != 1 || got[0].Cookies[0].Value != "existing-cookie" {
		t.Fatalf("partial update dropped existing cookies: %+v", got[0].Cookies)
	}
}

func TestDeleteMailboxRouteDeletesOldICloudRemoteBeforeLocalRecord(t *testing.T) {
	var paths []string
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
	}))
	defer remoteServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "old-remote-delete", "admin123")
	account, err := store.AddAccountForOwner("", "Old iCloud", "old@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSession(ICloudSession{
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "old-dsid",
		ClientID:           "old-client",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		PremiumMailBaseURL: remoteServer.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote("", account.ID, ICloudRemoteMailbox{
		AnonymousID: "old-remote-id",
		Origin:      "ICLOUD_WEB",
		Email:       "old-remote@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/mailboxes/"+mailbox.ID+"?delete_remote=1", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", rr.Code, rr.Body.String())
	}
	if got, want := strings.Join(paths, "\n"), "POST /v1/hme/deactivate\nPOST /v1/hme/delete"; got != want {
		t.Fatalf("remote delete paths = %q, want %q", got, want)
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("local mailbox record remains after remote and local deletion")
	}
}

func TestDeleteMailboxRouteKeepsLocalRecordWhenOldICloudRemoteDeleteFails(t *testing.T) {
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/hme/delete" {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`remote delete failed`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
	}))
	defer remoteServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "old-remote-failure", "admin123")
	account, err := store.AddAccountForOwner("", "Old iCloud", "old-failure@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSession(ICloudSession{
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "old-failure-dsid",
		PremiumMailBaseURL: remoteServer.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote("", account.ID, ICloudRemoteMailbox{
		AnonymousID: "old-failure-id",
		Origin:      "ICLOUD_WEB",
		Email:       "old-failure@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/mailboxes/"+mailbox.ID+"?delete_remote=1", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("delete status = %d body=%s", rr.Code, rr.Body.String())
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("local mailbox record was removed after remote deletion failure")
	}
	if updated.RemoteDeleteStatus != "unknown" || !strings.Contains(updated.RemoteDeleteError, "HTTP 502") {
		t.Fatalf("transient remote failure state = %+v", updated)
	}
}

func TestDeleteMailboxRemoteReturnsBusyWhenAccountOperationHeld(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	oldTimeout := mailboxAccountOperationAcquireTimeout
	mailboxAccountOperationAcquireTimeout = 40 * time.Millisecond
	t.Cleanup(func() { mailboxAccountOperationAcquireTimeout = oldTimeout })
	adminCookie, _ := registerTestUser(t, handler, "delete-busy", "admin123")
	account, err := store.AddAccountForOwner("", "Busy delete", "busy-delete@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote("", account.ID, ICloudRemoteMailbox{
		AnonymousID: "busy-delete-id",
		Origin:      "ICLOUD_WEB",
		Email:       "busy-delete@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	_, release, err := handler.acquireCurrentMailboxAccountOperation(context.Background(), mailbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	done := make(chan struct{})
	rr := httptest.NewRecorder()
	go func() {
		defer close(done)
		req := httptest.NewRequest(http.MethodDelete, "/api/mailboxes/"+mailbox.ID+"?delete_remote=1", nil)
		req.AddCookie(adminCookie)
		addClosureTestCSRF(req, adminCookie)
		handler.ServeHTTP(rr, req)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("remote delete blocked while account operation held")
	}
	if rr.Code != http.StatusConflict {
		t.Fatalf("delete status = %d body=%s, want 409 mailbox_operation_in_progress", rr.Code, rr.Body.String())
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); !ok {
		t.Fatal("local mailbox was removed while account operation was busy")
	}
}

func TestFailedOldICloudRemoteDeleteFailsClosed(t *testing.T) {
	mailbox := Mailbox{
		RemoteDeleteStatus: "failed",
		ICloudActive:       true,
		APIActive:          true,
		Status:             StatusAvailable,
	}

	if mailboxClaimable(mailbox) {
		t.Fatal("mailbox with failed remote deletion must not remain claimable")
	}
	if mailboxEligibleForMessageSync(mailbox) {
		t.Fatal("mailbox with failed remote deletion must not remain eligible for message sync")
	}
	if err := mailboxCodeAvailabilityError(mailbox); err == nil {
		t.Fatal("mailbox with failed remote deletion must not serve verification codes")
	}

	store := newTestStore(t)
	stored, err := store.AddMailboxForOwner("", "", "failed remote", "failed-remote@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMailboxRemoteDeleteFailed(stored.ID, "provider failed", time.Now()); err != nil {
		t.Fatal(err)
	}
	active := true
	if _, err := store.SetMailboxStatus(stored.ID, nil, &active, StatusAvailable, ""); !isCodedError(err, "remote_delete_failed") {
		t.Fatalf("reactivating failed remote mailbox error = %#v, want remote_delete_failed", err)
	}
	if mailboxEligibleForRemoteCleanup(Mailbox{RemoteDeleteStatus: "failed", ICloudActive: true, Status: StatusAvailable}) {
		t.Fatal("mailbox with failed remote deletion must not be eligible for remote cleanup")
	}
}

func TestManualMailboxCannotDeleteMatchingICloudRemoteWithoutStoredIdentity(t *testing.T) {
	var paths []string
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"hmeEmails": [
				{"anonymousId":"remote-match","hme":"manual-match@icloud.com","active":true}
			]
		}`))
	}))
	defer remoteServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	account, err := store.AddAccountForOwner("", "Manual mailbox", "manual@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSession(ICloudSession{
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "manual-dsid",
		PremiumMailBaseURL: remoteServer.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner("", account.ID, "Manual", "manual-match@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	err = handler.deleteICloudMailboxRemote(context.Background(), mailbox)
	if !isCodedError(err, "icloud_mailbox_anonymous_id_missing") {
		t.Fatalf("manual mailbox remote delete error = %#v, want missing stored identity", err)
	}
	if len(paths) != 0 {
		t.Fatalf("manual mailbox triggered remote requests = %#v", paths)
	}
}

func TestMailboxRemoteDeleteRejectsUnknownOriginWithoutProviderRequest(t *testing.T) {
	var paths []string
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer remoteServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	account, err := store.AddAccountForOwner("", "Unknown origin", "unknown-origin@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSession(ICloudSession{
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "unknown-origin-dsid",
		PremiumMailBaseURL: remoteServer.URL,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwnerWithRemote("", account.ID, ICloudRemoteMailbox{
		AnonymousID: "unknown-origin-remote-id",
		Origin:      "provider-specific-unknown",
		Email:       "unknown-origin@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	err = handler.deleteICloudMailboxRemote(context.Background(), mailbox)
	if !isCodedError(err, "icloud_mailbox_remote_origin_unknown") {
		t.Fatalf("unknown-origin remote delete error = %#v, want coded origin error", err)
	}
	if len(paths) != 0 {
		t.Fatalf("unknown-origin mailbox triggered remote requests = %#v", paths)
	}
}

func TestDeleteMailboxRouteDeletesAppleAccountRemoteBeforeLocalRecord(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var gotPath, gotAPIKey string
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.Method + " " + r.URL.Path
		gotAPIKey = r.Header.Get("X-Apple-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer remoteServer.Close()
	appleAccountManageBaseURL = remoteServer.URL

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "apple-remote-delete", "admin123")
	account, err := store.AddAccountForOwner("", "Apple Account", "apple-account@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.SaveICloudSession(ICloudSession{
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
	mailbox, err := store.AddMailboxForOwnerWithRemote("", account.ID, ICloudRemoteMailbox{
		AnonymousID: "apple-remote-id",
		Origin:      "APPLE_ACCOUNT",
		Email:       "apple-remote@icloud.com",
		IsActive:    true,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/mailboxes/"+mailbox.ID+"?delete_remote=1", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", rr.Code, rr.Body.String())
	}
	if gotPath != "DELETE /account/manage/email/private/apple-remote-id/remove" || gotAPIKey != "api-key" {
		t.Fatalf("Apple Account delete request = %q api=%q", gotPath, gotAPIKey)
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("local mailbox record remains after Apple Account remote deletion")
	}
}

func TestAddAccountRejectsAppleIDOwnedByOtherOwner(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.AddAccountForOwner("owner-a", "A", "shared-apple@icloud.com", ""); err != nil {
		t.Fatal(err)
	}
	_, err := store.AddAccountForOwner("owner-b", "B", "shared-apple@icloud.com", "")
	if !isCodedError(err, "apple_id_exists_other_owner") {
		t.Fatalf("error = %#v, want apple_id_exists_other_owner", err)
	}
}

func TestAddAccountRejectsDuplicateAppleIDForSameOwner(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.AddAccountForOwner("owner-dup", "A", "dup-apple@icloud.com", ""); err != nil {
		t.Fatal(err)
	}
	_, err := store.AddAccountForOwner("owner-dup", "B", "dup-apple@icloud.com", "")
	if !isCodedError(err, "apple_id_exists") {
		t.Fatalf("error = %#v, want apple_id_exists", err)
	}
}

func TestIMAPSaveWithoutAccountIDRejectsAppleIDOwnedByOtherOwner(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, _ := registerTestUser(t, handler, "imap-apple-id-owner-a", "user123")
	_, userB := registerTestUser(t, handler, "imap-apple-id-owner-b", "user456")
	if _, err := store.AddAccountForOwner(userB.ID, "Other", "taken-apple@icloud.com", ""); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/save", strings.NewReader(
		`{"email":"taken-apple@icloud.com","app_password":"app-secret"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("imap save status = %d body=%s, want 409", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "apple_id_exists_other_owner") {
		t.Fatalf("imap save body = %s, want apple_id_exists_other_owner", rr.Body.String())
	}
}

func TestCreateICloudMailboxRechecksReconciliationAfterAccountLock(t *testing.T) {
	webServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("unexpected iCloud Web request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
	}))
	defer webServer.Close()

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	ownerID := "owner-create-lock-recheck"
	account, err := store.AddAccountForOwner(ownerID, "Lock recheck", "lock-recheck@icloud.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AccountID:          account.ID,
		AppleID:            account.AppleID,
		DSID:               "lock-recheck-dsid",
		PremiumMailBaseURL: webServer.URL,
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "session", Value: "cookie"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "session", Value: "cookie"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	release, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(ownerID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, _, createErr := handler.createICloudMailboxForOwner(context.Background(), ownerID, account.ID, "label", "note")
		errCh <- createErr
	}()
	time.Sleep(50 * time.Millisecond)
	if err := store.MarkAccountMailboxCreateReconciliationRequired(ownerID, account.ID, "第一次结果未确认", time.Now()); err != nil {
		release()
		t.Fatal(err)
	}
	release()
	select {
	case createErr := <-errCh:
		if !isCodedError(createErr, "mailbox_create_reconciliation_required") {
			t.Fatalf("create error = %#v, want mailbox_create_reconciliation_required", createErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("createICloudMailboxForOwner did not return after the account lock was released")
	}
}

func TestICloudWebMailboxCreateMarksReserveHTMLFailureUncertain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/hme/generate":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":{"hme":"candidate@icloud.com"}}`))
		case "/v1/hme/reserve":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("<html>bad gateway</html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := (&ICloudClient{client: server.Client()}).CreatePrivacyMailbox(
		context.Background(),
		ICloudSession{
			DSID:               "web-dsid",
			PremiumMailBaseURL: server.URL,
			IsICloudPlus:       true,
			CanCreateHME:       true,
			Cookies:            []SessionCookie{{Name: "session", Value: "web-cookie"}},
		},
		"label",
		"note",
	)
	if !isCodedError(err, "icloud_create_uncertain") {
		t.Fatalf("CreatePrivacyMailbox error = %v, want icloud_create_uncertain", err)
	}
}

func TestSetMailboxLastCodeRejectsAlreadyServedMessage(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailboxForOwner("", "", "ALREADY-SERVED", "already-served@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	message, err := store.AddMessage(mailbox.ID, "code subject", "from@example.com", "code 123456", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetMailboxLastCode(mailbox.ID, message.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, err = store.SetMailboxLastCode(mailbox.ID, message.ID, time.Now())
	if !isCodedError(err, "mailbox_code_already_served") {
		t.Fatalf("error = %#v, want mailbox_code_already_served", err)
	}
}

func TestWriteMailboxCodeSuccessDoesNotReturnAlreadyServedCode(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{APIKey: "global-key"}, store, discardLogger()).(*Server)
	mailbox, err := store.AddMailboxForOwner("owner-code-dup", "", "CODE-DUP", "code-dup@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	message, err := store.AddMessage(mailbox.ID, "Your code is 654321", "noreply@tm.openai.com", "Enter 654321", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetMailboxLastCode(mailbox.ID, message.ID, time.Now()); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/mailboxes/"+mailbox.ID+"/code?key="+mailbox.APIToken, nil)
	handler.writeMailboxCodeSuccess(rr, req, mailbox, message, "654321", "", true)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"code":"no_code"`) {
		t.Fatalf("already served code response = %d %s, want no_code", rr.Code, rr.Body.String())
	}
}
