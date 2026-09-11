package app

import (
	"strings"
	"testing"
)

func TestIndexTemplateKeepsAccountFilterDuringSearchAndUsesAllSelectedIDs(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	for _, marker := range []string{
		`function mailboxListQuery()`,
		`if (activeMailboxAccountKey && activeMailboxAccountKey !== 'all') {`,
		`params.set('account_key', activeMailboxAccountKey);`,
		`function selectedMailboxIDsList()`,
		`return Array.from(selectedMailboxIDs);`,
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("index template missing marker %q", marker)
		}
	}
	if strings.Contains(html, "function selectedMailboxListIDs()") {
		t.Error("index template still contains unused legacy selectedMailboxListIDs helper")
	}
	for _, marker := range []string{
		"function setMailboxSearch() {\n      mailboxPage = 1;\n      invalidateMailboxSelection();\n      renderMailboxes();",
		"function clearMailboxSearch() {\n      if ($('mailboxSearch')) $('mailboxSearch').value = '';\n      mailboxPage = 1;\n      invalidateMailboxSelection();\n      renderMailboxes();",
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("index template missing search-clear block %q", marker)
		}
	}
}

func TestIndexTemplateOffersAppleAccountOnlySessionsForExistingMailboxSync(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	start := strings.Index(html, "const syncChoices =")
	if start < 0 {
		t.Fatal("index template is missing syncChoices")
	}
	end := strings.Index(html[start:], "const syncSelect =")
	if end < 0 {
		t.Fatal("index template is missing syncSelect after syncChoices")
	}
	block := html[start : start+end]
	if !strings.Contains(block, "iCloudWebLoginSaved(session) || appleAccountLoginSaved(session)") {
		t.Fatalf("syncChoices must include sessions that can list existing iCloud mailboxes through either provider")
	}
	if !strings.Contains(block, "mailboxSyncSourceLabel(session)") {
		t.Fatalf("syncChoices must include the provider label for existing mailbox sync")
	}
	if !strings.Contains(html, "function mailboxSyncSourceLabel(session)") || !strings.Contains(html, "return '新接口';") {
		t.Fatalf("syncChoices must label Apple Account-only sessions as the new provider")
	}
}

func TestIndexTemplateShowsBulkDeleteFailureDetails(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	for _, marker := range []string{
		"err.data = data;",
		"(data.failures || []).forEach",
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("index template missing bulk delete error detail marker %q", marker)
		}
	}
}

func TestIndexTemplateRefreshesAfterPartialBulkDelete(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	block := scriptFunctionBlock(t, string(data), "async function deleteSelectedMailboxes", "async function cleanAllRemoteCodes")
	for _, marker := range []string{"const data = err.data || {};", "(data.failures || []).forEach"} {
		if !strings.Contains(block, marker) {
			t.Errorf("partial bulk delete must expose structured failure details; missing %q", marker)
		}
	}
	errorDataAt := strings.Index(block, "const data = err.data || {};")
	refreshAt := strings.Index(block[errorDataAt:], "await refresh()")
	refreshAt = errorDataAt + refreshAt
	conditionalAt := strings.Index(block[errorDataAt:], "if (Number(data.deleted || 0) > 0)")
	conditionalAt = errorDataAt + conditionalAt
	if errorDataAt < 0 || refreshAt < errorDataAt || conditionalAt < errorDataAt || refreshAt > conditionalAt {
		t.Fatalf("partial bulk delete must refresh the mailbox list before checking whether local rows were deleted, block=%s", block)
	}
}

func TestIndexTemplateShowsRemoteCleanupFailureSummary(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "async function cleanAllRemoteCodes", "async function setMailboxStatus")
	for _, marker := range []string{
		"const data = err.data || {};",
		"data.failed_mailboxes",
		"data.cleanup",
		"处理邮箱",
		"失败邮箱",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("remote cleanup failure path must show summary; missing %q in %s", marker, block)
		}
	}
}

func TestIndexTemplateShowsStructuredCreateFailureDetails(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	block := scriptFunctionBlock(t, string(data), "async function createICloudMailbox", "function createChannelLabel")
	for _, marker := range []string{
		"const data = err.data || {};",
		"const failures = data.failures || [];",
		"renderCreateDetails(mailboxes, failures, remotes);",
		"data.message || '本次创建失败'",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("create failure path must show structured result details; missing %q in %s", marker, block)
		}
	}
}

func TestIndexTemplateSendsUnboundRemoteCleanupScope(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "async function cleanAllRemoteCodes", "async function setMailboxStatus")
	for _, marker := range []string{
		"const isUnbound = activeMailboxAccountKey === 'unbound';",
		"activeMailboxAccountKey !== 'all'",
		"body: JSON.stringify({account_id: accountID",
		"未绑定 Apple 账号 TAB",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("remote cleanup must preserve the unbound tab scope; missing %q in %s", marker, block)
		}
	}
	if strings.Contains(block, "activeMailboxAccountKey !== 'unbound'") {
		t.Fatal("remote cleanup must not convert the unbound tab into an all-mailboxes request")
	}
}

func TestIndexTemplateDoesNotInferICloudWebFromGenericCookieCount(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	start := strings.Index(html, "function iCloudWebLoginSaved(session)")
	if start < 0 {
		t.Fatal("index template is missing iCloudWebLoginSaved")
	}
	end := strings.Index(html[start:], "\n    function appleAccountLoginSaved")
	if end < 0 {
		t.Fatal("index template is missing appleAccountLoginSaved after iCloudWebLoginSaved")
	}
	block := html[start : start+end]
	if strings.Contains(block, "cookie_count") {
		t.Fatalf("iCloud Web login detection must not infer login state from generic cookie_count: %s", block)
	}
	if !strings.Contains(block, "session.icloud_web_login_saved") {
		t.Fatalf("iCloud Web login detection must use the backend-specific flag: %s", block)
	}
}

func TestIndexTemplateKeepsUnboundMailboxExportScope(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "if (activeMailboxAccountKey !== 'all') {\n          return activeMailboxAccountKey;") {
		t.Fatal("current mailbox export scope must preserve the unbound account tab")
	}
	if !strings.Contains(html, "id: 'unbound', title: '未绑定 Apple 账号'") {
		t.Fatal("index export account options must include the unbound mailbox group")
	}
}

func TestIndexTemplateProvidesMailboxAccountBindingControl(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	for _, marker := range []string{
		"function mailboxBindAccounts()",
		"function mailboxBindControl(row)",
		"async function bindMailboxToAccount",
		"/api/mailboxes/${encodeURIComponent(id)}/bind",
		"JSON.stringify({account_id: accountID})",
		"${mailboxBindControl(row)}",
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("index template missing mailbox account binding marker %q", marker)
		}
	}
}

func TestIndexTemplateEscapesDynamicInlineJavaScriptArguments(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "function jsArg(value)") {
		t.Fatal("index template must provide a JSON-based inline JavaScript argument helper")
	}
	for _, unsafeMarker := range []string{
		`toggleMailboxSelection('${esc(row.id)}'`,
		`verifyMailbox('${row.id}'`,
		`syncMailbox('${row.id}'`,
		`deleteMailbox('${row.id}'`,
	} {
		if strings.Contains(html, unsafeMarker) {
			t.Errorf("index template still interpolates an unsafe inline JavaScript argument: %q", unsafeMarker)
		}
	}
}

func TestIndexTemplateExportURLKeepsAPIExportedFilter(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	start := strings.Index(html, "function mailboxExportURL(")
	if start < 0 {
		t.Fatal("index template is missing mailboxExportURL")
	}
	end := strings.Index(html[start:], "function selectedMailboxIDsList")
	if end < 0 {
		t.Fatal("index template is missing selectedMailboxIDsList after mailboxExportURL")
	}
	block := html[start : start+end]
	for _, marker := range []string{
		"activeMailboxExportFilter",
		"params.set('api_exported', activeMailboxExportFilter === 'exported' ? '1' : '0')",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("index mailbox export URL missing marker %q in %s", marker, block)
		}
	}
}

func TestIndexTemplateExportURLKeepsMailboxSearch(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	start := strings.Index(html, "function mailboxExportURL(")
	if start < 0 {
		t.Fatal("index template is missing mailboxExportURL")
	}
	end := strings.Index(html[start:], "function selectedMailboxIDsList")
	if end < 0 {
		t.Fatal("index template is missing selectedMailboxIDsList after mailboxExportURL")
	}
	block := html[start : start+end]
	for _, marker := range []string{
		"const keyword = ($('mailboxSearch') ? $('mailboxSearch').value : '').trim();",
		"if (keyword) params.set('search', keyword);",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("index mailbox export URL missing search marker %q in %s", marker, block)
		}
	}
}

func TestIndexTemplateSendsExplicitLoginAccountID(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	for _, marker := range []string{
		`id="loginAccountID"`,
		`function renderLoginAccountOptions()`,
		`account_id: selectedLoginAccountID()`,
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("login form missing explicit account target marker %q", marker)
		}
	}
}

func TestIndexTemplateAllMailboxTabUsesFilteredTotal(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	start := strings.Index(html, "function renderMailboxAccountTabs()")
	if start < 0 {
		t.Fatal("index template is missing renderMailboxAccountTabs")
	}
	end := strings.Index(html[start:], "function renderMailboxExportAccountOptions()")
	if end < 0 {
		t.Fatal("index template is missing renderMailboxExportAccountOptions after renderMailboxAccountTabs")
	}
	block := html[start : start+end]
	if !strings.Contains(block, "全部 ${lastMailboxPagination.total || 0}") {
		t.Fatalf("all mailbox tab must use filtered pagination.total, block=%s", block)
	}
	if strings.Contains(block, "全部 ${lastMailboxPagination.total_all || 0}") {
		t.Fatalf("all mailbox tab still uses unfiltered total_all, block=%s", block)
	}
}

func TestIndexTemplateDoesNotResetActiveMailboxAccountWhenFilterHasZeroRows(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	start := strings.Index(html, "function renderMailboxAccountTabs()")
	if start < 0 {
		t.Fatal("index template is missing renderMailboxAccountTabs")
	}
	end := strings.Index(html[start:], "function renderMailboxExportAccountOptions()")
	if end < 0 {
		t.Fatal("index template is missing renderMailboxExportAccountOptions after renderMailboxAccountTabs")
	}
	block := html[start : start+end]
	if strings.Contains(block, "activeMailboxAccountKey = 'all';") {
		t.Fatalf("renderMailboxAccountTabs must not silently reset current account scope to all when the filtered group is empty, block=%s", block)
	}
	if !strings.Contains(block, "count: 0") {
		t.Fatalf("renderMailboxAccountTabs should render the current empty account group with count 0, block=%s", block)
	}
}

func TestIndexTemplatePreservesSelectedExportAccountWhenFilterHasZeroRows(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	start := strings.Index(html, "function renderMailboxExportAccountOptions()")
	if start < 0 {
		t.Fatal("index template is missing renderMailboxExportAccountOptions")
	}
	end := strings.Index(html[start:], "function setMailboxAccountTab")
	if end < 0 {
		t.Fatal("index template is missing setMailboxAccountTab after renderMailboxExportAccountOptions")
	}
	block := html[start : start+end]
	for _, marker := range []string{
		"current && current !== '__current' && current !== ''",
		"!ordered.some(group => group.id === current)",
		"ordered.push({",
		"id: current",
		"count: 0",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("export account options must preserve an empty selected account; missing %q in %s", marker, block)
		}
	}
}

func TestIndexTemplateClearsMailboxSelectionStateBeforeEmptyReturn(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	start := strings.Index(html, "function renderMailboxes()")
	if start < 0 {
		t.Fatal("index template is missing renderMailboxes")
	}
	end := strings.Index(html[start:], "function mailboxAccountTitle")
	if end < 0 {
		t.Fatal("index template is missing mailboxAccountTitle after renderMailboxes")
	}
	block := html[start : start+end]
	emptyAt := strings.Index(block, "if (rows.length === 0)")
	if emptyAt < 0 {
		t.Fatal("renderMailboxes is missing empty rows branch")
	}
	for _, marker := range []string{"const visibleSelectedCount", "const pageSelectEl", "const selectedInfo"} {
		at := strings.Index(block, marker)
		if at < 0 || at > emptyAt {
			t.Fatalf("%s must be updated before empty rows return, block=%s", marker, block)
		}
	}
}

func TestIndexTemplateRefreshesMailboxListAfterAPIExport(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "return true;") || !strings.Contains(html, "return false;") {
		t.Fatal("downloadExportFile should return success/cancel state so API exports can refresh the mailbox list")
	}
	apiBlock := scriptFunctionBlock(t, html, "async function exportMailboxAPIs", "async function exportMailboxEmails")
	for _, marker := range []string{
		"const exported = await downloadExportFile(",
		"if (exported) {",
		"selectedMailboxIDs.clear();",
		"await loadMailboxPage({silent: true});",
	} {
		if !strings.Contains(apiBlock, marker) {
			t.Errorf("exportMailboxAPIs must refresh after successful API export; missing %q in %s", marker, apiBlock)
		}
	}
	selectedBlock := scriptFunctionBlock(t, html, "async function exportSelectedMailboxes", "function initSessionCheckSettings")
	for _, marker := range []string{
		"const exported = await downloadExportFile(",
		"if (exported && mode !== 'email')",
		"await loadMailboxPage({silent: true});",
	} {
		if !strings.Contains(selectedBlock, marker) {
			t.Errorf("selected API export must refresh exported state; missing %q in %s", marker, selectedBlock)
		}
	}
}

func TestIndexTemplateUsesPOSTForWholeAPIExport(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "async function exportMailboxAPIs", "async function exportMailboxEmails")
	if !strings.Contains(block, "method: 'POST'") {
		t.Fatalf("whole API export must use POST because it updates APIExportedAt, block=%s", block)
	}
	if !strings.Contains(block, "body: JSON.stringify({format})") {
		t.Fatalf("whole API export must send the selected format in the POST body, block=%s", block)
	}
}

func TestIndexTemplateChoosesExportFileBeforeServerMarksExported(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "async function downloadExportFile", "async function exportMailboxAPIs")
	pickerAt := strings.Index(block, "showSaveFilePicker")
	fetchAt := strings.Index(block, "fetch(path")
	if pickerAt < 0 || fetchAt < 0 || pickerAt > fetchAt {
		t.Fatalf("downloadExportFile should open save picker before fetching export data, block=%s", block)
	}
}

func TestIndexTemplateRuntimeExportUsesDownloadHelper(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "async function exportRuntimeData", "function selectedMailboxExportFormat")
	for _, marker := range []string{
		"downloadExportFile(",
		"/api/runtime/export",
		"'json'",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("runtime export must use the safe download helper; missing %q in %s", marker, block)
		}
	}
}

func TestIndexTemplateSupportsJSONRuntimeExportTypes(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "function exportFileTypes", "async function downloadExportFile")
	if !strings.Contains(block, "format === 'json'") {
		t.Fatalf("index exportFileTypes must support runtime JSON exports, block=%s", block)
	}
}

func TestIndexTemplateIgnoresStaleMailboxResponses(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "async function loadMailboxPage", "function renderMailboxes")
	if !strings.Contains(html, "let mailboxLoadRequestSeq = 0;") {
		t.Fatalf("index template must declare a mailbox request sequence guard")
	}
	for _, marker := range []string{
		"const requestSeq = ++mailboxLoadRequestSeq;",
		"if (requestSeq !== mailboxLoadRequestSeq) {",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("loadMailboxPage must ignore stale mailbox responses; missing %q in %s", marker, block)
		}
	}
}

func TestIndexTemplateGuardsAsyncFilteredMailboxSelection(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "async function selectAllFilteredMailboxes", "function clearMailboxSelection")
	for _, marker := range []string{
		"let mailboxSelectionGeneration = 0;",
		"let mailboxSelectionAbortController = null;",
		"const selectionGeneration = ++mailboxSelectionGeneration;",
		"new AbortController()",
		"signal: controller.signal",
		"if (selectionGeneration !== mailboxSelectionGeneration)",
		"mailboxSelectionAbortController.abort()",
	} {
		if !strings.Contains(html, marker) && !strings.Contains(block, marker) {
			t.Errorf("filtered mailbox selection is missing race guard %q", marker)
		}
	}
}

func TestIndexTemplateSingleMailboxDeleteLogsRemoteFailures(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "async function deleteMailbox", "async function copyMailboxValue")
	for _, marker := range []string{
		"try {",
		"catch (err)",
		"log('删除邮箱失败：' + err.message);",
		"confirm_unknown",
		"confirm_failed",
		"remoteStatus === 'unknown'",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("deleteMailbox must log deletion failures; missing %q in %s", marker, block)
		}
	}
}

func TestIndexTemplateRefreshesAfterSingleMailboxDeleteFailure(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	block := scriptFunctionBlock(t, string(data), "async function deleteMailbox", "async function copyMailboxValue")
	errorAt := strings.Index(block, "catch (err)")
	if errorAt < 0 || !strings.Contains(block[errorAt:], "await refresh()") {
		t.Fatalf("single mailbox delete failure must refresh persisted remote-delete state: %s", block)
	}
}

func TestIndexTemplateShowsRemoteCleanupFailureDetails(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	block := scriptFunctionBlock(t, string(data), "async function cleanAllRemoteCodes", "async function setMailboxStatus")
	if !strings.Contains(block, "(data.failures || []).forEach") {
		t.Fatalf("remote cleanup must log failed mailbox details: %s", block)
	}
}

func TestIndexTemplateCopiesExternalMailboxAPIWithSeparateToken(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "async function copyMailboxValue", "async function writeClipboard")
	for _, marker := range []string{
		"row.api_url",
		"row.api_token",
		"const apiValue = `${apiURL}----${apiToken}`",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("copyMailboxValue must expose API URL and independent token; missing %q in %s", marker, block)
		}
	}
	if strings.Contains(block, "mailboxCodeURL(row") {
		t.Fatalf("copyMailboxValue must not copy the browser-only session URL")
	}
}

func TestIndexTemplateShowsPendingRemoteDeleteState(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	for _, marker := range []string{
		"remote_delete_status === 'pending'",
		"远端删除中",
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("index template missing pending remote delete marker %q", marker)
		}
	}
}

func TestIndexTemplateMailboxStatusActionsLogFailures(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	for _, tc := range []struct {
		name        string
		startMarker string
		endMarker   string
		logMarker   string
	}{
		{
			name:        "status",
			startMarker: "async function setMailboxStatus",
			endMarker:   "async function disableMailbox",
			logMarker:   "log('状态更新失败：' + err.message);",
		},
		{
			name:        "disable",
			startMarker: "async function disableMailbox",
			endMarker:   "async function deleteMailbox",
			logMarker:   "log('停用失败：' + err.message);",
		},
	} {
		block := scriptFunctionBlock(t, html, tc.startMarker, tc.endMarker)
		for _, marker := range []string{"try {", "catch (err)", tc.logMarker} {
			if !strings.Contains(block, marker) {
				t.Errorf("%s mailbox action must log failures; missing %q in %s", tc.name, marker, block)
			}
		}
	}
}

func TestIndexTemplateExportNetworkFailuresAreVisible(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	block := scriptFunctionBlock(t, string(data), "async function downloadExportFile", "async function exportMailboxAPIs")
	for _, marker := range []string{
		"try {\n        res = await fetch(",
		"log(failText + '：' + err.message);",
		"blob = await res.blob();",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("downloadExportFile must expose export network/body failures; missing %q in %s", marker, block)
		}
	}
}

func TestIndexTemplateLoginStartFailuresAreVisible(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	for _, tc := range []struct {
		name        string
		startMarker string
		endMarker   string
		logMarker   string
		buttonID    string
	}{
		{
			name:        "iCloud Web",
			startMarker: "async function startProtocolLogin",
			endMarker:   "async function submitProtocol2FA",
			logMarker:   "log('旧接口登录失败：' + err.message);",
			buttonID:    "protocolLoginButton",
		},
		{
			name:        "Apple Account",
			startMarker: "async function startAppleAccountLogin",
			endMarker:   "async function submitAppleAccount2FA",
			logMarker:   "log('新接口登录失败：' + err.message);",
			buttonID:    "appleAccountLoginButton",
		},
	} {
		block := scriptFunctionBlock(t, html, tc.startMarker, tc.endMarker)
		for _, marker := range []string{
			"const button = $('" + tc.buttonID + "');",
			"try {",
			"catch (err)",
			tc.logMarker,
			"finally {",
			"button.disabled = false;",
		} {
			if !strings.Contains(block, marker) {
				t.Errorf("%s login start must recover from request failures; missing %q in %s", tc.name, marker, block)
			}
		}
	}
}

func TestIndexTemplateFillsLoginFormOnSessionTab(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	for _, marker := range []string{
		"function fillLoginFormFromActiveSession(force)",
		"fillLoginFormFromActiveSession(true)",
		"function handleSessionCardKey(event, key)",
		"function showSessionLoginNotice(message)",
		"account.apple_password",
		"account.proxy_url",
		"$('icloudProxyURL')",
		"$('protocolPassword')",
		"$('protocolAppleId')",
		`onclick="setICloudSessionTab(${jsArg(sessionKey(active))})"`,
		"onkeydown=\"handleSessionCardKey(event,",
		"else if (switching)",
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("index template missing login autofill marker %q", marker)
		}
	}
	block := scriptFunctionBlock(t, html, "function setICloudSessionTab(key)", "function handleSessionCardKey(event, key)")
	if !strings.Contains(block, "fillLoginFormFromActiveSession(true)") {
		t.Fatalf("clicking a saved account must fill the login form, block=%s", block)
	}
	fillBlock := scriptFunctionBlock(t, html, "function fillLoginFormFromActiveSession(force)", "function sessionLoginNoticeBanner()")
	if !strings.Contains(fillBlock, "if (password)") || !strings.Contains(fillBlock, "else if (switching)") {
		t.Fatalf("empty stored password must not overwrite typed password, block=%s", fillBlock)
	}
	refreshBlock := scriptFunctionBlock(t, html, "async function refresh()", "function ensureSchedulerPolling()")
	if strings.Contains(refreshBlock, "fillLoginFormFromActiveSession(") {
		t.Fatal("refresh must not auto-fill the login form; filling is click-driven")
	}
	if strings.Contains(refreshBlock, "lastAccounts = [];") {
		t.Fatal("refresh must not clear lastAccounts when GET /api/accounts fails")
	}
	if strings.Contains(refreshBlock, "sessionLoginNotice = ''") || strings.Contains(refreshBlock, "clearSessionLoginNotice(") {
		t.Fatal("refresh must not clear a pending 2FA login notice")
	}
}

func TestIndexTemplateKeepsTwoFactorNoticeAfterRefresh(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	for _, marker := range []string{
		"let sessionLoginNotice = '';",
		"function sessionLoginNoticeBanner()",
		`id="sessionLoginNoticeBanner"`,
		"if (sessionLoginNotice)",
		"sessionLoginNoticeBanner() +",
		"function clearSessionLoginNotice()",
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("index template missing 2FA notice persistence marker %q", marker)
		}
	}
	renderBlock := scriptFunctionBlock(t, html, "function renderICloudSessions(sessions)", "function sessionKey(session)")
	if !strings.Contains(renderBlock, "sessionLoginNoticeBanner()") {
		t.Fatalf("renderICloudSessions must keep the 2FA banner after refresh, block=%s", renderBlock)
	}
	emptyAt := strings.Index(renderBlock, "if (displaySessions.length === 0)")
	if emptyAt < 0 || !strings.Contains(renderBlock[emptyAt:], "sessionLoginNoticeBanner()") {
		t.Fatal("empty session list must still show the pending 2FA notice")
	}
	for _, tc := range []struct {
		name        string
		startMarker string
		endMarker   string
	}{
		{"iCloud Web login", "async function startProtocolLogin", "async function submitProtocol2FA"},
		{"Apple Account login", "async function startAppleAccountLogin", "async function submitAppleAccount2FA"},
	} {
		block := scriptFunctionBlock(t, html, tc.startMarker, tc.endMarker)
		noticeAt := strings.Index(block, "showSessionLoginNotice(")
		refreshAt := strings.Index(block, "await refresh();")
		if noticeAt < 0 || refreshAt < 0 || noticeAt > refreshAt {
			t.Fatalf("%s must show the 2FA notice before refresh, block=%s", tc.name, block)
		}
	}
}

func TestIndexTemplateKeepsSessionTabsOnLoginNotice(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "function showSessionLoginNotice(message)") {
		t.Fatal("index template is missing showSessionLoginNotice")
	}
	for _, tc := range []struct {
		name        string
		startMarker string
		endMarker   string
	}{
		{"iCloud Web login", "async function startProtocolLogin", "async function submitProtocol2FA"},
		{"Apple Account login", "async function startAppleAccountLogin", "async function submitAppleAccount2FA"},
		{"iCloud Web 2FA", "async function submitProtocol2FA", "async function startAppleAccountLogin"},
		{"Apple Account 2FA", "async function submitAppleAccount2FA", "async function createICloudMailbox"},
	} {
		block := scriptFunctionBlock(t, html, tc.startMarker, tc.endMarker)
		if strings.Contains(block, "$('icloudSessionInfo').textContent =") {
			t.Errorf("%s still overwrites session tabs via icloudSessionInfo.textContent", tc.name)
		}
		if !strings.Contains(block, "showSessionLoginNotice(") {
			t.Errorf("%s must keep session tabs through showSessionLoginNotice", tc.name)
		}
	}
}

func TestIndexTemplateDisablesBrowserAutofillOnAppleLoginFields(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	for _, marker := range []string{
		`id="protocolAppleId" name="ipm-apple-id" autocomplete="off"`,
		`id="protocolPassword" name="ipm-apple-password" type="password" autocomplete="new-password"`,
		`id="icloudProxyURL" name="ipm-account-proxy" autocomplete="off"`,
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("index template missing browser autofill shield %q", marker)
		}
	}
	if strings.Contains(html, `id="protocolAppleId" autocomplete="username"`) {
		t.Fatal("Apple ID field still allows browser username autofill")
	}
	if strings.Contains(html, `id="protocolPassword" type="password" autocomplete="current-password"`) {
		t.Fatal("Apple password field still allows browser password autofill")
	}
}

func TestIndexTemplateClearsProxyInputAfterLoginStart(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	for _, tc := range []struct {
		name        string
		startMarker string
		endMarker   string
	}{
		{"iCloud Web login", "async function startProtocolLogin", "async function submitProtocol2FA"},
		{"Apple Account login", "async function startAppleAccountLogin", "async function submitAppleAccount2FA"},
	} {
		block := scriptFunctionBlock(t, html, tc.startMarker, tc.endMarker)
		requestAt := strings.Index(block, "proxy_url: $('icloudProxyURL').value.trim()")
		clearAt := strings.Index(block, "$('icloudProxyURL').value = '';")
		if requestAt < 0 {
			t.Fatalf("%s block is missing proxy_url payload: %s", tc.name, block)
		}
		if clearAt < 0 || clearAt < requestAt {
			t.Fatalf("%s must clear the proxy input after reading it into the login request, block=%s", tc.name, block)
		}
		needsAt := strings.Index(block, "if (data.needs_2fa)")
		if needsAt < 0 || needsAt > clearAt {
			t.Fatalf("%s must keep the typed proxy when 2FA is required, block=%s", tc.name, block)
		}
	}
}

func TestIndexTemplateShowsAppleAccountKeepAliveRetrying(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "function sessionManageRefreshBadge(session)", "function loginStateChipMode")
	for _, marker := range []string{
		"session.apple_account_keep_alive_stopped",
		"新接口保活：已停止",
		"session.apple_account_keep_alive_retrying",
		"新接口保活：重试中",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("keepalive badge missing marker %q", marker)
		}
	}
	clockBlock := scriptFunctionBlock(t, html, "function updateManageRefreshClocks()", "function ensureManageRefreshClockTimer")
	if !strings.Contains(clockBlock, "node.classList.contains('retrying')") || !strings.Contains(clockBlock, "新接口保活：重试中") {
		t.Fatalf("keepalive clock updater must keep retrying text stable, block=%s", clockBlock)
	}
}

func scriptFunctionBlock(t *testing.T, html, startMarker, endMarker string) string {
	t.Helper()
	start := strings.Index(html, startMarker)
	if start < 0 {
		t.Fatalf("template is missing %s", startMarker)
	}
	end := strings.Index(html[start:], endMarker)
	if end < 0 {
		t.Fatalf("template is missing %s after %s", endMarker, startMarker)
	}
	return html[start : start+end]
}
