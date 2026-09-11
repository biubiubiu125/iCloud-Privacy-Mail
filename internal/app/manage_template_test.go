package app

import (
	"strings"
	"testing"
)

func TestManageTemplateIncludesMailboxPoolBatchControls(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	html := string(data)
	for _, marker := range []string{
		`id="mailboxExportFilter"`,
		`id="mailboxPageSelectAll"`,
		`onclick="exportSelectedMailboxes('api')"`,
		`onclick="deleteSelectedMailboxes(true)"`,
		`function selectAllFilteredMailboxes()`,
		`function handleMailboxSelectionChange`,
		`api_exported`,
		`confirm_unknown`,
		`remote_delete_status === 'pending'`,
		`remote_delete_status === 'unknown'`,
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("manage template missing mailbox pool marker %q", marker)
		}
	}
}

func TestManageTemplateShowsBulkDeleteFailureDetails(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	html := string(data)
	for _, marker := range []string{
		"err.data = data;",
		"(data.failures || []).forEach",
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("manage template missing bulk delete error detail marker %q", marker)
		}
	}
}

func TestManageTemplateRefreshesAfterPartialBulkDelete(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	block := scriptFunctionBlock(t, string(data), "async function deleteSelectedMailboxes", "async function deleteMailboxFromManage")
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

func TestManageTemplateIncludesUnboundMailboxExportOption(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "value=\"unbound\"") {
		t.Fatal("manage export account options must include the unbound mailbox group")
	}
}

func TestManageTemplateProvidesMailboxAccountBindingControl(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	html := string(data)
	for _, marker := range []string{
		"function mailboxBindAccounts()",
		"function mailboxBindControl(mailbox)",
		"async function bindMailboxToAccount",
		"/api/mailboxes/${encodeURIComponent(id)}/bind",
		"JSON.stringify({account_id: accountID})",
		"${mailboxBindControl(m)}",
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("manage template missing mailbox account binding marker %q", marker)
		}
	}
}

func TestManageTemplateEscapesDynamicInlineJavaScriptArguments(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "function jsArg(value)") {
		t.Fatal("manage template must provide a JSON-based inline JavaScript argument helper")
	}
	for _, unsafeMarker := range []string{
		`handleMailboxSelectionChange('${esc(m.id)}'`,
		`deleteMailboxFromManage('${esc(m.id)}'`,
		`deleteUser('${esc(u.id)}'`,
		`updateAccountProxy('${esc(a.id)}'`,
	} {
		if strings.Contains(html, unsafeMarker) {
			t.Errorf("manage template still interpolates an unsafe inline JavaScript argument: %q", unsafeMarker)
		}
	}
}

func TestManageTemplateExportURLKeepsAPIExportedFilter(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	html := string(data)
	start := strings.Index(html, "function mailboxExportURL(")
	if start < 0 {
		t.Fatal("manage template is missing mailboxExportURL")
	}
	end := strings.Index(html[start:], "function exportFileTypes")
	if end < 0 {
		t.Fatal("manage template is missing exportFileTypes after mailboxExportURL")
	}
	block := html[start : start+end]
	for _, marker := range []string{
		"mailboxExportFilter",
		"params.set('api_exported', mailboxExportFilter === 'exported' ? '1' : '0')",
		"selectedOwner === ''",
		"__global",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("manage mailbox export URL missing marker %q in %s", marker, block)
		}
	}
}

func TestManageTemplateRefreshesMailboxListAfterAPIExport(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "return true;") || !strings.Contains(html, "return false;") {
		t.Fatal("downloadExportFile should return success/cancel state so API exports can refresh the mailbox list")
	}
	selectedBlock := scriptFunctionBlock(t, html, "async function exportSelectedMailboxes", "async function deleteSelectedMailboxes")
	for _, marker := range []string{
		"const exported = await downloadExportFile(",
		"if (exported && mode !== 'email')",
		"await refresh();",
	} {
		if !strings.Contains(selectedBlock, marker) {
			t.Errorf("selected API export must refresh exported state; missing %q in %s", marker, selectedBlock)
		}
	}
	apiBlock := scriptFunctionBlock(t, html, "async function exportMailboxAPIs", "async function exportMailboxEmails")
	for _, marker := range []string{
		"const exported = await downloadExportFile(",
		"if (exported) {",
		"selectedMailboxIDs.clear();",
		"await refresh();",
	} {
		if !strings.Contains(apiBlock, marker) {
			t.Errorf("exportMailboxAPIs must refresh after successful API export; missing %q in %s", marker, apiBlock)
		}
	}
}

func TestManageTemplateRefreshesAfterSingleMailboxDeleteFailure(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	block := scriptFunctionBlock(t, string(data), "async function deleteMailboxFromManage", "async function exportData")
	errorAt := strings.Index(block, "catch (err)")
	if errorAt < 0 || !strings.Contains(block[errorAt:], "await refresh()") {
		t.Fatalf("single mailbox delete failure must refresh persisted remote-delete state: %s", block)
	}
}

func TestManageTemplateBulkRemoteDeleteOnlyConfirmsUnknown(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatal(err)
	}
	block := scriptFunctionBlock(t, string(data), "async function deleteSelectedMailboxes", "async function deleteMailboxFromManage")
	if !strings.Contains(block, "remote_delete_status === 'unknown'") {
		t.Fatalf("bulk remote delete must only confirm unknown rows: %s", block)
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

func TestManageTemplateRollsBackAPIExportWhenBlobReadFails(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
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

func TestManageTemplateSendsMailboxSelectionScopeWithBulkDelete(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	block := scriptFunctionBlock(t, string(data), "async function deleteSelectedMailboxes", "async function deleteMailboxFromManage")
	for _, marker := range []string{
		"function mailboxSelectionScope()",
		"scope: mailboxSelectionScope()",
		"owner_id",
		"account_key",
		"exported",
	} {
		if !strings.Contains(string(data), marker) && !strings.Contains(block, marker) {
			t.Errorf("manage bulk delete is missing selection scope marker %q", marker)
		}
	}
}

func TestManageTemplateUsesPOSTForWholeAPIExport(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
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

func TestManageTemplateRuntimeExportUsesDownloadHelper(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "async function exportData", "function selectedMailboxExportFormat")
	for _, marker := range []string{
		"downloadExportFile(",
		"/api/runtime/export",
		"owner_id",
		"'json'",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("runtime export must use the safe download helper; missing %q in %s", marker, block)
		}
	}
}

func TestManageTemplateSupportsJSONRuntimeExportTypes(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "function exportFileTypes", "async function downloadExportFile")
	if !strings.Contains(block, "format === 'json'") {
		t.Fatalf("manage exportFileTypes must support runtime JSON exports, block=%s", block)
	}
}

func TestManageTemplateChoosesExportFileBeforeServerMarksExported(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "async function downloadExportFile", "async function exportMailboxAPIs")
	pickerAt := strings.Index(block, "showSaveFilePicker")
	fetchAt := strings.Index(block, "fetch(path")
	if pickerAt < 0 || fetchAt < 0 || pickerAt > fetchAt {
		t.Fatalf("downloadExportFile should open save picker before fetching export data, block=%s", block)
	}
}

func TestManageTemplateExportNetworkFailuresAreVisible(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
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

func TestManageTemplateShowsStructuredExportFailures(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	block := scriptFunctionBlock(t, string(data), "async function downloadExportFile", "async function exportMailboxAPIs")
	for _, marker := range []string{
		"let message = `HTTP ${res.status}`;",
		"const data = await res.json();",
		"message = data.message || data.code || message;",
		"log(failText + '：' + message);",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("manage export failure must expose structured server details; missing %q", marker)
		}
	}
}

func TestManageTemplatePrefillsFullAccountProxy(t *testing.T) {
	data, err := webFS.ReadFile("templates/manage.html")
	if err != nil {
		t.Fatalf("read manage template: %v", err)
	}
	html := string(data)
	block := scriptFunctionBlock(t, html, "async function updateAccountProxy", "function mailboxBindAccounts")
	for _, marker := range []string{
		"window.prompt(promptText, account.proxy_url || '')",
		"会按填写内容原样保存（含账号密码）",
	} {
		if !strings.Contains(block, marker) {
			t.Errorf("manage proxy editor missing full-proxy marker %q in %s", marker, block)
		}
	}
	if strings.Contains(block, "出于安全原因不会回显") {
		t.Fatal("manage proxy editor still hides the saved proxy")
	}
}
