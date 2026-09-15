package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIndexLoginFillBehavior(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node is required to execute the homepage login fill loop")
	}
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read index template: %v", err)
	}
	html := string(data)
	sessionKeyFn := scriptFunctionBlock(t, html, "function sessionKey(session)", "function setICloudSessionTab(key)")
	accountFn := scriptFunctionBlock(t, html, "function accountForSession(session)", "function fillLoginFormFromActiveSession(force)")
	fillFn := scriptFunctionBlock(t, html, "function fillLoginFormFromActiveSession(force)", "function sessionLoginNoticeBanner()")
	activeFn := scriptFunctionBlock(t, html, "function activeICloudSessionForBinding()", "function activeICloudSessionAccountID()")
	harness := `const fields = {
  protocolAppleId: { value: '' },
  protocolPassword: { value: 'typed-password' },
  icloudProxyURL: { value: '' },
  loginAccountID: { value: '' }
};
function $(id) { return fields[id]; }
function visibleICloudSessions(sessions) { return (sessions || []).filter(session => session && session.saved); }
function assert(cond, msg) { if (!cond) { console.error(msg); process.exit(1); } }
let lastAccounts = [];
let lastICloudSessions = [];
let activeICloudSessionKey = '';
` + sessionKeyFn + "\n" + accountFn + "\n" + fillFn + "\n" + activeFn + `
lastAccounts = [{id:'acc_1', apple_id:'yx@example.com', apple_password:'secret-pass', proxy_url:'http://user:pass@10.0.0.8:1080'}];
lastICloudSessions = [{saved:true, account_id:'acc_1', apple_id:'yx@example.com', proxy_url:'http://ignored'}];
activeICloudSessionKey = 'acc_1';
fillLoginFormFromActiveSession(true);
assert(fields.protocolAppleId.value === 'yx@example.com', 'apple id');
assert(fields.protocolPassword.value === 'secret-pass', 'password');
assert(fields.icloudProxyURL.value === 'http://user:pass@10.0.0.8:1080', 'full proxy');
assert(fields.loginAccountID.value === 'acc_1', 'account id');
fields.protocolPassword.value = 'typed-password';
lastAccounts[0].apple_password = '';
fillLoginFormFromActiveSession(true);
assert(fields.protocolPassword.value === 'typed-password', 'keep typed password');
fields.protocolAppleId.value = 'old@example.com';
fields.protocolPassword.value = 'typed-password';
fields.icloudProxyURL.value = 'http://old-user:old-pass@127.0.0.1:7890';
lastAccounts = [{id:'acc_2', apple_id:'new@example.com', apple_password:'', proxy_url:''}];
lastICloudSessions = [{saved:true, account_id:'acc_2', apple_id:'new@example.com'}];
activeICloudSessionKey = 'acc_2';
fillLoginFormFromActiveSession(true);
assert(fields.protocolAppleId.value === 'new@example.com', 'switched apple id');
assert(fields.protocolPassword.value === '', 'clear password when switching');
assert(fields.icloudProxyURL.value === '', 'clear proxy when switching');
console.log('ok');
`
	dir := t.TempDir()
	path := filepath.Join(dir, "fill.js")
	if err := os.WriteFile(path, []byte(harness), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("login fill behavior failed: %v\n%s", err, out)
	}
}
