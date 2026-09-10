package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGitHubReleaseWorkflowPublishesBareBinariesForUpdater(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	workflowPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	text := string(data)
	for _, marker := range []string{
		"on:",
		"push:",
		"tags:",
		"permissions:",
		"contents: write",
		"concurrency:",
		"actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
		"actions/setup-go@d35c59abb061a4a6fb18e82ac0862c26744d6ab5",
		"go test -count=1 ./...",
		"go vet ./...",
		"go build ./...",
		"gh release create",
		"gh release upload",
		"gh release edit \"$RELEASE_TAG\" --draft=false",
		"gh release view \"$RELEASE_TAG\" --json isDraft -q '.isDraft'",
		"published release already exists",
		"--draft",
		"icloud-privacy-mail_linux_amd64",
		"icloud-privacy-mail_linux_arm64",
		"icloud-privacy-mail_windows_amd64.exe",
		"sha256sum dist/* > dist/SHA256SUMS",
		"SHA256SUMS",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("release workflow missing %q:\n%s", marker, text)
		}
	}
	uploadAt := strings.Index(text, "gh release upload")
	publishAt := strings.Index(text, "gh release edit \"$RELEASE_TAG\" --draft=false")
	if uploadAt < 0 || publishAt < 0 || uploadAt > publishAt {
		t.Fatalf("release workflow must upload assets before publishing the draft release:\n%s", text)
	}
	createAt := strings.Index(text, "- name: Create draft release")
	buildAt := strings.Index(text, "- name: Build release binaries")
	if createAt < 0 || buildAt < 0 || createAt < buildAt {
		t.Fatalf("release workflow must verify and build before creating the draft release:\n%s", text)
	}
}

func TestGitHubReleaseWorkflowRefusesToOverwritePublishedRelease(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	workflowPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	text := string(data)
	guardStart := strings.Index(text, "- name: Verify release tag is reusable")
	guardEnd := strings.Index(text, "- name: Set up Go")
	if guardStart < 0 || guardEnd <= guardStart {
		t.Fatalf("release workflow is missing the reusable-tag guard:\n%s", text)
	}
	guard := text[guardStart:guardEnd]
	for _, marker := range []string{
		"gh release view \"$RELEASE_TAG\" --json isDraft -q '.isDraft'",
		"published release already exists",
		"exit 1",
	} {
		if !strings.Contains(guard, marker) {
			t.Fatalf("release tag guard missing %q:\n%s", marker, guard)
		}
	}
}

func TestDeploymentGuidesUseOneStatePathAndMatchingServiceBinary(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(sourceFile), "..", "..")
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	releaseGuide, err := os.ReadFile(filepath.Join(root, "发布说明.md"))
	if err != nil {
		t.Fatalf("read release guide: %v", err)
	}
	for name, text := range map[string]string{
		"README": string(readme),
		"发布说明":   string(releaseGuide),
	} {
		if strings.Contains(text, "/opt/icloud-privacy-mail/shared/data/state.json") {
			t.Fatalf("%s still documents the obsolete shared state path", name)
		}
		if strings.Contains(text, "/opt/icloud-privacy-mail/shared/config.json") {
			t.Fatalf("%s still documents the obsolete shared config path", name)
		}
		if strings.Contains(text, "/opt/icloud-privacy-mail/current") {
			t.Fatalf("%s still documents the unsupported current symlink deployment", name)
		}
		if !strings.Contains(text, "/opt/icloud-privacy-mail/data/state.json") {
			t.Fatalf("%s must document /opt/icloud-privacy-mail/data/state.json", name)
		}
	}
	if !strings.Contains(string(readme), "ExecStart=/opt/icloud-privacy-mail/icloud-privacy-mail") ||
		!strings.Contains(string(releaseGuide), "ExecStart=/opt/icloud-privacy-mail/icloud-privacy-mail") {
		t.Fatal("deployment guides must use the fixed binary path supported by the updater")
	}
}

func TestReleaseGuideDocumentsOwnedUpdateAndImageSources(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	guidePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "发布说明.md")
	data, err := os.ReadFile(guidePath)
	if err != nil {
		t.Fatalf("read release guide: %v", err)
	}
	text := string(data)
	for _, marker := range []string{
		"biubiubiu125/iCloud-Privacy-Mail",
		"ghcr.io/biubiubiu125/icloud-privacy-mail",
		"update_enabled",
		"update_repository",
		"update_manifest_url",
		"update_asset_name",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("release guide missing %q:\n%s", marker, text)
		}
	}
}

func TestGitHubReleaseWorkflowCancelsStaleTagRuns(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	workflowPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	text := string(data)
	for _, marker := range []string{
		"concurrency:",
		"group: ${{ github.workflow }}-${{ github.ref }}",
		"cancel-in-progress: true",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("release workflow missing %q:\n%s", marker, text)
		}
	}
}

func TestREADMEDescribesAutomaticReleaseAssetPublication(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	readmePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "README.md")
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	text := string(data)
	for _, marker := range []string{
		".github/workflows/release.yml",
		"版本标签推送后",
		"自动构建",
		"icloud-privacy-mail_linux_amd64",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("README missing release publication marker %q:\n%s", marker, text)
		}
	}
}
