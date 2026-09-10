package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVersionIsNewer(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{current: "2026.07.01", latest: "2026.07.02", want: true},
		{current: "v1.2.3", latest: "v1.2.3", want: false},
		{current: "2026.07.02", latest: "v2026.7.2", want: false},
		{current: "v1.2.4", latest: "v1.2.3", want: false},
		{current: "dev", latest: "2026.07.02", want: true},
		{current: "2026.07.02", latest: "", want: false},
	}
	for _, tt := range tests {
		if got := versionIsNewer(tt.current, tt.latest); got != tt.want {
			t.Fatalf("versionIsNewer(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}

func TestSelectManifestAsset(t *testing.T) {
	assets := []updateManifestAsset{
		{Name: "icloud-privacy-mail_windows_amd64.exe", OS: "windows", Arch: "amd64", URL: "https://example.invalid/win"},
		{Name: "icloud-privacy-mail_linux_amd64.tar.gz", OS: "linux", Arch: "amd64", URL: "https://example.invalid/archive"},
		{Name: "icloud-privacy-mail_linux_amd64", OS: "linux", Arch: "amd64", URL: "https://example.invalid/linux"},
	}
	got, ok := selectManifestAsset(assets, "linux", "amd64", "")
	if !ok || got.Name != "icloud-privacy-mail_linux_amd64" {
		t.Fatalf("selected asset = %+v ok=%v, want linux amd64", got, ok)
	}
	got, ok = selectManifestAsset(assets, "linux", "amd64", "icloud-privacy-mail_windows_amd64.exe")
	if !ok || got.Name != "icloud-privacy-mail_linux_amd64" {
		t.Fatalf("preferred asset = %+v ok=%v, want compatible fallback", got, ok)
	}
}

func TestSelectGitHubReleaseAssetRejectsPreferredOtherPlatform(t *testing.T) {
	assets := []githubReleaseAsset{
		{Name: "icloud-privacy-mail_windows_amd64.exe", BrowserDownloadURL: "https://example.invalid/win"},
		{Name: "icloud-privacy-mail_linux_amd64", BrowserDownloadURL: "https://example.invalid/linux"},
	}
	if asset, ok := selectGitHubReleaseAsset(assets, "linux", "amd64", "icloud-privacy-mail_windows_amd64.exe"); !ok || asset.Name != "icloud-privacy-mail_linux_amd64" {
		t.Fatalf("selected asset = %+v ok=%v, want compatible fallback", asset, ok)
	}
}

func TestFetchGitHubReleaseUpdateCandidateUsesReleaseChecksum(t *testing.T) {
	const checksum = "203165b07063e4c7d44d3150ec17b8e2e2e4a3c5388c7e9c29e6d83e47d5030f"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/biubiubiu125/iCloud-Privacy-Mail/releases/latest":
			_, _ = w.Write([]byte(`{
				"tag_name":"2026.09.07",
				"name":"2026.09.07",
				"assets":[
					{"name":"icloud-privacy-mail_linux_amd64","browser_download_url":"https://example.invalid/download"},
					{"name":"SHA256SUMS","browser_download_url":"http://` + r.Host + `/download/SHA256SUMS"}
				]
			}`))
		case "/download/SHA256SUMS":
			_, _ = w.Write([]byte(checksum + "  icloud-privacy-mail_linux_amd64\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	oldBaseURL := updateGitHubAPIBaseURL
	updateGitHubAPIBaseURL = server.URL
	defer func() { updateGitHubAPIBaseURL = oldBaseURL }()

	s := &Server{cfg: Config{UpdateEnabled: true, UpdateRepository: "biubiubiu125/iCloud-Privacy-Mail"}}
	candidate, err := s.fetchGitHubReleaseUpdateCandidate(context.Background(), publicUpdateStatus{Enabled: true, Current: currentVersionInfo()})
	if err != nil {
		t.Fatalf("fetchGitHubReleaseUpdateCandidate returned error: %v", err)
	}
	if got := candidate.SHA256; got != checksum {
		t.Fatalf("candidate SHA256 = %q, want %q", got, checksum)
	}
}

func TestFetchGitHubReleaseUpdateCandidateRejectsMissingChecksum(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/biubiubiu125/iCloud-Privacy-Mail/releases/latest" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{
			"tag_name":"2026.09.07",
			"assets":[{"name":"icloud-privacy-mail_linux_amd64","browser_download_url":"https://example.invalid/download"}]
		}`))
	}))
	defer server.Close()

	oldBaseURL := updateGitHubAPIBaseURL
	updateGitHubAPIBaseURL = server.URL
	defer func() { updateGitHubAPIBaseURL = oldBaseURL }()

	s := &Server{cfg: Config{UpdateEnabled: true, UpdateRepository: "biubiubiu125/iCloud-Privacy-Mail"}}
	_, err := s.fetchGitHubReleaseUpdateCandidate(context.Background(), publicUpdateStatus{Enabled: true, Current: currentVersionInfo()})
	if err == nil || !strings.Contains(err.Error(), "SHA256SUMS") {
		t.Fatalf("error = %v, want missing SHA256SUMS error", err)
	}
}

func TestFetchManifestUpdateCandidateRejectsMissingChecksum(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"version":"2026.09.08",
			"assets":[{
				"name":"icloud-privacy-mail_linux_amd64",
				"os":"linux",
				"arch":"amd64",
				"url":"https://example.invalid/download"
			}]
		}`))
	}))
	defer server.Close()

	s := &Server{cfg: Config{UpdateEnabled: true}}
	_, err := s.fetchManifestUpdateCandidate(context.Background(), server.URL, publicUpdateStatus{
		Enabled: true,
		Current: currentVersionInfo(),
	})
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("error = %v, want manifest sha256 validation error", err)
	}
}

func TestFetchManifestUpdateCandidateRejectsInvalidChecksum(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"version":"2026.09.08",
			"assets":[{
				"name":"icloud-privacy-mail_linux_amd64",
				"os":"linux",
				"arch":"amd64",
				"url":"https://example.invalid/download",
				"sha256":"not-a-sha256"
			}]
		}`))
	}))
	defer server.Close()

	s := &Server{cfg: Config{UpdateEnabled: true}}
	_, err := s.fetchManifestUpdateCandidate(context.Background(), server.URL, publicUpdateStatus{
		Enabled: true,
		Current: currentVersionInfo(),
	})
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("error = %v, want manifest sha256 validation error", err)
	}
}

func TestFetchGitHubReleaseMissingFallsBackToDefaultBranchCommit(t *testing.T) {
	const latestSHA = "76acb88aabbccddeeff0011223344556677889900"
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		switch r.URL.Path {
		case "/repos/biubiubiu125/iCloud-Privacy-Mail/releases/latest":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found","status":"404"}`))
		case "/repos/biubiubiu125/iCloud-Privacy-Mail":
			_, _ = w.Write([]byte(`{"default_branch":"master"}`))
		case "/repos/biubiubiu125/iCloud-Privacy-Mail/commits/master":
			_, _ = w.Write([]byte(`{"sha":"` + latestSHA + `","commit":{"message":"最新提交","committer":{"date":"2026-07-02T03:00:00Z"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	oldBaseURL := updateGitHubAPIBaseURL
	oldCommit := AppCommit
	updateGitHubAPIBaseURL = server.URL
	AppCommit = "76acb88"
	defer func() {
		updateGitHubAPIBaseURL = oldBaseURL
		AppCommit = oldCommit
	}()

	s := &Server{cfg: Config{
		UpdateEnabled:    true,
		UpdateRepository: "biubiubiu125/iCloud-Privacy-Mail",
	}}
	candidate, err := s.fetchGitHubReleaseUpdateCandidate(context.Background(), publicUpdateStatus{
		Enabled:   true,
		Current:   currentVersionInfo(),
		CheckedAt: formatTime(time.Now()),
	})
	if err != nil {
		t.Fatalf("fetchGitHubReleaseUpdateCandidate returned error: %v", err)
	}
	if candidate.Status.Error != "" {
		t.Fatalf("status error = %q, want empty", candidate.Status.Error)
	}
	if candidate.Status.UpdateAvailable {
		t.Fatalf("update_available = true, want false when current commit matches default branch")
	}
	if !strings.Contains(candidate.Status.LatestName, "76acb88") {
		t.Fatalf("latest_name = %q, want short commit", candidate.Status.LatestName)
	}
	wantRequests := strings.Join([]string{
		"/repos/biubiubiu125/iCloud-Privacy-Mail/releases/latest",
		"/repos/biubiubiu125/iCloud-Privacy-Mail",
		"/repos/biubiubiu125/iCloud-Privacy-Mail/commits/master",
	}, ",")
	if got := strings.Join(requests, ","); got != wantRequests {
		t.Fatalf("requests = %s, want %s", got, wantRequests)
	}
}

func TestDownloadAndReplaceExecutableDoesNotReturnHTTPBody(t *testing.T) {
	const secret = "provider raw response secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(secret))
	}))
	defer server.Close()

	exePath := filepath.Join(t.TempDir(), "icloud-privacy-mail")
	if err := os.WriteFile(exePath, []byte("current"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := downloadAndReplaceExecutable(context.Background(), server.URL, strings.Repeat("0", 64), exePath)
	if err == nil {
		t.Fatal("downloadAndReplaceExecutable returned nil")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("download error leaked HTTP body: %q", err)
	}
	if !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("download error = %q, want HTTP 502", err)
	}
}
