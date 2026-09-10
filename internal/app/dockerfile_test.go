package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDockerfileBindsPanelToContainerNetwork(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dockerfilePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "Dockerfile")
	data, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	if !strings.Contains(string(data), `CMD ["--host", "0.0.0.0"`) {
		t.Fatalf("Dockerfile must bind the panel to 0.0.0.0 for published container ports:\n%s", data)
	}
}

func TestDockerfileChownsWritableDataMountAtStartup(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dockerfilePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "Dockerfile")
	data, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	text := string(data)
	for _, marker := range []string{
		"su-exec",
		"docker-entrypoint.sh",
		"ENTRYPOINT [\"/usr/local/bin/docker-entrypoint.sh\"]",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("Dockerfile missing %q:\n%s", marker, text)
		}
	}
	entrypointPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "docker-entrypoint.sh")
	entrypoint, err := os.ReadFile(entrypointPath)
	if err != nil {
		t.Fatalf("read docker-entrypoint.sh: %v", err)
	}
	if !strings.Contains(string(entrypoint), "if ! chown -R ipm:ipm /app/data") {
		t.Fatalf("docker-entrypoint.sh must repair data mount ownership:\n%s", entrypoint)
	}
}

func TestDockerfileInstallsCACertificatesForHTTPSProviders(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dockerfilePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "Dockerfile")
	data, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	if !strings.Contains(string(data), "ca-certificates") {
		t.Fatalf("Dockerfile must install ca-certificates for Apple/GitHub HTTPS calls:\n%s", data)
	}
}

func TestDockerEntrypointDropsPrivilegesAfterFixingDataDir(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	entrypointPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "docker-entrypoint.sh")
	data, err := os.ReadFile(entrypointPath)
	if err != nil {
		t.Fatalf("read docker-entrypoint.sh: %v", err)
	}
	text := string(data)
	for _, marker := range []string{
		"mkdir -p /app/data",
		"if ! chown -R ipm:ipm /app/data",
		"无法将 /app/data 设置为 ipm 用户可写",
		"exit 1",
		"exec su-exec ipm /app/icloud-privacy-mail \"$@\"",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("docker-entrypoint.sh missing %q:\n%s", marker, text)
		}
	}
}

func TestDockerEntrypointCopiesMountedConfigBeforeDroppingPrivileges(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(sourceFile), "..", "..")
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	if !strings.Contains(string(dockerfile), `CMD ["--host", "0.0.0.0", "--config", "/app/data/config.json"]`) {
		t.Fatalf("Dockerfile must use the writable copied config path:\n%s", dockerfile)
	}
	entrypoint, err := os.ReadFile(filepath.Join(root, "docker-entrypoint.sh"))
	if err != nil {
		t.Fatalf("read docker-entrypoint.sh: %v", err)
	}
	text := string(entrypoint)
	for _, marker := range []string{
		`CONFIG_SOURCE="${IPM_CONFIG_SOURCE:-/app/config.json}"`,
		"CONFIG_TARGET=/app/data/config.json",
		`[ ! -f "$CONFIG_TARGET" ] || [ "${IPM_CONFIG_FORCE:-}" = "1" ]`,
		"cp \"$CONFIG_SOURCE\" \"$CONFIG_TARGET\"",
		"chown ipm:ipm \"$CONFIG_TARGET\"",
		"chmod 600 \"$CONFIG_TARGET\"",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("docker-entrypoint.sh missing mounted config protection %q:\n%s", marker, text)
		}
	}
}

func TestDockerignoreExcludesLocalBuildOutputsAndSecrets(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	ignorePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", ".dockerignore")
	data, err := os.ReadFile(ignorePath)
	if err != nil {
		t.Fatalf("read .dockerignore: %v", err)
	}
	text := string(data)
	for _, marker := range []string{"panel", "config.json", "*.secret.json", "*.key", "*.pem", "data", "logs"} {
		if !strings.Contains(text, marker) {
			t.Errorf(".dockerignore missing %q", marker)
		}
	}
}

func TestDockerImageWorkflowBuildsOwnedGHCRImageOnEveryPush(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	workflowPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", ".github", "workflows", "docker-image.yml")
	data, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read docker workflow: %v", err)
	}
	text := string(data)
	for _, marker := range []string{
		"on:",
		"push:",
		"actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
		"actions/setup-go@d35c59abb061a4a6fb18e82ac0862c26744d6ab5",
		"docker/setup-qemu-action@1f40c72289eff860ee54a304f1438e3cff362e0a",
		"docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
		"docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9",
		"docker/metadata-action@c299e40c65443455700f0fdfc63efafe5b349051",
		"docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8",
		"PUSH_IMAGE=true",
		"if: env.PUSH_IMAGE == 'true'",
		"push: ${{ env.PUSH_IMAGE == 'true' }}",
		"type=cacheonly",
		"type=sha",
		"ghcr.io/biubiubiu125/icloud-privacy-mail",
		"packages: write",
		"attestations: write",
		"id-token: write",
		"provenance: false",
		"sbom: false",
		"go test -count=1 ./...",
		"go vet ./...",
		"go build ./...",
	} {
		if !strings.Contains(text, marker) {
			t.Errorf("docker workflow missing %q", marker)
		}
	}
	onStart := strings.Index(text, "on:\n")
	permissionsStart := strings.Index(text, "\npermissions:")
	if onStart < 0 || permissionsStart <= onStart {
		t.Fatalf("docker workflow trigger block is not in the expected form:\n%s", text)
	}
	triggerBlock := text[onStart:permissionsStart]
	if strings.Contains(triggerBlock, "\n    branches:") || strings.Contains(triggerBlock, "\n    tags:") {
		t.Fatalf("docker workflow must build every pushed branch/tag, not only selected refs:\n%s", triggerBlock)
	}
	if !strings.Contains(triggerBlock, "\n  workflow_dispatch:\n") {
		t.Fatalf("docker workflow must retain manual dispatch:\n%s", triggerBlock)
	}
	if strings.Contains(text, "\n          push: true\n") {
		t.Fatalf("docker workflow must not publish feature branch images into the stable namespace:\n%s", text)
	}
	setupQEMUAt := strings.Index(text, "docker/setup-qemu-action")
	setupBuildxAt := strings.Index(text, "docker/setup-buildx-action")
	if setupQEMUAt < 0 || setupBuildxAt < 0 || setupQEMUAt > setupBuildxAt {
		t.Fatalf("docker workflow must set up QEMU before buildx for multi-platform builds:\n%s", text)
	}
}

func TestDockerImageWorkflowDoesNotDuplicateTaggedReleaseBuilds(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	workflowPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", ".github", "workflows", "docker-image.yml")
	data, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read docker workflow: %v", err)
	}
	if strings.Contains(string(data), "\n  release:\n") {
		t.Fatal("docker workflow must not build the same published tag again through a release event")
	}
}

func TestDockerImageWorkflowBuildsExistingVersionTagStyle(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	workflowPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", ".github", "workflows", "docker-image.yml")
	data, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read docker workflow: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "type=ref,event=tag") {
		t.Fatalf("docker workflow must publish the repository's existing version tags:\n%s", data)
	}
}

func TestDockerImageWorkflowCancelsStaleInFlightBuilds(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	workflowPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", ".github", "workflows", "docker-image.yml")
	data, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read docker workflow: %v", err)
	}
	text := string(data)
	for _, marker := range []string{
		"concurrency:",
		"group: ${{ github.workflow }}-${{ github.ref }}",
		"cancel-in-progress: true",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("docker workflow missing %q:\n%s", marker, text)
		}
	}
}
