package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomicFileReplacesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("write old file: %v", err)
	}
	if err := writeAtomicFile(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("writeAtomicFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replaced file: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("replaced file = %q, want %q", data, "new")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file still exists: %v", err)
	}
}
