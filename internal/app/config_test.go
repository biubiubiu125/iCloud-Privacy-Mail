package app

import "testing"

func TestLoadConfigDefaultsUpdateRepositoryToUserRepo(t *testing.T) {
	t.Setenv("IPM_UPDATE_REPOSITORY", "")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}

	if got, want := cfg.UpdateRepository, "biubiubiu125/iCloud-Privacy-Mail"; got != want {
		t.Fatalf("UpdateRepository = %q, want %q", got, want)
	}
}
