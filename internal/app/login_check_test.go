package app

import (
	"context"
	"testing"
	"time"
)

func TestCheckSavedLoginStatesPassesSessionProxyToIMAPChecker(t *testing.T) {
	const proxyURL = "http://127.0.0.1:7890"
	var gotProxy string
	session := withICloudIMAPLoginState(ICloudSession{
		ProxyURL: proxyURL,
		AppleID:  "owner@example.com",
	}, LoginState{
		IMAPEmail:       "owner@icloud.com",
		IMAPAppPassword: "app-password",
		ProxyURL:        proxyURL,
	})

	_, ok, err := checkSavedLoginStatesWithIMAPProxy(
		context.Background(),
		NewICloudClient(),
		session,
		time.Now(),
		func(_ context.Context, _, _ string, proxy string) error {
			gotProxy = proxy
			return nil
		},
	)
	if err != nil || !ok {
		t.Fatalf("check result err=%v ok=%t", err, ok)
	}
	if gotProxy != proxyURL {
		t.Fatalf("IMAP proxy = %q, want %q", gotProxy, proxyURL)
	}
}

func TestServerIMAPCheckKeepsInjectedCheckerForProxyAwareChecks(t *testing.T) {
	const proxyURL = "http://127.0.0.1:7890"
	server := &Server{}
	var gotEmail, gotPassword string
	server.checkIMAPLogin = func(_ context.Context, email, password string) error {
		gotEmail = email
		gotPassword = password
		return nil
	}

	if err := server.checkSavedIMAPLoginWithProxy(context.Background(), "alias@icloud.com", "app-password", proxyURL); err != nil {
		t.Fatalf("proxy-aware IMAP check returned error: %v", err)
	}
	if gotEmail != "alias@icloud.com" || gotPassword != "app-password" {
		t.Fatalf("injected checker received %q/%q", gotEmail, gotPassword)
	}
}
