package app

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNormalizeProxyURL(t *testing.T) {
	t.Run("adds http scheme", func(t *testing.T) {
		got, err := normalizeProxyURL("127.0.0.1:7890")
		if err != nil {
			t.Fatal(err)
		}
		if got != "http://127.0.0.1:7890" {
			t.Fatalf("normalized proxy = %q", got)
		}
	})

	t.Run("keeps proxy credentials", func(t *testing.T) {
		got, err := normalizeProxyURL("http://user:pass@127.0.0.1:7890")
		if err != nil {
			t.Fatal(err)
		}
		if got != "http://user:pass@127.0.0.1:7890" {
			t.Fatalf("normalized proxy = %q", got)
		}
	})

	t.Run("keeps socks5 proxy", func(t *testing.T) {
		got, err := normalizeProxyURL("socks5://user:pass@127.0.0.1:1080")
		if err != nil {
			t.Fatal(err)
		}
		if got != "socks5://user:pass@127.0.0.1:1080" {
			t.Fatalf("normalized proxy = %q", got)
		}
	})

	t.Run("keeps socks5h proxy", func(t *testing.T) {
		got, err := normalizeProxyURL("socks5h://127.0.0.1:1080")
		if err != nil {
			t.Fatal(err)
		}
		if got != "socks5h://127.0.0.1:1080" {
			t.Fatalf("normalized proxy = %q", got)
		}
	})

	t.Run("rejects unsupported scheme", func(t *testing.T) {
		if _, err := normalizeProxyURL("socks4://127.0.0.1:1080"); !isCodedError(err, "unsupported_proxy_scheme") {
			t.Fatalf("error = %#v, want unsupported_proxy_scheme", err)
		}
	})

	t.Run("rejects missing host", func(t *testing.T) {
		if _, err := normalizeProxyURL("http://:7890"); !isCodedError(err, "invalid_proxy_url") {
			t.Fatalf("error = %#v, want invalid_proxy_url", err)
		}
	})

	t.Run("rejects invalid port", func(t *testing.T) {
		if _, err := normalizeProxyURL("http://127.0.0.1:70000"); !isCodedError(err, "invalid_proxy_url") {
			t.Fatalf("error = %#v, want invalid_proxy_url", err)
		}
	})

	t.Run("rejects path query or fragment", func(t *testing.T) {
		for _, raw := range []string{
			"http://127.0.0.1:7890/proxy",
			"http://127.0.0.1:7890?token=abc",
			"http://127.0.0.1:7890#proxy",
		} {
			if _, err := normalizeProxyURL(raw); !isCodedError(err, "invalid_proxy_url") {
				t.Fatalf("normalizeProxyURL(%q) error = %#v, want invalid_proxy_url", raw, err)
			}
		}
	})
}

func TestProxyDialAddressAddsDefaultPort(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "http", raw: "http://proxy.example", want: "proxy.example:80"},
		{name: "https", raw: "https://proxy.example", want: "proxy.example:443"},
		{name: "socks5", raw: "socks5://proxy.example", want: "proxy.example:1080"},
		{name: "ipv6", raw: "http://[::1]", want: "[::1]:80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := url.Parse(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := proxyDialAddress(parsed); got != tt.want {
				t.Fatalf("proxyDialAddress(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestDialICloudIMAPTLSViaProxyHonorsContextDuringConnectHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := dialICloudIMAPTLSViaProxy(ctx, "imap.example.test", 993, "http://"+listener.Addr().String())
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	}()

	var proxyConn net.Conn
	select {
	case proxyConn = <-accepted:
		defer proxyConn.Close()
	case <-time.After(time.Second):
		t.Fatal("proxy connection was not accepted")
	}
	cancel()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected proxy handshake to fail")
		}
		if ctx.Err() == nil {
			t.Fatalf("proxy handshake failed without context cancellation: %v", err)
		}
	case <-time.After(time.Second):
		_ = proxyConn.Close()
		select {
		case <-result:
		case <-time.After(time.Second):
		}
		t.Fatal("proxy handshake ignored context timeout")
	}
}

func TestHTTPClientWithProxyRoutesRequestThroughProxy(t *testing.T) {
	var requestURL string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURL = r.URL.String()
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "proxied")
	}))
	defer proxy.Close()

	client, err := httpClientWithProxy(&http.Client{}, proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get("http://target.invalid/private")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted || string(body) != "proxied" {
		t.Fatalf("proxy response = %d %q", resp.StatusCode, body)
	}
	if !strings.Contains(requestURL, "target.invalid/private") {
		t.Fatalf("proxy did not receive absolute target URL: %q", requestURL)
	}
}

func TestHTTPClientWithSOCKS5RoutesRequestThroughProxy(t *testing.T) {
	var connectedTo string
	ln := startSOCKS5TestProxy(t, func(conn net.Conn, target string) {
		connectedTo = target
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			_ = conn.Close()
			return
		}
		_ = req.Body.Close()
		resp := &http.Response{
			StatusCode:    http.StatusAccepted,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader("proxied")),
			ContentLength: 7,
			Close:         true,
		}
		_ = resp.Write(conn)
		_ = conn.Close()
	})

	client, err := httpClientWithProxy(&http.Client{Timeout: time.Second}, "socks5://"+ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get("http://target.invalid/private")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted || string(body) != "proxied" {
		t.Fatalf("socks5 proxy response = %d %q", resp.StatusCode, body)
	}
	if connectedTo != "target.invalid:80" {
		t.Fatalf("socks5 connect target = %q, want target.invalid:80", connectedTo)
	}
}

func TestSOCKS5DialContextHonorsContextDuringHandshake(t *testing.T) {
	addr, accepted := startHangingTCPProxy(t)
	parsed, err := url.Parse("socks5://" + addr)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := socks5DialContext(ctx, parsed, "imap.example.test:993")
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	}()

	proxyConn := waitAcceptedProxyConn(t, accepted)
	defer proxyConn.Close()
	cancel()
	waitCanceledProxyHandshake(t, ctx, result, proxyConn, "socks5 handshake")
}

func TestHTTPClientWithSOCKS5HonorsContextDuringHandshake(t *testing.T) {
	addr, accepted := startHangingTCPProxy(t)
	client, err := httpClientWithProxy(&http.Client{}, "socks5://"+addr)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://target.invalid/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		result <- err
	}()

	proxyConn := waitAcceptedProxyConn(t, accepted)
	defer proxyConn.Close()
	cancel()
	waitCanceledProxyHandshake(t, ctx, result, proxyConn, "socks5 HTTP handshake")
}

func TestDialICloudIMAPTLSViaSOCKSHonorsContextDuringHandshake(t *testing.T) {
	addr, accepted := startHangingTCPProxy(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := dialICloudIMAPTLSWithProxy(ctx, "imap.example.test", 993, "socks5://"+addr)
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	}()

	proxyConn := waitAcceptedProxyConn(t, accepted)
	defer proxyConn.Close()
	cancel()
	waitCanceledProxyHandshake(t, ctx, result, proxyConn, "socks5 IMAP handshake")
}

func TestDialICloudIMAPTLSViaSOCKSHonorsContextDuringTLSHandshake(t *testing.T) {
	accepted := make(chan net.Conn, 1)
	ln := startSOCKS5TestProxy(t, func(conn net.Conn, _ string) {
		accepted <- conn
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := dialICloudIMAPTLSWithProxy(ctx, "imap.example.test", 993, "socks5://"+ln.Addr().String())
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	}()

	proxyConn := waitAcceptedProxyConn(t, accepted)
	defer proxyConn.Close()
	cancel()
	waitCanceledProxyHandshake(t, ctx, result, proxyConn, "socks5 IMAP TLS handshake")
}

func startHangingTCPProxy(t *testing.T) (string, <-chan net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	return listener.Addr().String(), accepted
}

func waitAcceptedProxyConn(t *testing.T, accepted <-chan net.Conn) net.Conn {
	t.Helper()
	select {
	case conn := <-accepted:
		return conn
	case <-time.After(time.Second):
		t.Fatal("proxy connection was not accepted")
		return nil
	}
}

func waitCanceledProxyHandshake(t *testing.T, ctx context.Context, result <-chan error, proxyConn net.Conn, label string) {
	t.Helper()
	select {
	case err := <-result:
		if err == nil {
			t.Fatalf("expected %s to fail", label)
		}
		if ctx.Err() == nil {
			t.Fatalf("%s failed without context cancellation: %v", label, err)
		}
	case <-time.After(time.Second):
		_ = proxyConn.Close()
		select {
		case <-result:
		case <-time.After(time.Second):
		}
		t.Fatalf("%s ignored context cancellation", label)
	}
}

func startSOCKS5TestProxy(t *testing.T, after func(conn net.Conn, target string)) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				target, err := socks5AcceptConnect(c)
				if err != nil {
					_ = c.Close()
					return
				}
				after(c, target)
			}(conn)
		}
	}()
	return ln
}

func socks5AcceptConnect(conn net.Conn) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[0] != 5 {
		return "", errCode("invalid_proxy_url", "SOCKS5 版本不正确", false)
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return "", err
	}
	if req[0] != 5 || req[1] != 1 {
		return "", errCode("invalid_proxy_url", "SOCKS5 请求不正确", false)
	}
	var host string
	switch req[3] {
	case 1:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return "", err
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", err
		}
		host = string(name)
	case 4:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()
	default:
		return "", errCode("invalid_proxy_url", "SOCKS5 地址类型不支持", false)
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return "", err
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func TestHTTPClientWithProxyRejectsUnsupportedDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() {
		http.DefaultTransport = original
	})
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, nil
	})

	_, err := httpClientWithProxy(&http.Client{}, "http://127.0.0.1:7890")
	if !isCodedError(err, "proxy_transport_unsupported") {
		t.Fatalf("error = %#v, want proxy_transport_unsupported", err)
	}
}

func TestMergeICloudSessionPreservesProxyURL(t *testing.T) {
	existing := ICloudSession{ProxyURL: "http://old-proxy:8080"}
	incoming := ICloudSession{}
	if got := mergeICloudSession(existing, incoming).ProxyURL; got != existing.ProxyURL {
		t.Fatalf("empty incoming proxy replaced existing proxy: %q", got)
	}

	incoming.ProxyURL = "http://new-proxy:8080"
	if got := mergeICloudSession(existing, incoming).ProxyURL; got != incoming.ProxyURL {
		t.Fatalf("incoming proxy was not preferred: %q", got)
	}
}

func TestICloudWebSessionPromotesNestedProxyWhenRootCookiesExist(t *testing.T) {
	input := ICloudSession{
		Cookies: []SessionCookie{{
			Name:  "session",
			Value: "cookie-value",
		}},
		LoginStates: []LoginState{{
			Kind:     LoginStateICloudWeb,
			ProxyURL: "http://127.0.0.1:7890",
			Host:     "www.icloud.com.cn",
		}},
	}
	session, ok := iCloudWebSessionForClient(input)
	if !ok {
		t.Fatal("expected iCloud Web session")
	}
	if session.ProxyURL != "http://127.0.0.1:7890" {
		t.Fatalf("proxy = %q, want nested iCloud Web proxy", session.ProxyURL)
	}
	if session.Host != "www.icloud.com.cn" {
		t.Fatalf("host = %q, want nested iCloud Web host", session.Host)
	}
	if !iCloudWebLoginSaved(input) {
		t.Fatal("root cookies with an explicit iCloud Web state were not reported as saved")
	}
	if _, ok := iCloudWebLoginState(input); !ok {
		t.Fatal("root cookies with an explicit iCloud Web state did not return a login state")
	}
}

func TestICloudWebSessionPrefersNestedCookiesWhenRootCookiesExist(t *testing.T) {
	session, ok := iCloudWebSessionForClient(ICloudSession{
		Cookies: []SessionCookie{{
			Name:  "session",
			Value: "stale-root-cookie",
		}},
		LoginStates: []LoginState{{
			Kind: LoginStateICloudWeb,
			Cookies: []SessionCookie{{
				Name:  "session",
				Value: "fresh-nested-cookie",
			}},
		}},
	})
	if !ok {
		t.Fatal("expected iCloud Web session")
	}
	if len(session.Cookies) != 1 || session.Cookies[0].Value != "fresh-nested-cookie" {
		t.Fatalf("cookies = %+v, want fresh nested cookie", session.Cookies)
	}
}

func TestAppleAccountOnlyCookiesAreNotTreatedAsICloudWebLogin(t *testing.T) {
	session := ICloudSession{
		Cookies: []SessionCookie{{
			Name:  "session",
			Value: "apple-account-cookie",
		}},
		LoginStates: []LoginState{{
			Kind: LoginStateAppleAccount,
			Cookies: []SessionCookie{{
				Name:  "session",
				Value: "apple-account-cookie",
			}},
		}},
	}

	if iCloudWebLoginSaved(session) {
		t.Fatal("Apple Account-only cookies were reported as an iCloud Web login")
	}
	if _, ok := iCloudWebLoginState(session); ok {
		t.Fatal("Apple Account-only cookies returned an iCloud Web login state")
	}
	if _, ok := iCloudWebSessionForClient(session); ok {
		t.Fatal("Apple Account-only cookies returned an iCloud Web client session")
	}
}

func TestLegacyRootCookiesRemainAnICloudWebLoginWithoutLoginStates(t *testing.T) {
	session := ICloudSession{
		Cookies: []SessionCookie{{
			Name:  "session",
			Value: "legacy-web-cookie",
		}},
	}

	if !iCloudWebLoginSaved(session) {
		t.Fatal("legacy root cookies were not reported as an iCloud Web login")
	}
	if _, ok := iCloudWebLoginState(session); !ok {
		t.Fatal("legacy root cookies did not return an iCloud Web login state")
	}
	if _, ok := iCloudWebSessionForClient(session); !ok {
		t.Fatal("legacy root cookies did not return an iCloud Web client session")
	}
}

func TestLegacyRootCookiesRemainAnICloudWebLoginWhenIMAPStateIsMerged(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-legacy-web-imap"
	legacy := ICloudSession{
		OwnerID: ownerID,
		AppleID: "legacy-web-imap@example.com",
		Cookies: []SessionCookie{{
			Name:  "session",
			Value: "legacy-web-cookie",
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, legacy); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID: ownerID,
		AppleID: "legacy-web-imap@example.com",
		LoginStates: []LoginState{{
			Kind:            LoginStateICloudIMAP,
			IMAPEmail:       "imap@example.com",
			IMAPUsername:    "imap@example.com",
			IMAPHost:        "imap.mail.me.com",
			IMAPPort:        993,
			IMAPAppPassword: "app-password",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %+v, want one merged session", sessions)
	}
	if !iCloudWebLoginSaved(sessions[0]) {
		t.Fatalf("legacy root cookies lost iCloud Web capability after IMAP merge: %+v", sessions[0])
	}
	webState, ok := iCloudWebLoginState(sessions[0])
	if !ok || len(webState.Cookies) != 1 || webState.Cookies[0].Value != "legacy-web-cookie" {
		t.Fatalf("legacy iCloud Web state = %+v, want root cookie promoted after IMAP merge", webState)
	}
}

func TestUnmarshalDoesNotInferICloudWebStateFromAppleAccountCookies(t *testing.T) {
	var session ICloudSession
	if err := json.Unmarshal([]byte(`{
		"cookies": [{"name": "session", "value": "apple-account-cookie"}],
		"login_states": [{
			"kind": "apple_account",
			"cookies": [{"name": "session", "value": "apple-account-cookie"}]
		}]
	}`), &session); err != nil {
		t.Fatal(err)
	}

	if hasLoginStateKind(session.LoginStates, LoginStateICloudWeb) {
		t.Fatalf("Apple Account-only session gained an inferred iCloud Web state: %+v", session.LoginStates)
	}
}

func TestUpdateAccountProxyUpdatesSessionAndLoginStates(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwner("owner-proxy", "Proxy account", "proxy@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner("owner-proxy", ICloudSession{
		AccountID: account.ID,
		AppleID:   account.AppleID,
		LoginStates: []LoginState{
			{Kind: LoginStateICloudWeb, ProxyURL: "http://old-proxy:8080"},
			{Kind: LoginStateAppleAccount, ProxyURL: "http://old-proxy:8080", Scnt: "scnt"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	updated, err := store.UpdateAccountProxyForOwner("owner-proxy", account.ID, "127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}
	if updated.ProxyURL != "http://127.0.0.1:7890" {
		t.Fatalf("account proxy = %q", updated.ProxyURL)
	}
	session, ok := store.ICloudSessionForOwnerAccount("owner-proxy", account.ID)
	if !ok {
		t.Fatal("updated session not found")
	}
	if session.ProxyURL != updated.ProxyURL {
		t.Fatalf("session proxy = %q", session.ProxyURL)
	}
	for _, state := range session.LoginStates {
		if state.ProxyURL != updated.ProxyURL {
			t.Fatalf("login state %s proxy = %q", state.Kind, state.ProxyURL)
		}
	}

	updated, err = store.UpdateAccountProxyForOwner("owner-proxy", account.ID, "socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if updated.ProxyURL != "socks5://127.0.0.1:1080" {
		t.Fatalf("socks5 account proxy = %q", updated.ProxyURL)
	}
}

func TestUpdateAccountProxyRollsBackWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwnerWithProxy("owner-proxy-persist", "Proxy account", "persist@example.com", "", "http://old-proxy:8080")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner("owner-proxy-persist", ICloudSession{
		AccountID: account.ID,
		AppleID:   account.AppleID,
		ProxyURL:  "http://old-proxy:8080",
		LoginStates: []LoginState{{
			Kind:     LoginStateICloudWeb,
			ProxyURL: "http://old-proxy:8080",
			Cookies:  []SessionCookie{{Name: "session", Value: "cookie"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	_, err = store.UpdateAccountProxyForOwner("owner-proxy-persist", account.ID, "http://new-proxy:8080")
	if !isCodedError(err, "account_proxy_persist_failed") {
		t.Fatalf("UpdateAccountProxy error = %#v, want account_proxy_persist_failed", err)
	}
	currentAccount, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account disappeared after proxy persistence failure")
	}
	if currentAccount.ProxyURL != "http://old-proxy:8080" {
		t.Fatalf("account proxy after persistence failure = %q, want old proxy", currentAccount.ProxyURL)
	}
	currentSession, ok := store.ICloudSessionForOwnerAccount("owner-proxy-persist", account.ID)
	if !ok {
		t.Fatal("session disappeared after proxy persistence failure")
	}
	if currentSession.ProxyURL != "http://old-proxy:8080" || len(currentSession.LoginStates) != 1 || currentSession.LoginStates[0].ProxyURL != "http://old-proxy:8080" {
		t.Fatalf("session after persistence failure = %+v, want old proxy", currentSession)
	}
}

func TestAddAccountWithProxyRollsBackWhenPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	_, err := store.AddAccountForOwnerWithProxy("owner-proxy-create-persist", "Proxy account", "create-persist@example.com", "", "http://proxy:8080")
	if !isCodedError(err, "account_create_persist_failed") {
		t.Fatalf("AddAccountForOwnerWithProxy error = %#v, want account_create_persist_failed", err)
	}
	for _, account := range store.Snapshot().Accounts {
		if account.OwnerID == "owner-proxy-create-persist" && strings.EqualFold(account.AppleID, "create-persist@example.com") {
			t.Fatal("account remained in memory after account persistence failure")
		}
	}
}

func TestSaveICloudSessionDoesNotOverwriteConfiguredAccountProxyWithStaleSessionProxy(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwnerWithProxy("owner-stale-proxy", "Proxy account", "stale@example.com", "", "127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner("owner-stale-proxy", ICloudSession{
		AccountID: account.ID,
		AppleID:   account.AppleID,
		ProxyURL:  "http://127.0.0.1:7890",
		LoginStates: []LoginState{{
			Kind:     LoginStateAppleAccount,
			Scnt:     "scnt",
			ProxyURL: "http://127.0.0.1:7890",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateAccountProxyForOwner("owner-stale-proxy", account.ID, "127.0.0.1:7891"); err != nil {
		t.Fatal(err)
	}

	stale := ICloudSession{
		AccountID: account.ID,
		AppleID:   account.AppleID,
		ProxyURL:  "http://127.0.0.1:7890",
		LoginStates: []LoginState{{
			Kind:     LoginStateAppleAccount,
			Scnt:     "refreshed-scnt",
			ProxyURL: "http://127.0.0.1:7890",
		}},
	}
	if err := store.SaveICloudSessionForOwner("owner-stale-proxy", stale); err != nil {
		t.Fatal(err)
	}

	updated, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account not found")
	}
	if updated.ProxyURL != "http://127.0.0.1:7891" {
		t.Fatalf("account proxy was overwritten by stale session proxy: %q", updated.ProxyURL)
	}
	session, ok := store.ICloudSessionForOwnerAccount("owner-stale-proxy", account.ID)
	if !ok {
		t.Fatal("session not found")
	}
	if session.ProxyURL != "http://127.0.0.1:7891" {
		t.Fatalf("session proxy = %q, want configured account proxy", session.ProxyURL)
	}
	state, ok := appleAccountLoginState(session)
	if !ok {
		t.Fatal("apple account state not found")
	}
	if state.ProxyURL != "http://127.0.0.1:7891" {
		t.Fatalf("login state proxy = %q, want configured account proxy", state.ProxyURL)
	}
}

func TestSaveICloudSessionDoesNotRestoreClearedAccountProxyFromStaleSessionProxy(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwnerWithProxy("owner-cleared-proxy", "Proxy account", "cleared@example.com", "", "127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner("owner-cleared-proxy", ICloudSession{
		AccountID: account.ID,
		AppleID:   account.AppleID,
		ProxyURL:  "http://127.0.0.1:7890",
		LoginStates: []LoginState{{
			Kind:     LoginStateAppleAccount,
			Scnt:     "scnt",
			ProxyURL: "http://127.0.0.1:7890",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateAccountProxyForOwner("owner-cleared-proxy", account.ID, ""); err != nil {
		t.Fatal(err)
	}

	stale := ICloudSession{
		AccountID: account.ID,
		AppleID:   account.AppleID,
		ProxyURL:  "http://127.0.0.1:7890",
		LoginStates: []LoginState{{
			Kind:     LoginStateAppleAccount,
			Scnt:     "refreshed-scnt",
			ProxyURL: "http://127.0.0.1:7890",
		}},
	}
	if err := store.SaveICloudSessionForOwner("owner-cleared-proxy", stale); err != nil {
		t.Fatal(err)
	}

	updated, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account not found")
	}
	if updated.ProxyURL != "" {
		t.Fatalf("cleared account proxy was restored by stale session proxy: %q", updated.ProxyURL)
	}
	session, ok := store.ICloudSessionForOwnerAccount("owner-cleared-proxy", account.ID)
	if !ok {
		t.Fatal("session not found")
	}
	if session.ProxyURL != "" {
		t.Fatalf("session proxy = %q, want cleared account proxy", session.ProxyURL)
	}
	state, ok := appleAccountLoginState(session)
	if !ok {
		t.Fatal("apple account state not found")
	}
	if state.ProxyURL != "" {
		t.Fatalf("login state proxy = %q, want cleared account proxy", state.ProxyURL)
	}
}

func TestReadICloudSessionUsesClearedAccountProxyAsAuthoritative(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwner("owner-read-clear", "Proxy account", "read-clear@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.state.ICloudSessions = append(store.state.ICloudSessions, ICloudSession{
		OwnerID:   "owner-read-clear",
		AccountID: account.ID,
		AppleID:   account.AppleID,
		ProxyURL:  "http://127.0.0.1:7890",
		LoginStates: []LoginState{{
			Kind:     LoginStateAppleAccount,
			ProxyURL: "http://127.0.0.1:7890",
		}},
	})
	store.mu.Unlock()

	got, ok := store.ICloudSessionForOwnerAccount("owner-read-clear", account.ID)
	if !ok {
		t.Fatal("session not found")
	}
	if got.ProxyURL != "" {
		t.Fatalf("read session proxy = %q, want cleared account proxy to win", got.ProxyURL)
	}
	for _, state := range got.LoginStates {
		if state.ProxyURL != "" {
			t.Fatalf("read login state proxy = %q, want cleared account proxy to win", state.ProxyURL)
		}
	}
}

func TestSaveICloudSessionWithProxyUpdateAdoptsExplicitLoginProxy(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwnerWithProxy("owner-login-proxy", "Proxy account", "login-proxy@example.com", "", "127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwnerUpdatingProxy("owner-login-proxy", ICloudSession{
		AccountID: account.ID,
		AppleID:   account.AppleID,
		ProxyURL:  "http://127.0.0.1:7892",
		LoginStates: []LoginState{{
			Kind:     LoginStateAppleAccount,
			Scnt:     "login-scnt",
			ProxyURL: "http://127.0.0.1:7892",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	updated, ok := store.FindAccountByID(account.ID)
	if !ok {
		t.Fatal("account not found")
	}
	if updated.ProxyURL != "http://127.0.0.1:7892" {
		t.Fatalf("account proxy = %q, want explicit login proxy", updated.ProxyURL)
	}
	session, ok := store.ICloudSessionForOwnerAccount("owner-login-proxy", account.ID)
	if !ok {
		t.Fatal("session not found")
	}
	if session.ProxyURL != "http://127.0.0.1:7892" {
		t.Fatalf("session proxy = %q, want explicit login proxy", session.ProxyURL)
	}
}

func TestSaveICloudSessionInheritsConfiguredAccountProxyWithoutOwner(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwnerWithProxy("", "Apple", "global@example.com", "", "127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}
	err = store.SaveICloudSession(ICloudSession{
		AccountID: account.ID,
		AppleID:   account.AppleID,
		LoginStates: []LoginState{{
			Kind: LoginStateAppleAccount,
			Scnt: "scnt",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	session, ok := store.ICloudSessionForOwnerAccount("", account.ID)
	if !ok {
		t.Fatal("saved session not found")
	}
	if session.ProxyURL != "http://127.0.0.1:7890" {
		t.Fatalf("session proxy = %q", session.ProxyURL)
	}
}

func TestReadICloudSessionResolvesAccountProxy(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwnerWithProxy("owner-read", "Apple", "read@example.com", "", "127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}
	err = store.SaveICloudSessionForOwner("owner-read", ICloudSession{
		AccountID: account.ID,
		AppleID:   account.AppleID,
	})
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.state.ICloudSessions[0].ProxyURL = ""
	store.mu.Unlock()

	session, ok := store.ICloudSessionForOwnerAccount("owner-read", account.ID)
	if !ok {
		t.Fatal("saved session not found")
	}
	if session.ProxyURL != "http://127.0.0.1:7890" {
		t.Fatalf("read session proxy = %q", session.ProxyURL)
	}
	snapshot := store.SnapshotForOwner("owner-read")
	if len(snapshot.ICloudSessions) == 0 || snapshot.ICloudSessions[0].ProxyURL != "http://127.0.0.1:7890" {
		t.Fatalf("snapshot sessions = %+v", snapshot.ICloudSessions)
	}
}

func TestAdminCanUpdateAnyAccountProxy(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin-proxy", "admin123")
	_, user := registerTestUser(t, handler, "user-proxy", "user123")
	account, err := store.AddAccountForOwner(user.ID, "User Apple", "user@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPatch, "/api/accounts/"+account.ID+"?owner_id=all", strings.NewReader(`{"proxy_url":"127.0.0.1:7890"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin proxy update status = %d body=%s", rr.Code, rr.Body.String())
	}
	updated, ok := store.FindAccountByID(account.ID)
	if !ok || updated.ProxyURL != "http://127.0.0.1:7890" {
		t.Fatalf("updated account = %+v ok=%t", updated, ok)
	}
}

func TestUpdateAccountProxyWaitsForMailboxAccountOperation(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "proxy-gate-user", "user123")
	account, err := store.AddAccountForOwner(user.ID, "Gated Apple", "gated@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	releaseAccountOperation, err := handler.acquireMailboxAccountOperationSlot(
		context.Background(),
		mailboxAccountOperationKey(account.OwnerID, account.ID),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPatch, "/api/accounts/"+account.ID, strings.NewReader(`{"proxy_url":"127.0.0.1:7890"}`))
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
	case <-done:
		releaseAccountOperation()
		t.Fatal("account proxy update completed while the mailbox account operation was held")
	case <-time.After(100 * time.Millisecond):
	}
	updated, ok := store.FindAccountByID(account.ID)
	if !ok {
		releaseAccountOperation()
		t.Fatal("account disappeared while proxy update was waiting")
	}
	if updated.ProxyURL != "" {
		releaseAccountOperation()
		t.Fatalf("account proxy changed before operation release: %q", updated.ProxyURL)
	}
	releaseAccountOperation()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("account proxy update did not finish after the mailbox account operation was released")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("account proxy update status = %d body=%s, want 200", rr.Code, rr.Body.String())
	}
	updated, ok = store.FindAccountByID(account.ID)
	if !ok || updated.ProxyURL != "http://127.0.0.1:7890" {
		t.Fatalf("updated account = %+v ok=%t, want normalized proxy", updated, ok)
	}
}

func TestAdminLoginProxyUsesUniqueUserAccountProxy(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "admin-login-proxy", "admin123")
	_, user := registerTestUser(t, handler, "user-login-proxy", "user123")
	if _, err := store.AddAccountForOwnerWithProxy(user.ID, "User Apple", "user-login@example.com", "", "127.0.0.1:7890"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/start?owner_id=all", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	if got := handler.loginProxyForRequest(req, "USER-LOGIN@EXAMPLE.COM", ""); got != "http://127.0.0.1:7890" {
		t.Fatalf("admin login proxy = %q, want configured user account proxy", got)
	}
}

func TestAdminLoginTargetResolvesExistingUserAccount(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "admin-login-target", "admin123")
	_, user := registerTestUser(t, handler, "user-login-target", "user123")
	account, err := store.AddAccountForOwner(user.ID, "User Apple", "user-login-target@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/start?owner_id=all", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	target, err := handler.resolveLoginTarget(req, account.AppleID, "")
	if err != nil {
		t.Fatal(err)
	}
	if target.OwnerID != user.ID || target.AccountID != account.ID {
		t.Fatalf("login target = %+v, want owner=%q account=%q", target, user.ID, account.ID)
	}
}

func TestLoginTargetRejectsAmbiguousAppleIDWithoutAccountID(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "admin-login-target-ambiguous", "admin123")
	_, userA := registerTestUser(t, handler, "user-login-target-a", "user123")
	_, userB := registerTestUser(t, handler, "user-login-target-b", "user456")
	if _, err := store.AddAccountForOwner(userA.ID, "Duplicate Apple", "ambiguous-login@example.com", ""); err != nil {
		t.Fatal(err)
	}
	appendAccountWithAppleID(store, userB.ID, "ambiguous-login@example.com", "")

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/start?owner_id=all", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	_, err := handler.resolveLoginTarget(req, "ambiguous-login@example.com", "")
	if !isCodedError(err, "account_ambiguous") {
		t.Fatalf("ambiguous login target error = %#v, want account_ambiguous", err)
	}
}

func TestLoginTargetRejectsAppleIDMismatchForExplicitAccount(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "login-target-mismatch", "user123")
	account, err := store.AddAccountForOwner(user.ID, "Apple", "expected@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/start", nil)
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	_, err = handler.resolveLoginTarget(req, "other@example.com", account.ID)
	if !isCodedError(err, "apple_id_account_mismatch") {
		t.Fatalf("explicit account mismatch error = %#v, want apple_id_account_mismatch", err)
	}
}

func TestSavePendingICloudSessionBindsExplicitLoginTarget(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	_, user := registerTestUser(t, handler, "pending-login-target", "user123")
	account, err := store.AddAccountForOwner(user.ID, "Apple", "pending-target@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	err = handler.savePendingICloudSession(appleAuthPending{
		OwnerID:       user.ID,
		TargetOwnerID: user.ID,
		AccountID:     account.ID,
		ProxyExplicit: false,
	}, ICloudSession{AppleID: account.AppleID})
	if err != nil {
		t.Fatal(err)
	}
	session, ok := store.ICloudSessionForOwnerAccount(user.ID, account.ID)
	if !ok {
		t.Fatal("target session was not saved under explicit account")
	}
	if session.OwnerID != user.ID || session.AccountID != account.ID {
		t.Fatalf("saved session = %+v, want owner=%q account=%q", session, user.ID, account.ID)
	}
}

func TestLoginProxySelectionDistinguishesStoredProxyFromExplicitRequest(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, user := registerTestUser(t, handler, "proxy-selection", "user123")
	if _, err := store.AddAccountForOwnerWithProxy(user.ID, "Apple", "proxy-selection@example.com", "", "127.0.0.1:7890"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/start", nil)
	req.AddCookie(cookie)
	addClosureTestCSRF(req, cookie)
	got, explicit := handler.loginProxySelectionForRequest(req, "PROXY-SELECTION@EXAMPLE.COM", "")
	if got != "http://127.0.0.1:7890" || explicit {
		t.Fatalf("stored proxy selection = %q, explicit=%t, want configured proxy and explicit=false", got, explicit)
	}

	got, explicit = handler.loginProxySelectionForRequest(req, "PROXY-SELECTION@EXAMPLE.COM", "127.0.0.1:7891")
	if got != "127.0.0.1:7891" || !explicit {
		t.Fatalf("explicit proxy selection = %q, explicit=%t, want request proxy and explicit=true", got, explicit)
	}
}

func TestAdminLoginProxySkipsAmbiguousUserAccountProxies(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger()).(*Server)
	adminCookie, _ := registerTestUser(t, handler, "admin-ambiguous-proxy", "admin123")
	_, userA := registerTestUser(t, handler, "user-ambiguous-a", "user123")
	_, userB := registerTestUser(t, handler, "user-ambiguous-b", "user456")
	if _, err := store.AddAccountForOwnerWithProxy(userA.ID, "Duplicate Apple", "duplicate@example.com", "", "127.0.0.1:7890"); err != nil {
		t.Fatal(err)
	}
	appendAccountWithAppleID(store, userB.ID, "duplicate@example.com", "http://127.0.0.1:7891")

	req := httptest.NewRequest(http.MethodPost, "/api/icloud/protocol-login/start?owner_id=all", nil)
	req.AddCookie(adminCookie)
	addClosureTestCSRF(req, adminCookie)
	if got := handler.loginProxyForRequest(req, "duplicate@example.com", ""); got != "" {
		t.Fatalf("ambiguous admin login proxy = %q, want empty", got)
	}
}

func TestAccountProxyForOwnerAppleIDSkipsAmbiguousAccounts(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.AddAccountForOwnerWithProxy("owner-ambiguous", "Duplicate Apple", "duplicate@example.com", "", "127.0.0.1:7890"); err != nil {
		t.Fatal(err)
	}
	appendAccountWithAppleID(store, "owner-ambiguous", "duplicate@example.com", "http://127.0.0.1:7891")

	if got, ok := store.AccountProxyForOwnerAppleID("owner-ambiguous", "DUPLICATE@EXAMPLE.COM"); ok || got != "" {
		t.Fatalf("ambiguous owner proxy = %q, ok=%t, want empty/false", got, ok)
	}
}

func TestAccountProxyForOwnerAppleIDDoesNotPreferBlankDuplicate(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.AddAccountForOwner("owner-ambiguous-blank", "Duplicate Apple", "duplicate@example.com", ""); err != nil {
		t.Fatal(err)
	}
	appendAccountWithAppleID(store, "owner-ambiguous-blank", "duplicate@example.com", "http://127.0.0.1:7890")

	if got, ok := store.AccountProxyForOwnerAppleID("owner-ambiguous-blank", "duplicate@example.com"); ok || got != "" {
		t.Fatalf("blank/configured owner proxy = %q, ok=%t, want empty/false", got, ok)
	}
}

func TestSaveICloudSessionInheritsConfiguredAccountProxy(t *testing.T) {
	store := newTestStore(t)
	account, err := store.AddAccountForOwnerWithProxy("owner-inherit", "Apple", "owner@example.com", "", "127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}
	err = store.SaveICloudSessionForOwner("owner-inherit", ICloudSession{
		AppleID: account.AppleID,
		LoginStates: []LoginState{{
			Kind: LoginStateAppleAccount,
			Scnt: "scnt",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	session, ok := store.ICloudSessionForOwnerAccount("owner-inherit", account.ID)
	if !ok {
		t.Fatal("saved session not found")
	}
	if session.ProxyURL != "http://127.0.0.1:7890" {
		t.Fatalf("session proxy = %q", session.ProxyURL)
	}
	state, ok := appleAccountLoginState(session)
	if !ok || state.ProxyURL != session.ProxyURL {
		t.Fatalf("login state = %+v ok=%t", state, ok)
	}
}

func appendAccountWithAppleID(store *FileStore, ownerID, appleID, proxyURL string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.state.Accounts = append(store.state.Accounts, Account{
		ID:       store.nextIDLocked("acc"),
		OwnerID:  strings.TrimSpace(ownerID),
		Label:    "Duplicate Apple",
		AppleID:  strings.TrimSpace(appleID),
		ProxyURL: strings.TrimSpace(proxyURL),
		Status:   StatusActive,
	})
}
