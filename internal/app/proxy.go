package app

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

func normalizeProxyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errCode("invalid_proxy_url", "代理地址格式不正确", false)
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", errCode("unsupported_proxy_scheme", "当前代理仅支持 HTTP/HTTPS 或 SOCKS5 代理", false)
	}
	if strings.TrimSpace(parsed.Host) == "" || strings.TrimSpace(parsed.Hostname()) == "" {
		return "", errCode("invalid_proxy_url", "代理地址缺少主机和端口", false)
	}
	if parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errCode("invalid_proxy_url", "代理地址不能包含路径、查询参数或片段", false)
	}
	if hasInvalidProxyPortSyntax(parsed.Host, parsed.Port()) {
		return "", errCode("invalid_proxy_url", "代理端口格式不正确", false)
	}
	if port := strings.TrimSpace(parsed.Port()); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return "", errCode("invalid_proxy_url", "代理端口必须在 1-65535 之间", false)
		}
	}
	parsed.Scheme = strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if parsed.Path == "/" {
		parsed.Path = ""
	}
	return parsed.String(), nil
}

func hasInvalidProxyPortSyntax(host, parsedPort string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return true
	}
	if strings.HasPrefix(host, "[") {
		closing := strings.LastIndex(host, "]")
		if closing < 0 {
			return true
		}
		suffix := host[closing+1:]
		if suffix == "" {
			return false
		}
		if !strings.HasPrefix(suffix, ":") {
			return true
		}
		return strings.TrimPrefix(suffix, ":") == "" || strings.TrimSpace(parsedPort) == ""
	}
	switch strings.Count(host, ":") {
	case 0:
		return false
	case 1:
		_, rawPort, _ := strings.Cut(host, ":")
		return strings.TrimSpace(rawPort) == "" || strings.TrimSpace(parsedPort) == ""
	default:
		return true
	}
}

func httpClientWithProxy(base *http.Client, rawProxyURL string) (*http.Client, error) {
	normalized, err := normalizeProxyURL(rawProxyURL)
	if err != nil {
		return nil, err
	}
	if normalized == "" {
		return httpClientWithoutProxy(base)
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return nil, errCode("invalid_proxy_url", "代理地址格式不正确", false)
	}
	if base == nil {
		base = &http.Client{}
	}
	transport, ok := base.Transport.(*http.Transport)
	if !ok && base.Transport != nil {
		return nil, errCode("proxy_transport_unsupported", "当前 HTTP 客户端不支持动态配置代理", false)
	}
	if transport == nil {
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok || defaultTransport == nil {
			return nil, errCode("proxy_transport_unsupported", "当前 HTTP 客户端不支持动态配置代理", false)
		}
		transport = defaultTransport
	}
	transport = transport.Clone()
	if isSOCKSProxy(parsed) {
		networkDialer, err := proxyNetworkDialer(parsed)
		if err != nil {
			return nil, err
		}
		transport.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
		transport.DialContext = networkDialer.DialContext
	} else {
		transport.Proxy = http.ProxyURL(parsed)
	}
	client := *base
	client.Transport = transport
	return &client, nil
}

func isSOCKSProxy(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "socks5", "socks5h":
		return true
	default:
		return false
	}
}

type contextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func proxyNetworkDialer(parsed *url.URL) (contextDialer, error) {
	if parsed == nil || !isSOCKSProxy(parsed) {
		return nil, errCode("invalid_proxy_url", "代理地址格式不正确", false)
	}
	return contextDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		return socks5DialContext(ctx, parsed, address)
	}), nil
}

func socks5DialContext(ctx context.Context, parsed *url.URL, address string) (net.Conn, error) {
	if parsed == nil {
		return nil, errCode("invalid_proxy_url", "代理地址格式不正确", false)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", proxyDialAddress(parsed))
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	stopWatch := closeConnWhenDone(ctx, conn)
	defer stopWatch()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	} else if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return nil, err
	}
	if err := socks5Connect(conn, parsed, address); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	success = true
	return conn, nil
}

func closeConnWhenDone(ctx context.Context, conn net.Conn) func() {
	if ctx == nil || conn == nil {
		return func() {}
	}
	done := make(chan struct{})
	var mu sync.Mutex
	finished := false
	go func() {
		select {
		case <-ctx.Done():
			mu.Lock()
			if !finished {
				_ = conn.Close()
			}
			mu.Unlock()
		case <-done:
		}
	}()
	return func() {
		mu.Lock()
		finished = true
		mu.Unlock()
		close(done)
	}
}

func socks5Connect(conn net.Conn, parsed *url.URL, address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errCode("invalid_proxy_url", "代理目标端口不正确", false)
	}
	username := ""
	password := ""
	if parsed.User != nil {
		username = parsed.User.Username()
		password, _ = parsed.User.Password()
	}
	methods := []byte{0x00}
	if username != "" || password != "" {
		methods = []byte{0x02, 0x00}
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 5 {
		return errCode("proxy_connect_failed", "SOCKS5 代理握手失败", true)
	}
	switch reply[1] {
	case 0x00:
	case 0x02:
		if err := socks5Authenticate(conn, username, password); err != nil {
			return err
		}
	default:
		return errCode("proxy_connect_failed", "SOCKS5 代理不支持当前认证方式", true)
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return errCode("invalid_proxy_url", "SOCKS5 目标主机名无效", false)
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != 5 {
		return errCode("proxy_connect_failed", "SOCKS5 代理握手失败", true)
	}
	if hdr[1] != 0 {
		return errCode("proxy_connect_failed", "通过 SOCKS5 代理连接目标失败", true)
	}
	switch hdr[3] {
	case 1:
		_, err := io.ReadFull(conn, make([]byte, 6))
		return err
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return err
		}
		_, err := io.ReadFull(conn, make([]byte, int(n[0])+2))
		return err
	case 4:
		_, err := io.ReadFull(conn, make([]byte, 18))
		return err
	default:
		return errCode("proxy_connect_failed", "SOCKS5 代理返回无法识别的地址类型", true)
	}
}

func socks5Authenticate(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return errCode("invalid_proxy_url", "SOCKS5 用户名或密码过长", false)
	}
	req := []byte{0x01, byte(len(username))}
	req = append(req, username...)
	req = append(req, byte(len(password)))
	req = append(req, password...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 1 || reply[1] != 0 {
		return errCode("proxy_connect_failed", "SOCKS5 代理认证失败", true)
	}
	return nil
}

type contextDialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (d contextDialerFunc) Dial(network, address string) (net.Conn, error) {
	return d(context.Background(), network, address)
}

func (d contextDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d(ctx, network, address)
}

func httpClientWithoutProxy(base *http.Client) (*http.Client, error) {
	if base == nil {
		base = &http.Client{}
	}
	transport, ok := base.Transport.(*http.Transport)
	if !ok && base.Transport != nil {
		return base, nil
	}
	if transport == nil {
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok || defaultTransport == nil {
			return nil, errCode("proxy_transport_unsupported", "当前 HTTP 客户端不支持动态配置代理", false)
		}
		transport = defaultTransport
	}
	transport = transport.Clone()
	transport.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	client := *base
	client.Transport = transport
	return &client, nil
}

func proxyDisplayURL(raw string) string {
	normalized, err := normalizeProxyURL(raw)
	if err != nil || normalized == "" {
		return ""
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return ""
	}
	parsed.User = nil
	return parsed.String()
}
