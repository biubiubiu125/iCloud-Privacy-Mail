package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ICloudClient struct {
	client *http.Client
}

type ICloudRemoteMailbox struct {
	AnonymousID    string
	Email          string
	Label          string
	Note           string
	ForwardToEmail string
	IsActive       bool
	Origin         string
}

func appleAccountRemoteAnonymousID(id, anonymousID string) string {
	return strings.TrimSpace(firstNonEmpty(id, anonymousID))
}

func iCloudWebRemoteAnonymousID(id, anonymousID string) string {
	return strings.TrimSpace(firstNonEmpty(anonymousID, id))
}

type privacyMailboxDeleteOutcome struct {
	Deactivated bool
}

type ICloudSyncedMessage struct {
	RemoteID   string
	UID        string
	Subject    string
	From       string
	Body       string
	ReceivedAt time.Time
}

type ICloudMailCleanupResult struct {
	MovedToTrash int `json:"moved_to_trash"`
	Destroyed    int `json:"destroyed"`
	Skipped      int `json:"skipped"`
}

func iCloudWebSessionForClient(session ICloudSession) (ICloudSession, bool) {
	hasWebState := false
	for _, state := range session.LoginStates {
		if state.Kind != LoginStateICloudWeb {
			continue
		}
		hasWebState = true
		if len(state.Cookies) == 0 {
			continue
		}
		session.Cookies = append([]SessionCookie(nil), state.Cookies...)
		session.ProxyURL = firstNonEmpty(session.ProxyURL, state.ProxyURL)
		session.Host = firstNonEmpty(session.Host, state.Host)
		session.SavedAt = firstNonZeroTime(session.SavedAt, state.SavedAt)
		return session, true
	}
	if len(session.Cookies) > 0 && (len(session.LoginStates) == 0 || hasWebState) {
		for _, state := range session.LoginStates {
			if state.Kind != LoginStateICloudWeb {
				continue
			}
			session.ProxyURL = firstNonEmpty(session.ProxyURL, state.ProxyURL)
			session.Host = firstNonEmpty(session.Host, state.Host)
			session.SavedAt = firstNonZeroTime(session.SavedAt, state.SavedAt)
			break
		}
		return session, true
	}
	return session, false
}

func NewICloudClient() *ICloudClient {
	return &ICloudClient{client: &http.Client{Timeout: 30 * time.Second}}
}

func newICloudKeepAliveClient() *ICloudClient {
	return &ICloudClient{client: &http.Client{}}
}

const mailboxSyncCursorOverlap = 2 * time.Minute
const appleAccountManageRefreshSkew = 0 * time.Second
const appleAccountKeepAliveDefaultInterval = 4 * time.Minute
const appleAccountKeepAliveTimeout = 60 * time.Second
const appleAccountKeepAliveMaxAuthFails = 3
const appleAccountManageOperationTimeout = 2 * appleAccountKeepAliveTimeout
const icloudWebCheckTimeout = 30 * time.Second
const icloudIMAPCheckTimeout = 25 * time.Second

var appleAccountManageBaseURL = "https://appleid.apple.com"
var appleAccountOperationMu sync.Mutex
var appleAccountOperationGates = make(map[string]chan struct{})

const (
	appleAccountManageOrigin     = "https://account.apple.com"
	appleAccountManageUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	appleAccountManageRequestCtx = "ca"
	appleAccountManageLanguage   = "zh"
	appleAccountManageTimeZone   = "Asia/Shanghai"
	appleAccountManageGMTOffset  = "GMT+08:00"
	appleAccountManagePlatform   = `"macOS"`
	appleAccountManageTZOffset   = 8 * 60 * 60
)

const appleAccountHTTPStatusSessionTimeout = 419

func appleAccountManageHostForICloudHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.Contains(host, "appleid.apple.com.cn") {
		return "appleid.apple.com.cn"
	}
	return "appleid.apple.com"
}

func appleAccountManageOriginForHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.Contains(host, "account.apple.com.cn") || strings.Contains(host, "appleid.apple.com.cn") {
		return "https://account.apple.com.cn"
	}
	return appleAccountManageOrigin
}

func appleAccountManageBaseForState(state LoginState) string {
	baseURL := strings.TrimSpace(appleAccountManageBaseURL)
	if baseURL == "" {
		baseURL = "https://appleid.apple.com"
	}
	if strings.TrimRight(baseURL, "/") != "https://appleid.apple.com" {
		return baseURL
	}
	host := strings.TrimSpace(state.Host)
	if host == "" {
		return baseURL
	}
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Trim(host, "/")
	if host == "" {
		return baseURL
	}
	return "https://" + host
}

func appleAccountPortalBaseForState(state LoginState) string {
	baseURL := strings.TrimSpace(appleAccountManageBaseURL)
	if baseURL != "" && strings.TrimRight(baseURL, "/") != "https://appleid.apple.com" {
		return baseURL
	}
	return strings.TrimRight(firstNonEmpty(state.Origin, appleAccountManageOriginForHost(state.Host), appleAccountManageOrigin), "/")
}

func appleAccountLoginState(session ICloudSession) (LoginState, bool) {
	for _, state := range session.LoginStates {
		if state.Kind != LoginStateAppleAccount {
			continue
		}
		if strings.TrimSpace(state.Scnt) == "" {
			continue
		}
		state.ProxyURL = firstNonEmpty(state.ProxyURL, session.ProxyURL)
		return state, true
	}
	return LoginState{}, false
}

func appleAccountManageReady(session ICloudSession) bool {
	state, ok := appleAccountLoginState(session)
	return ok && strings.TrimSpace(state.APIKey) != ""
}

func appleAccountManageNeedsCreateRefresh(loginState LoginState, now time.Time) bool {
	if loginState.KeepAliveStopped || loginState.KeepAliveFailCount > 0 {
		return true
	}
	return !appleAccountManageRecentStateUsable(loginState, now)
}

func appleAccountManageNeedsListRefresh(loginState LoginState, now time.Time) bool {
	if strings.TrimSpace(loginState.APIKey) == "" {
		return true
	}
	if loginState.ManageExpiresAt.IsZero() {
		return false
	}
	return !now.Before(loginState.ManageExpiresAt.Add(-appleAccountManageRefreshSkew))
}

func appleAccountManageRecentStateUsable(loginState LoginState, now time.Time) bool {
	if strings.TrimSpace(loginState.Scnt) == "" {
		return false
	}
	if strings.TrimSpace(loginState.APIKey) == "" {
		return false
	}
	if loginState.LastCheckedAt.IsZero() {
		return false
	}
	if loginState.ManageExpiresAt.IsZero() {
		return false
	}
	return now.Before(loginState.ManageExpiresAt.Add(-appleAccountManageRefreshSkew))
}

func appleAccountManageRecentlyOK(loginState LoginState, now time.Time) bool {
	return loginState.LastCheckOK && appleAccountManageRecentStateUsable(loginState, now)
}

func markAppleAccountManageOK(loginState *LoginState) {
	if loginState == nil {
		return
	}
	loginState.LastCheckedAt = time.Now()
	loginState.LastCheckOK = true
	loginState.LastStatusMessage = "新接口登录态正常"
	loginState.KeepAliveFailCount = 0
	loginState.KeepAliveStopped = false
}

func appleAccountKeepAliveRetrying(loginState LoginState) bool {
	return !loginState.KeepAliveStopped && !loginState.LastCheckOK && loginState.KeepAliveFailCount > 0
}

func appleAccountKeepAliveDeferred(loginState LoginState) bool {
	return strings.Contains(loginState.LastStatusMessage, "暂时失败")
}

func appleAccountPublicLoginOK(loginState LoginState) bool {
	return loginState.LastCheckOK && !appleAccountKeepAliveDeferred(loginState)
}

func markAppleAccountKeepAliveAuthFailure(loginState LoginState, cause error) LoginState {
	loginState.LastCheckedAt = time.Now()
	loginState.LastCheckOK = false
	loginState.KeepAliveFailCount++
	if loginState.KeepAliveFailCount >= appleAccountKeepAliveMaxAuthFails {
		loginState.KeepAliveStopped = true
		loginState.LastStatusMessage = "新接口登录态异常：" + publicErrorMessage(cause)
		return loginState
	}
	loginState.KeepAliveStopped = false
	loginState.LastStatusMessage = "新接口保活：重试中"
	return loginState
}

func appleAccountKeepAliveAuthError(loginState LoginState) error {
	if loginState.KeepAliveStopped {
		return errCode("apple_account_auth_failed", "Apple Account 管理态已失效，请重新协议登录", true)
	}
	return errCode("apple_account_keepalive_retrying", "新接口保活重试中", true)
}

func appleAccountKeepAliveShouldRescue(err error) bool {
	if isCodedError(err, "apple_account_auth_failed") {
		return true
	}
	if !isCodedError(err, "apple_account_api_failed") {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "http 401") || strings.Contains(msg, "http 403")
}

func appleAccountListShouldRescue(err error) bool {
	return appleAccountKeepAliveShouldRescue(err) ||
		isCodedError(err, "apple_account_api_key_missing") ||
		isCodedError(err, "apple_account_mailbox_list_incomplete")
}

func appleAccountKeepAliveTransientError(err error) bool {
	if err == nil || isCodedError(err, "apple_account_auth_failed") || isCodedError(err, "apple_account_keepalive_retrying") || isCodedError(err, "apple_account_session_missing") {
		return false
	}
	if isCodedError(err, "apple_account_api_failed") || isCodedError(err, "apple_account_hme_limit") {
		return !appleAccountKeepAliveShouldRescue(err)
	}
	return isAppleTransientNetworkError(err)
}

func appleAccountKeepAlivePersistTransient(previous, next LoginState) LoginState {
	out := next
	if strings.TrimSpace(out.Scnt) == "" {
		out = previous
	}
	out.LastCheckOK = previous.LastCheckOK
	out.KeepAliveFailCount = previous.KeepAliveFailCount
	out.KeepAliveStopped = previous.KeepAliveStopped
	out.LastStatusMessage = previous.LastStatusMessage
	out.LastCheckedAt = time.Now()
	return out
}

func markAppleAccountManageTokenTTL(loginState *LoginState, timeoutMinutes int, now time.Time) {
	if loginState == nil || timeoutMinutes <= 0 {
		return
	}
	loginState.ManageExpiresAt = now.Add(time.Duration(timeoutMinutes) * time.Minute)
}

func (c *ICloudClient) CheckAppleAccountManageSession(ctx context.Context, session ICloudSession) (ICloudSession, error) {
	return c.checkAppleAccountManageSession(ctx, session, appleAccountKeepAliveDefaultInterval)
}

func (c *ICloudClient) checkAppleAccountManageSession(ctx context.Context, session ICloudSession, interval time.Duration) (ICloudSession, error) {
	loginState, ok := appleAccountLoginState(session)
	if !ok {
		return session, errCode("apple_account_session_missing", "未保存新接口登录态，请先完成新接口登录", true)
	}
	now := time.Now()
	if interval <= 0 {
		interval = appleAccountKeepAliveDefaultInterval
	}
	if appleAccountManageRecentlyOK(loginState, now) && !appleAccountKeepAliveDue(loginState, now, interval) && !appleAccountKeepAliveDeferred(loginState) {
		return withAppleAccountLoginState(session, loginState), nil
	}
	release, err := acquireAppleAccountOperationGate(ctx, appleAccountOperationKey(session, loginState))
	if err != nil {
		return session, err
	}
	defer release()
	keepAliveCtx, cancel := context.WithTimeout(ctx, appleAccountKeepAliveTimeout)
	defer cancel()
	kept, err := c.keepAliveAppleAccountManageStateUnlocked(keepAliveCtx, loginState)
	session = withAppleAccountLoginState(session, kept)
	if err != nil {
		return session, err
	}
	return session, nil
}

func withAppleAccountLoginState(session ICloudSession, next LoginState) ICloudSession {
	next.Kind = LoginStateAppleAccount
	next.ProxyURL = firstNonEmpty(next.ProxyURL, session.ProxyURL)
	session.ProxyURL = firstNonEmpty(session.ProxyURL, next.ProxyURL)
	for i, state := range session.LoginStates {
		if state.Kind == LoginStateAppleAccount {
			session.LoginStates[i] = next
			return session
		}
	}
	session.LoginStates = append(session.LoginStates, next)
	return session
}

func (c *ICloudClient) CreatePrivacyMailbox(ctx context.Context, session ICloudSession, label, note string) (ICloudRemoteMailbox, error) {
	var ok bool
	if session, ok = iCloudWebSessionForClient(session); !ok || strings.TrimSpace(session.PremiumMailBaseURL) == "" || strings.TrimSpace(session.DSID) == "" {
		return ICloudRemoteMailbox{}, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true)
	}
	if !session.IsICloudPlus || !session.CanCreateHME {
		return ICloudRemoteMailbox{}, errCode("icloud_hme_unavailable", "当前登录态没有可创建隐私邮箱的 iCloud+ 权限", false)
	}

	generated, err := c.generate(ctx, session)
	if err != nil {
		return ICloudRemoteMailbox{}, err
	}
	label = strings.TrimSpace(label)
	if label == "" {
		label = "UPI-" + time.Now().Format("0102-150405")
	}
	return c.reserve(ctx, session, generated, label, strings.TrimSpace(note))
}

func (c *ICloudClient) CreatePrivacyMailboxWithAppleAccount(ctx context.Context, session ICloudSession, fallbackAPIKey, label, note string) (ICloudRemoteMailbox, ICloudSession, error) {
	loginState, ok := appleAccountLoginState(session)
	if !ok {
		return ICloudRemoteMailbox{}, session, errCode("apple_account_session_missing", "当前登录态缺少 Apple Account 管理态，请重新协议登录", true)
	}
	release, err := acquireAppleAccountOperationGate(ctx, appleAccountOperationKey(session, loginState))
	if err != nil {
		return ICloudRemoteMailbox{}, session, err
	}
	defer release()

	fallbackAPIKey = strings.TrimSpace(fallbackAPIKey)
	refreshedBeforeCreate := false
	if appleAccountManageNeedsCreateRefresh(loginState, time.Now()) {
		refreshedBeforeCreate = true
		loginState, session, err = c.refreshAppleAccountManageStateForOperation(ctx, session, loginState, fallbackAPIKey)
		if err != nil {
			return ICloudRemoteMailbox{}, session, err
		}
	}

	remote, updatedSession, err := c.createPrivacyMailboxWithAppleAccountState(ctx, session, loginState, fallbackAPIKey, label, note)
	if err == nil || !appleAccountKeepAliveShouldRescue(err) || refreshedBeforeCreate {
		return remote, updatedSession, err
	}

	retryState, ok := appleAccountLoginState(updatedSession)
	if !ok {
		retryState = loginState
	}
	retryState, updatedSession, refreshErr := c.refreshAppleAccountManageStateForOperation(ctx, updatedSession, retryState, fallbackAPIKey)
	if refreshErr != nil {
		return ICloudRemoteMailbox{}, updatedSession, refreshErr
	}
	return c.createPrivacyMailboxWithAppleAccountState(ctx, updatedSession, retryState, fallbackAPIKey, label, note)
}

func (c *ICloudClient) DeletePrivacyMailboxWithAppleAccount(ctx context.Context, session ICloudSession, fallbackAPIKey, anonymousID string) (ICloudSession, error) {
	session, _, err := c.deletePrivacyMailboxWithAppleAccountDetailed(ctx, session, fallbackAPIKey, anonymousID, false)
	return session, err
}

func (c *ICloudClient) deletePrivacyMailboxWithAppleAccountDetailed(ctx context.Context, session ICloudSession, fallbackAPIKey, anonymousID string, skipStop bool) (ICloudSession, privacyMailboxDeleteOutcome, error) {
	anonymousID = strings.TrimSpace(anonymousID)
	if anonymousID == "" {
		return session, privacyMailboxDeleteOutcome{}, errCode("icloud_mailbox_anonymous_id_missing", "隐私邮箱匿名 ID 为空", false)
	}
	loginState, ok := appleAccountLoginState(session)
	if !ok {
		return session, privacyMailboxDeleteOutcome{}, errCode("apple_account_session_missing", "当前登录态缺少 Apple Account 管理态，请重新协议登录", true)
	}
	release, err := acquireAppleAccountOperationGate(ctx, appleAccountOperationKey(session, loginState))
	if err != nil {
		return session, privacyMailboxDeleteOutcome{}, err
	}
	defer release()

	fallbackAPIKey = strings.TrimSpace(fallbackAPIKey)
	refreshedBeforeDelete := false
	if appleAccountManageNeedsCreateRefresh(loginState, time.Now()) {
		refreshedBeforeDelete = true
		loginState, session, err = c.refreshAppleAccountManageStateForOperation(ctx, session, loginState, fallbackAPIKey)
		if err != nil {
			return session, privacyMailboxDeleteOutcome{}, err
		}
	}

	updatedSession, outcome, err := c.deletePrivacyMailboxWithAppleAccountState(ctx, session, loginState, fallbackAPIKey, anonymousID, skipStop)
	if err == nil || !appleAccountKeepAliveShouldRescue(err) {
		return updatedSession, outcome, err
	}
	if refreshedBeforeDelete && !outcome.Deactivated {
		return updatedSession, outcome, err
	}

	retryState, ok := appleAccountLoginState(updatedSession)
	if !ok {
		retryState = loginState
	}
	retryState, updatedSession, refreshErr := c.refreshAppleAccountManageStateForOperation(ctx, updatedSession, retryState, fallbackAPIKey)
	if refreshErr != nil {
		return updatedSession, outcome, refreshErr
	}
	retriedSession, retriedOutcome, retriedErr := c.deletePrivacyMailboxWithAppleAccountState(ctx, updatedSession, retryState, fallbackAPIKey, anonymousID, outcome.Deactivated)
	retriedOutcome.Deactivated = retriedOutcome.Deactivated || outcome.Deactivated
	return retriedSession, retriedOutcome, retriedErr
}

func (c *ICloudClient) deletePrivacyMailboxWithAppleAccountState(ctx context.Context, session ICloudSession, loginState LoginState, fallbackAPIKey, anonymousID string, skipStop bool) (ICloudSession, privacyMailboxDeleteOutcome, error) {
	outcome := privacyMailboxDeleteOutcome{}
	apiKey := strings.TrimSpace(firstNonEmpty(loginState.APIKey, fallbackAPIKey))
	if apiKey == "" {
		return session, outcome, errCode("apple_account_api_key_missing", "Apple Account 管理态缺少 api_key，请重新完成 Apple Account 登录流程", true)
	}
	loginState.APIKey = apiKey
	session = withAppleAccountLoginState(session, loginState)
	remoteID := url.PathEscape(strings.TrimSpace(anonymousID))
	if skipStop {
		outcome.Deactivated = true
	} else {
		stopPath := "/account/manage/email/private/" + remoteID + "/stop"
		stopRaw, stopErr := c.callAppleAccountRaw(ctx, &loginState, apiKey, http.MethodDelete, stopPath, nil, nil)
		if !isAppleAccountStopContinue(stopRaw, stopErr) {
			return withAppleAccountLoginState(session, loginState), outcome, stopErr
		}
		outcome.Deactivated = true
	}
	removePath := "/account/manage/email/private/" + remoteID + "/remove"
	raw, err := c.callAppleAccountRaw(ctx, &loginState, apiKey, http.MethodDelete, removePath, nil, nil)
	if err != nil && !isAppleAccountRemoveGone(raw, err) {
		return withAppleAccountLoginState(session, loginState), outcome, err
	}
	markAppleAccountManageOK(&loginState)
	return withAppleAccountLoginState(session, loginState), outcome, nil
}

func (c *ICloudClient) refreshAppleAccountManageStateForOperation(ctx context.Context, session ICloudSession, loginState LoginState, fallbackAPIKey string) (LoginState, ICloudSession, error) {
	refreshed, err := c.refreshAppleAccountManageStateUnlocked(ctx, loginState)
	loginState = refreshed
	session = withAppleAccountLoginState(session, loginState)
	if err != nil && (fallbackAPIKey == "" || !isCodedError(err, "apple_account_api_key_missing")) {
		return loginState, session, err
	}
	return loginState, session, nil
}

func (c *ICloudClient) createPrivacyMailboxWithAppleAccountState(ctx context.Context, session ICloudSession, loginState LoginState, fallbackAPIKey, label, note string) (ICloudRemoteMailbox, ICloudSession, error) {
	apiKey := strings.TrimSpace(firstNonEmpty(loginState.APIKey, fallbackAPIKey))
	if apiKey == "" {
		return ICloudRemoteMailbox{}, session, errCode("apple_account_api_key_missing", "Apple Account 管理态缺少 api_key，请重新完成 Apple Account 登录流程", true)
	}
	loginState.APIKey = apiKey
	session = withAppleAccountLoginState(session, loginState)
	label = strings.TrimSpace(label)
	if label == "" {
		label = "UPI-" + time.Now().Format("0102-150405")
	}
	note = strings.TrimSpace(note)

	generatedRaw, err := c.callAppleAccountRaw(ctx, &loginState, apiKey, http.MethodPost, "/account/manage/email/private/add", map[string]any{}, nil)
	if err != nil {
		return ICloudRemoteMailbox{}, withAppleAccountLoginState(session, loginState), err
	}
	generated := parseAppleAccountPrivateEmailPayload(generatedRaw.Body)
	generatedEmail := strings.TrimSpace(firstNonEmpty(generated.EmailAddress, generated.Email))
	if generatedEmail == "" {
		return ICloudRemoteMailbox{}, withAppleAccountLoginState(session, loginState), errCode("apple_account_generate_empty", "Apple Account 未返回候选隐私邮箱；"+appleAccountRawResponseDetail("生成候选隐私邮箱", generatedRaw), true)
	}

	completeBody := map[string]string{
		"emailAddress": generatedEmail,
		"label":        label,
		"note":         note,
	}
	completedRaw, completeErr := c.callAppleAccountRaw(ctx, &loginState, apiKey, http.MethodPut, "/account/manage/email/private/add/complete", completeBody, nil)
	if completeErr != nil && appleAccountKeepAliveShouldRescue(completeErr) {
		refreshed, refreshErr := c.refreshAppleAccountManageStateUnlocked(ctx, loginState)
		loginState = refreshed
		session = withAppleAccountLoginState(session, loginState)
		if refreshErr == nil {
			apiKey = strings.TrimSpace(firstNonEmpty(loginState.APIKey, apiKey))
			completedRaw, completeErr = c.callAppleAccountRaw(ctx, &loginState, apiKey, http.MethodPut, "/account/manage/email/private/add/complete", completeBody, nil)
		}
	}
	remote := appleAccountRemoteMailboxFromCreate(parseAppleAccountPrivateEmailPayload(completedRaw.Body), generatedEmail, label, note)
	if completeErr != nil {
		if recovered, ok := c.lookupAppleAccountCreatedMailbox(ctx, &loginState, generatedEmail); ok {
			if strings.TrimSpace(recovered.Label) == "" {
				recovered.Label = label
			}
			if strings.TrimSpace(recovered.Note) == "" {
				recovered.Note = strings.TrimSpace(firstNonEmpty(note, "created by Apple Account private email API"))
			}
			remote = recovered
			completeErr = nil
		}
	}
	if completeErr != nil {
		return ICloudRemoteMailbox{}, withAppleAccountLoginState(session, loginState), errCode(
			"apple_account_create_uncertain",
			"Apple Account 已提交隐私邮箱确认请求，但未收到可确认的结果；请先同步远端隐私邮箱列表确认后再重试",
			true,
		)
	}
	remote = c.confirmAppleAccountCreatedMailbox(ctx, &loginState, apiKey, remote)
	if remote.Email == "" {
		return ICloudRemoteMailbox{}, withAppleAccountLoginState(session, loginState), errCode("apple_account_create_empty", "Apple Account 创建后未返回隐私邮箱；"+appleAccountRawResponseDetail("确认创建隐私邮箱", completedRaw), true)
	}
	markAppleAccountManageOK(&loginState)
	session = withAppleAccountLoginState(session, loginState)
	return remote, session, nil
}

func (c *ICloudClient) RefreshAppleAccountManageState(ctx context.Context, loginState LoginState) (LoginState, error) {
	release, err := acquireAppleAccountOperationGate(ctx, appleAccountOperationKey(ICloudSession{}, loginState))
	if err != nil {
		return loginState, err
	}
	defer release()
	return c.refreshAppleAccountManageStateUnlocked(ctx, loginState)
}

func (c *ICloudClient) KeepAliveAppleAccountManageState(ctx context.Context, loginState LoginState) (LoginState, error) {
	release, err := acquireAppleAccountOperationGate(ctx, appleAccountOperationKey(ICloudSession{}, loginState))
	if err != nil {
		return loginState, err
	}
	defer release()
	return c.keepAliveAppleAccountManageStateUnlocked(ctx, loginState)
}

func (c *ICloudClient) keepAliveAppleAccountManageStateUnlocked(ctx context.Context, loginState LoginState) (LoginState, error) {
	if strings.TrimSpace(loginState.Scnt) == "" {
		return loginState, errCode("apple_account_session_missing", "当前登录态缺少 Apple Account 管理态，请重新协议登录", true)
	}
	touched, err := c.touchAppleAccountManageStateUnlocked(ctx, loginState)
	if err == nil {
		markAppleAccountManageOK(&touched)
		return touched, nil
	}
	if !appleAccountKeepAliveShouldRescue(err) {
		return touched, err
	}
	recovered, recoverErr := c.recoverAppleAccountManageStateUnlocked(ctx, touched)
	if recoverErr == nil {
		markAppleAccountManageOK(&recovered)
		return recovered, nil
	}
	if !appleAccountKeepAliveShouldRescue(recoverErr) {
		return recovered, recoverErr
	}
	recovered.KeepAliveFailCount = loginState.KeepAliveFailCount
	recovered.KeepAliveStopped = loginState.KeepAliveStopped
	next := markAppleAccountKeepAliveAuthFailure(recovered, recoverErr)
	return next, appleAccountKeepAliveAuthError(next)
}

func (c *ICloudClient) touchAppleAccountManageStateUnlocked(ctx context.Context, loginState LoginState) (LoginState, error) {
	refreshed, err := c.refreshAppleAccountManageStateUnlocked(ctx, loginState)
	if err != nil {
		return loginState, err
	}
	if _, err := c.callAppleAccountRaw(ctx, &refreshed, refreshed.APIKey, http.MethodGet, "/account/manage/forwardemail", nil, nil); err != nil {
		return refreshed, err
	}
	if _, err := c.callAppleAccountRaw(ctx, &refreshed, refreshed.APIKey, http.MethodPost, "/v2/jslogs", appleAccountJSLogBody(), nil); err != nil {
		if os.Getenv("IPM_DEBUG_APPLE_ACCOUNT") == "1" {
			fmt.Fprintf(os.Stderr, "APPLE_ACCOUNT_DEBUG keepalive jslogs ignored err=%v\n", err)
		}
	}
	return refreshed, nil
}

func (c *ICloudClient) recoverAppleAccountManageStateUnlocked(ctx context.Context, loginState LoginState) (LoginState, error) {
	if err := c.warmAppleAccountPortal(ctx, &loginState); err != nil {
		return loginState, err
	}
	previousScnt := strings.TrimSpace(loginState.Scnt)
	loginState.Scnt = ""
	var token struct {
		TimeOutInterval int `json:"timeOutInterval"`
	}
	if err := c.callAppleAccount(ctx, &loginState, "", http.MethodGet, "/account/manage/gs/ws/token", nil, &token); err != nil {
		loginState.Scnt = previousScnt
		return loginState, err
	}
	markAppleAccountManageTokenTTL(&loginState, token.TimeOutInterval, time.Now())
	if err := c.loadAppleAccountManageAPIKey(ctx, &loginState); err != nil {
		return loginState, err
	}
	if _, err := c.callAppleAccountRaw(ctx, &loginState, loginState.APIKey, http.MethodGet, "/account/manage/forwardemail", nil, nil); err != nil {
		return loginState, err
	}
	if _, err := c.callAppleAccountRaw(ctx, &loginState, loginState.APIKey, http.MethodPost, "/v2/jslogs", appleAccountJSLogBody(), nil); err != nil {
		if os.Getenv("IPM_DEBUG_APPLE_ACCOUNT") == "1" {
			fmt.Fprintf(os.Stderr, "APPLE_ACCOUNT_DEBUG keepalive jslogs ignored err=%v\n", err)
		}
	}
	return loginState, nil
}

func appleAccountJSLogBody() []map[string]any {
	return []map[string]any{{
		"eventId":       appleAccountJSLogEventID(),
		"timestamp":     time.Now().UnixMilli(),
		"eventType":     "custom",
		"componentName": "performance",
		"action":        "memory",
		"metadata": map[string]any{
			"domNodeCount":    0,
			"usedJSHeapSize":  0,
			"totalJSHeapSize": 0,
			"heapUtilization": 0,
			"createdAt":       0,
			"elapsedTime":     0,
			"marks": map[string]any{
				"startTime": 0,
			},
			"eventVersion": 1,
		},
	}}
}

func appleAccountKeepAliveDue(loginState LoginState, now time.Time, interval time.Duration) bool {
	if interval <= 0 {
		interval = appleAccountKeepAliveDefaultInterval
	}
	if loginState.LastCheckedAt.IsZero() {
		return true
	}
	return !now.Before(loginState.LastCheckedAt.Add(interval))
}

func (c *ICloudClient) refreshAppleAccountManageStateUnlocked(ctx context.Context, loginState LoginState) (LoginState, error) {
	if strings.TrimSpace(loginState.Scnt) == "" {
		return loginState, errCode("apple_account_session_missing", "当前登录态缺少 Apple Account 管理态，请重新协议登录", true)
	}
	var token struct {
		TimeOutInterval int `json:"timeOutInterval"`
	}
	if err := c.callAppleAccount(ctx, &loginState, "", http.MethodGet, "/account/manage/gs/ws/token", nil, &token); err != nil {
		return loginState, err
	}
	markAppleAccountManageTokenTTL(&loginState, token.TimeOutInterval, time.Now())
	if token.TimeOutInterval <= 0 {
		if err := c.warmAppleAccountPortal(ctx, &loginState); err == nil {
			token = struct {
				TimeOutInterval int `json:"timeOutInterval"`
			}{}
			withoutScnt := loginState
			withoutScnt.Scnt = ""
			if err := c.callAppleAccount(ctx, &withoutScnt, "", http.MethodGet, "/account/manage/gs/ws/token", nil, &token); err == nil {
				loginState = withoutScnt
				markAppleAccountManageTokenTTL(&loginState, token.TimeOutInterval, time.Now())
			} else if err := c.callAppleAccount(ctx, &loginState, "", http.MethodGet, "/account/manage/gs/ws/token", nil, &token); err == nil {
				markAppleAccountManageTokenTTL(&loginState, token.TimeOutInterval, time.Now())
			}
		}
	}
	tokenScnt := strings.TrimSpace(loginState.Scnt)
	if err := c.loadAppleAccountManageAPIKey(ctx, &loginState); err == nil {
		return loginState, nil
	}
	if err := c.warmAppleAccountPortal(ctx, &loginState); err != nil {
		return loginState, err
	}
	withoutScnt := loginState
	withoutScnt.Scnt = ""
	if err := c.callAppleAccount(ctx, &withoutScnt, "", http.MethodGet, "/account/manage/gs/ws/token", nil, &token); err == nil {
		markAppleAccountManageTokenTTL(&withoutScnt, token.TimeOutInterval, time.Now())
		loginState = withoutScnt
	} else if err := c.callAppleAccount(ctx, &loginState, "", http.MethodGet, "/account/manage/gs/ws/token", nil, &token); err != nil {
		if tokenScnt == "" {
			return loginState, err
		}
		loginState.Scnt = tokenScnt
		if retryErr := c.callAppleAccount(ctx, &loginState, "", http.MethodGet, "/account/manage/gs/ws/token", nil, &token); retryErr != nil {
			return loginState, err
		}
		markAppleAccountManageTokenTTL(&loginState, token.TimeOutInterval, time.Now())
	} else {
		markAppleAccountManageTokenTTL(&loginState, token.TimeOutInterval, time.Now())
	}
	if err := c.loadAppleAccountManageAPIKey(ctx, &loginState); err != nil {
		return loginState, err
	}
	return loginState, nil
}

func appleAccountOperationKey(session ICloudSession, loginState LoginState) string {
	owner := firstNonEmpty(session.OwnerID, "global")
	identity := firstNonEmpty(session.AccountID, session.DSID, session.AppleID, loginState.SessionID, loginState.Scnt, loginState.APIKey, "default")
	return owner + ":" + identity
}

func acquireAppleAccountOperationGate(ctx context.Context, key string) (func(), error) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "global:default"
	}
	appleAccountOperationMu.Lock()
	gate := appleAccountOperationGates[key]
	if gate == nil {
		gate = make(chan struct{}, 1)
		appleAccountOperationGates[key] = gate
	}
	appleAccountOperationMu.Unlock()

	select {
	case gate <- struct{}{}:
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *ICloudClient) loadAppleAccountManageAPIKey(ctx context.Context, loginState *LoginState) error {
	var manage struct {
		APIKey string `json:"apiKey"`
	}
	if err := c.callAppleAccount(ctx, loginState, "", http.MethodGet, "/account/manage", nil, &manage); err != nil {
		return err
	}
	if apiKey := strings.TrimSpace(manage.APIKey); apiKey != "" {
		loginState.APIKey = apiKey
	}
	if strings.TrimSpace(loginState.APIKey) == "" {
		return errCode("apple_account_api_key_missing", "Apple Account 管理接口未返回 api_key，请重新完成 Apple Account 登录流程", true)
	}
	return nil
}

func (c *ICloudClient) warmAppleAccountPortal(ctx context.Context, loginState *LoginState) error {
	if _, err := c.callAppleAccountPortal(ctx, loginState, "/account/manage/section/privacy", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", false, "document", "navigate"); err != nil {
		return err
	}
	data, err := c.callAppleAccountPortal(ctx, loginState, "/bootstrap/portal", "application/json, text/plain, */*", true, "empty", "cors")
	if err != nil {
		return err
	}
	var portal struct {
		TimeOutInterval int `json:"timeOutInterval"`
	}
	if json.Unmarshal(data, &portal) == nil {
		markAppleAccountManageTokenTTL(loginState, portal.TimeOutInterval, time.Now())
	}
	return nil
}

func (c *ICloudClient) callAppleAccountPortal(ctx context.Context, loginState *LoginState, path, accept string, jsonContent bool, secFetchDest, secFetchMode string) ([]byte, error) {
	var data []byte
	err := retryAppleTransient(ctx, func() error {
		next, err := c.callAppleAccountPortalOnce(ctx, loginState, path, accept, jsonContent, secFetchDest, secFetchMode)
		if err != nil {
			return err
		}
		data = next
		return nil
	})
	return data, err
}

func (c *ICloudClient) callAppleAccountPortalOnce(ctx context.Context, loginState *LoginState, path, accept string, jsonContent bool, secFetchDest, secFetchMode string) ([]byte, error) {
	if loginState == nil {
		return nil, errCode("apple_account_session_missing", "当前登录态缺少 Apple Account 管理态，请重新协议登录", true)
	}
	base, err := url.Parse(strings.TrimRight(appleAccountPortalBaseForState(*loginState), "/") + "/")
	if err != nil {
		return nil, err
	}
	rel, err := url.Parse(strings.TrimLeft(path, "/"))
	if err != nil {
		return nil, err
	}
	if rel.IsAbs() || rel.Host != "" {
		return nil, errCode("apple_account_invalid_endpoint", "Apple Account 接口路径无效", false)
	}
	rawURL := base.ResolveReference(rel).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	userAgent := firstNonEmpty(loginState.UserAgent, appleAccountManageUserAgent)
	req.Header.Set("Accept", accept)
	if jsonContent {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Referer", strings.TrimRight(firstNonEmpty(loginState.Origin, appleAccountManageOrigin), "/")+"/")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept-Language", appleAccountManageLanguage+",en;q=0.9")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", secFetchMode)
	req.Header.Set("Sec-Fetch-Dest", secFetchDest)
	req.Header.Set("Sec-CH-UA-Platform", appleAccountManagePlatform)
	req.Header.Set("Sec-CH-UA", `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	if cookie := cookieHeader(loginState.Cookies, rawURL); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if jsonContent {
		req.Header.Set("X-Apple-I-Request-Context", appleAccountManageRequestCtx)
		req.Header.Set("X-Apple-I-TimeZone", appleAccountManageTimeZone)
		req.Header.Set("X-Apple-I-FD-Client-Info", appleAccountFDClientInfo(userAgent))
	}
	httpClient, err := httpClientWithProxy(c.client, loginState.ProxyURL)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if os.Getenv("IPM_DEBUG_APPLE_ACCOUNT") == "1" {
		fmt.Fprintf(os.Stderr, "APPLE_ACCOUNT_PORTAL_DEBUG method=GET path=%s status=%d req_cookie_len=%d req_scnt=%s res_scnt=%s res_session=%s set_cookie=%d body=%q\n",
			path,
			resp.StatusCode,
			len(req.Header.Get("Cookie")),
			appleDebugFingerprint(req.Header.Get("scnt")),
			appleDebugFingerprint(resp.Header.Get("scnt")),
			appleDebugFingerprint(resp.Header.Get("X-Apple-ID-Session-Id")),
			len(resp.Cookies()),
			appleDebugBody(data),
		)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return data, appleAccountAPIError(resp.StatusCode, data, appleAccountRequestStage(http.MethodGet, path))
	}
	mergeSessionCookies(&loginState.Cookies, resp.Request.URL, resp.Cookies())
	updateAppleAccountLoginStateFromHeaders(loginState, resp.Header)
	return data, nil
}

func (c *ICloudClient) ListPrivacyMailboxes(ctx context.Context, session ICloudSession) ([]ICloudRemoteMailbox, error) {
	if _, ok := appleAccountLoginState(session); ok && !iCloudWebLoginSaved(session) {
		remotes, _, err := c.ListPrivacyMailboxesForOriginWithSession(ctx, session, mailboxRemoteOriginAppleAccount)
		return remotes, err
	}
	return c.listICloudWebPrivacyMailboxes(ctx, session)
}

func (c *ICloudClient) ListPrivacyMailboxesForOrigin(ctx context.Context, session ICloudSession, origin string) ([]ICloudRemoteMailbox, error) {
	remotes, _, err := c.ListPrivacyMailboxesForOriginWithSession(ctx, session, origin)
	return remotes, err
}

func (c *ICloudClient) ListPrivacyMailboxesForOriginWithSession(ctx context.Context, session ICloudSession, origin string) ([]ICloudRemoteMailbox, ICloudSession, error) {
	return c.ListPrivacyMailboxesForOriginWithSessionAndAPIKey(ctx, session, origin, "")
}

func (c *ICloudClient) ListPrivacyMailboxesForOriginWithSessionAndAPIKey(ctx context.Context, session ICloudSession, origin, fallbackAPIKey string) ([]ICloudRemoteMailbox, ICloudSession, error) {
	switch strings.ToUpper(strings.TrimSpace(origin)) {
	case mailboxRemoteOriginAppleAccount, strings.ToUpper(string(mailboxCreateChannelAppleAccount)):
		state, ok := appleAccountLoginState(session)
		if !ok {
			return nil, session, errCode("apple_account_session_missing", "未保存 Apple Account 新接口登录态，请先完成新接口登录", true)
		}
		release, err := acquireAppleAccountOperationGate(ctx, appleAccountOperationKey(session, state))
		if err != nil {
			return nil, session, err
		}
		defer release()
		fallbackAPIKey = strings.TrimSpace(fallbackAPIKey)
		state.APIKey = firstNonEmpty(strings.TrimSpace(state.APIKey), fallbackAPIKey)
		if appleAccountManageNeedsListRefresh(state, time.Now()) {
			refreshedState, refreshedSession, refreshErr := c.refreshAppleAccountManageStateForOperation(ctx, session, state, fallbackAPIKey)
			if refreshErr != nil {
				return nil, refreshedSession, refreshErr
			}
			session = refreshedSession
			state = refreshedState
			state.APIKey = firstNonEmpty(strings.TrimSpace(state.APIKey), fallbackAPIKey)
		}
		remotes, err := c.listAppleAccountPrivacyMailboxes(ctx, &state)
		if err != nil && appleAccountListShouldRescue(err) {
			incompleteList := isCodedError(err, "apple_account_mailbox_list_incomplete")
			refreshedState, refreshedSession, refreshErr := c.refreshAppleAccountManageStateForOperation(ctx, session, state, fallbackAPIKey)
			if refreshErr != nil && !incompleteList {
				return nil, refreshedSession, refreshErr
			}
			if refreshErr == nil {
				session = refreshedSession
				state = refreshedState
				state.APIKey = firstNonEmpty(strings.TrimSpace(state.APIKey), fallbackAPIKey)
			}
			if incompleteList {
				_ = c.warmAppleAccountPortal(ctx, &state)
			}
			remotes, err = c.listAppleAccountPrivacyMailboxes(ctx, &state)
		}
		if err != nil {
			return nil, withAppleAccountLoginState(session, state), err
		}
		return remotes, withAppleAccountLoginState(session, state), nil
	case mailboxRemoteOriginICloudWeb, strings.ToUpper(string(mailboxCreateChannelICloudWeb)):
		remotes, err := c.listICloudWebPrivacyMailboxes(ctx, session)
		return remotes, session, err
	default:
		return nil, session, errCode("icloud_mailbox_remote_origin_unknown", "无法识别隐私邮箱列表来源，已拒绝调用错误的接口", false)
	}
}

const maxPrivacyMailboxListPages = 100

func (c *ICloudClient) listICloudWebPrivacyMailboxes(ctx context.Context, session ICloudSession) ([]ICloudRemoteMailbox, error) {
	var ok bool
	if session, ok = iCloudWebSessionForClient(session); !ok || strings.TrimSpace(session.PremiumMailBaseURL) == "" || strings.TrimSpace(session.DSID) == "" {
		return nil, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true)
	}
	remotes := make([]ICloudRemoteMailbox, 0)
	seenRemoteIDs := make(map[string]string)
	seenEmails := make(map[string]string)
	seenCursors := make(map[string]struct{})
	path := "/v2/hme/list"
	for pageIndex := 0; ; pageIndex++ {
		var out struct {
			HMEEmails         json.RawMessage `json:"hmeEmails"`
			HasMore           *bool           `json:"hasMore"`
			HasMoreSnake      *bool           `json:"has_more"`
			NextCursor        string          `json:"nextCursor"`
			NextCursorSnake   string          `json:"next_cursor"`
			NextPageToken     string          `json:"nextPageToken"`
			ContinuationToken string          `json:"continuationToken"`
			Items             []struct {
				AnonymousID    string `json:"anonymousId"`
				ID             string `json:"id"`
				HME            string `json:"hme"`
				Label          string `json:"label"`
				ForwardToEmail string `json:"forwardToEmail"`
				Active         *bool  `json:"active"`
				IsActive       *bool  `json:"isActive"`
				Origin         string `json:"origin"`
			} `json:"-"`
		}
		if err := retryAppleTransient(ctx, func() error {
			return c.call(ctx, session, http.MethodGet, path, nil, &out)
		}); err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(out.HMEEmails)) == 0 || bytes.Equal(bytes.TrimSpace(out.HMEEmails), []byte("null")) {
			return nil, errCode("icloud_mailbox_list_incomplete", "iCloud 隐私邮箱列表响应缺少 hmeEmails，未执行本地远端缺失标记", true)
		}
		if err := json.Unmarshal(out.HMEEmails, &out.Items); err != nil {
			return nil, errCode("icloud_mailbox_list_incomplete", "iCloud 隐私邮箱列表字段无法解析，未执行本地远端缺失标记", true)
		}
		for _, item := range out.Items {
			email := strings.ToLower(strings.TrimSpace(item.HME))
			if email == "" {
				return nil, errCode("icloud_mailbox_list_incomplete", "iCloud 隐私邮箱列表包含缺少邮箱地址的记录，未执行本地远端缺失标记", true)
			}
			anonymousID := iCloudWebRemoteAnonymousID(item.ID, item.AnonymousID)
			if anonymousID == "" {
				return nil, errCode("icloud_mailbox_list_incomplete", "iCloud 隐私邮箱列表包含缺少远端匿名 ID 的记录，未执行本地远端缺失标记", true)
			}
			remoteKey := strings.ToLower(anonymousID)
			if previousEmail, ok := seenRemoteIDs[remoteKey]; ok {
				return nil, errCode("icloud_mailbox_list_incomplete", fmt.Sprintf("iCloud 隐私邮箱列表包含重复远端匿名 ID（%s，对应 %s 和 %s），未执行本地远端缺失标记", anonymousID, previousEmail, email), true)
			}
			if previousRemoteID, ok := seenEmails[email]; ok {
				return nil, errCode("icloud_mailbox_list_incomplete", fmt.Sprintf("iCloud 隐私邮箱列表包含重复邮箱地址（%s，对应 %s 和 %s），未执行本地远端缺失标记", email, previousRemoteID, anonymousID), true)
			}
			seenRemoteIDs[remoteKey] = email
			seenEmails[email] = anonymousID
			isActive := true
			if item.Active != nil {
				isActive = *item.Active
			} else if item.IsActive != nil {
				isActive = *item.IsActive
			}
			remotes = append(remotes, ICloudRemoteMailbox{
				AnonymousID:    anonymousID,
				Email:          email,
				Label:          strings.TrimSpace(item.Label),
				ForwardToEmail: strings.TrimSpace(item.ForwardToEmail),
				IsActive:       isActive,
				// This endpoint is the legacy iCloud Web provider. The payload's
				// origin field describes how Apple classified the mailbox, not
				// which provider endpoint must be used for later deletion.
				Origin: mailboxRemoteOriginICloudWeb,
			})
		}
		hasMore := out.HasMore != nil && *out.HasMore
		if out.HasMoreSnake != nil {
			hasMore = hasMore || *out.HasMoreSnake
		}
		queryKey, cursor, more, err := mailboxListNextCursor(
			hasMore,
			out.NextCursor,
			out.NextCursorSnake,
			out.NextPageToken,
			out.ContinuationToken,
		)
		if err != nil {
			return nil, errCode("icloud_mailbox_list_incomplete", "iCloud 隐私邮箱列表标记仍有下一页但未返回下一页游标，未执行本地远端缺失标记", true)
		}
		if !more {
			return remotes, nil
		}
		if pageIndex+1 >= maxPrivacyMailboxListPages {
			return nil, errCode("icloud_mailbox_list_incomplete", "iCloud 隐私邮箱列表分页超过安全上限，未执行本地远端缺失标记", true)
		}
		if _, exists := seenCursors[cursor]; exists {
			return nil, errCode("icloud_mailbox_list_incomplete", "iCloud 隐私邮箱列表分页游标重复，未执行本地远端缺失标记", true)
		}
		seenCursors[cursor] = struct{}{}
		path = appendURLQuery(path, queryKey, cursor)
	}
}

type appleAccountMailboxListPage struct {
	HMEEmails                json.RawMessage `json:"hmeEmails"`
	PrivateEmailList         json.RawMessage `json:"privateEmailList"`
	InactivePrivateEmailList json.RawMessage `json:"inactivePrivateEmailList"`
	HasMore                  *bool           `json:"hasMore"`
	HasMoreSnake             *bool           `json:"has_more"`
	NextCursor               string          `json:"nextCursor"`
	NextCursorSnake          string          `json:"next_cursor"`
	NextPageToken            string          `json:"nextPageToken"`
	ContinuationToken        string          `json:"continuationToken"`
}

type appleAccountMailboxListResponse struct {
	appleAccountMailboxListPage
	Result              appleAccountMailboxListPage `json:"result"`
	Data                appleAccountMailboxListPage `json:"data"`
	HideMyEmail         appleAccountMailboxListPage `json:"hideMyEmail"`
	HideMyEmailBootData appleAccountMailboxListPage `json:"hideMyEmailBootData"`
	Success             *bool                       `json:"success"`
}

type appleAccountMailboxListItem struct {
	AnonymousID    string `json:"anonymousId"`
	ID             string `json:"id"`
	HME            string `json:"hme"`
	EmailAddress   string `json:"emailAddress"`
	Email          string `json:"email"`
	Label          string `json:"label"`
	Note           string `json:"note"`
	ForwardToEmail string `json:"forwardToEmail"`
	Active         *bool  `json:"active"`
	IsActive       *bool  `json:"isActive"`
	Origin         string `json:"origin"`
}

type appleAccountPrivateEmailPayload struct {
	EmailAddress   string `json:"emailAddress"`
	Email          string `json:"email"`
	Label          string `json:"label"`
	Note           string `json:"note"`
	ID             string `json:"id"`
	AnonymousID    string `json:"anonymousId"`
	ForwardToEmail string `json:"forwardToEmail"`
	Active         *bool  `json:"active"`
	IsActive       *bool  `json:"isActive"`
}

type appleAccountPrivateEmailResponse struct {
	appleAccountPrivateEmailPayload
	Result appleAccountPrivateEmailPayload `json:"result"`
	Data   appleAccountPrivateEmailPayload `json:"data"`
}

func parseAppleAccountPrivateEmailPayload(raw []byte) appleAccountPrivateEmailPayload {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || trimmed[0] != '{' {
		return appleAccountPrivateEmailPayload{}
	}
	var response appleAccountPrivateEmailResponse
	if err := json.Unmarshal(trimmed, &response); err != nil {
		return appleAccountPrivateEmailPayload{}
	}
	return mergeAppleAccountPrivateEmailPayload(mergeAppleAccountPrivateEmailPayload(response.appleAccountPrivateEmailPayload, response.Result), response.Data)
}

func mergeAppleAccountPrivateEmailPayload(primary, nested appleAccountPrivateEmailPayload) appleAccountPrivateEmailPayload {
	if strings.TrimSpace(primary.EmailAddress) == "" {
		primary.EmailAddress = nested.EmailAddress
	}
	if strings.TrimSpace(primary.Email) == "" {
		primary.Email = nested.Email
	}
	if strings.TrimSpace(primary.Label) == "" {
		primary.Label = nested.Label
	}
	if strings.TrimSpace(primary.Note) == "" {
		primary.Note = nested.Note
	}
	if strings.TrimSpace(primary.ID) == "" {
		primary.ID = nested.ID
	}
	if strings.TrimSpace(primary.AnonymousID) == "" {
		primary.AnonymousID = nested.AnonymousID
	}
	if strings.TrimSpace(primary.ForwardToEmail) == "" {
		primary.ForwardToEmail = nested.ForwardToEmail
	}
	if primary.Active == nil {
		primary.Active = nested.Active
	}
	if primary.IsActive == nil {
		primary.IsActive = nested.IsActive
	}
	return primary
}

func appleAccountRemoteMailboxFromCreate(payload appleAccountPrivateEmailPayload, generatedEmail, label, note string) ICloudRemoteMailbox {
	remote := ICloudRemoteMailbox{
		AnonymousID:    appleAccountRemoteAnonymousID(payload.ID, payload.AnonymousID),
		Email:          strings.ToLower(strings.TrimSpace(firstNonEmpty(payload.EmailAddress, payload.Email, generatedEmail))),
		Label:          strings.TrimSpace(firstNonEmpty(payload.Label, label)),
		Note:           strings.TrimSpace(firstNonEmpty(payload.Note, note, "created by Apple Account private email API")),
		ForwardToEmail: strings.TrimSpace(payload.ForwardToEmail),
		IsActive:       true,
		Origin:         mailboxRemoteOriginAppleAccount,
	}
	if payload.Active != nil {
		remote.IsActive = *payload.Active
	} else if payload.IsActive != nil {
		remote.IsActive = *payload.IsActive
	}
	return remote
}

func applyAppleAccountPrivateEmailPayload(remote *ICloudRemoteMailbox, payload appleAccountPrivateEmailPayload) {
	if remote == nil {
		return
	}
	if id := appleAccountRemoteAnonymousID(payload.ID, payload.AnonymousID); id != "" {
		remote.AnonymousID = id
	}
	if email := strings.ToLower(strings.TrimSpace(firstNonEmpty(payload.EmailAddress, payload.Email))); email != "" {
		remote.Email = email
	}
	if label := strings.TrimSpace(payload.Label); label != "" {
		remote.Label = label
	}
	if note := strings.TrimSpace(payload.Note); note != "" {
		remote.Note = note
	}
	if forward := strings.TrimSpace(payload.ForwardToEmail); forward != "" {
		remote.ForwardToEmail = forward
	}
	if payload.Active != nil {
		remote.IsActive = *payload.Active
	} else if payload.IsActive != nil {
		remote.IsActive = *payload.IsActive
	}
}

func (c *ICloudClient) lookupAppleAccountCreatedMailbox(ctx context.Context, loginState *LoginState, generatedEmail string) (ICloudRemoteMailbox, bool) {
	want := strings.ToLower(strings.TrimSpace(generatedEmail))
	if loginState == nil || want == "" {
		return ICloudRemoteMailbox{}, false
	}
	remotes, err := c.listAppleAccountPrivacyMailboxes(ctx, loginState)
	if err != nil {
		return ICloudRemoteMailbox{}, false
	}
	for _, remote := range remotes {
		if strings.ToLower(strings.TrimSpace(remote.Email)) == want && strings.TrimSpace(remote.AnonymousID) != "" {
			return remote, true
		}
	}
	return ICloudRemoteMailbox{}, false
}

func (c *ICloudClient) confirmAppleAccountCreatedMailbox(ctx context.Context, loginState *LoginState, apiKey string, remote ICloudRemoteMailbox) ICloudRemoteMailbox {
	anonymousID := strings.TrimSpace(remote.AnonymousID)
	if loginState == nil || anonymousID == "" {
		return remote
	}
	path := "/account/manage/email/private/" + url.PathEscape(anonymousID) + ".em"
	raw, err := c.callAppleAccountRaw(ctx, loginState, apiKey, http.MethodGet, path, nil, nil)
	if err != nil {
		return remote
	}
	applyAppleAccountPrivateEmailPayload(&remote, parseAppleAccountPrivateEmailPayload(raw.Body))
	return remote
}

func (c *ICloudClient) listAppleAccountPrivacyMailboxes(ctx context.Context, loginState *LoginState) ([]ICloudRemoteMailbox, error) {
	if loginState == nil {
		return nil, errCode("apple_account_session_missing", "未保存 Apple Account 新接口登录态，请先完成新接口登录", true)
	}
	apiKey := strings.TrimSpace(loginState.APIKey)
	if apiKey == "" {
		return nil, errCode("apple_account_api_key_missing", "Apple Account 管理态缺少 api_key，请重新完成 Apple Account 登录流程", true)
	}
	remotes := make([]ICloudRemoteMailbox, 0)
	seenRemoteIDs := make(map[string]string)
	seenEmails := make(map[string]string)
	seenCursors := make(map[string]struct{})
	path := "/account/manage/email/private"
	for pageIndex := 0; ; pageIndex++ {
		raw, err := c.callAppleAccountRaw(ctx, loginState, apiKey, http.MethodGet, path, nil, nil)
		if err != nil {
			return nil, err
		}
		page, err := parseAppleAccountMailboxListPage(raw)
		if err != nil {
			return nil, err
		}
		for _, item := range page.items {
			email := strings.ToLower(strings.TrimSpace(firstNonEmpty(item.HME, item.EmailAddress, item.Email)))
			if email == "" {
				return nil, errCode("apple_account_mailbox_list_incomplete", "Apple Account 隐私邮箱列表包含缺少邮箱地址的记录，未执行本地远端缺失标记；"+appleAccountRawResponseDetail("读取隐私邮箱列表", raw), true)
			}
			anonymousID := appleAccountRemoteAnonymousID(item.ID, item.AnonymousID)
			if anonymousID == "" {
				return nil, errCode("apple_account_mailbox_list_incomplete", "Apple Account 隐私邮箱列表包含缺少远端匿名 ID 的记录，未执行本地远端缺失标记；"+appleAccountRawResponseDetail("读取隐私邮箱列表", raw), true)
			}
			remoteKey := strings.ToLower(anonymousID)
			if previousEmail, ok := seenRemoteIDs[remoteKey]; ok {
				return nil, errCode("apple_account_mailbox_list_incomplete", fmt.Sprintf("Apple Account 隐私邮箱列表包含重复远端匿名 ID（%s，对应 %s 和 %s），未执行本地远端缺失标记；%s", anonymousID, previousEmail, email, appleAccountRawResponseDetail("读取隐私邮箱列表", raw)), true)
			}
			if previousRemoteID, ok := seenEmails[email]; ok {
				return nil, errCode("apple_account_mailbox_list_incomplete", fmt.Sprintf("Apple Account 隐私邮箱列表包含重复邮箱地址（%s，对应 %s 和 %s），未执行本地远端缺失标记；%s", email, previousRemoteID, anonymousID, appleAccountRawResponseDetail("读取隐私邮箱列表", raw)), true)
			}
			seenRemoteIDs[remoteKey] = email
			seenEmails[email] = anonymousID
			isActive := true
			if item.Active != nil {
				isActive = *item.Active
			} else if item.IsActive != nil {
				isActive = *item.IsActive
			}
			remotes = append(remotes, ICloudRemoteMailbox{
				AnonymousID:    anonymousID,
				Email:          email,
				Label:          strings.TrimSpace(item.Label),
				Note:           strings.TrimSpace(item.Note),
				ForwardToEmail: strings.TrimSpace(item.ForwardToEmail),
				IsActive:       isActive,
				Origin:         mailboxRemoteOriginAppleAccount,
			})
		}
		if !page.hasMore && !page.hasNextPage {
			return remotes, nil
		}
		if pageIndex+1 >= maxPrivacyMailboxListPages {
			return nil, errCode("apple_account_mailbox_list_incomplete", "Apple Account 隐私邮箱列表分页超过安全上限，未执行本地远端缺失标记", true)
		}
		if page.nextCursor == "" || page.nextCursorParam == "" {
			return nil, errCode("apple_account_mailbox_list_incomplete", "Apple Account 隐私邮箱列表仍有未读取的分页但缺少下一页游标，未执行本地远端缺失标记", true)
		}
		if _, exists := seenCursors[page.nextCursor]; exists {
			return nil, errCode("apple_account_mailbox_list_incomplete", "Apple Account 隐私邮箱列表分页游标重复，未执行本地远端缺失标记", true)
		}
		seenCursors[page.nextCursor] = struct{}{}
		path = appendURLQuery(path, page.nextCursorParam, page.nextCursor)
	}
}

type parsedAppleAccountMailboxList struct {
	items           []appleAccountMailboxListItem
	hasMore         bool
	hasNextPage     bool
	nextCursorParam string
	nextCursor      string
	responseBody    []byte
}

func parseAppleAccountMailboxListPage(raw appleAccountRawResponse) (parsedAppleAccountMailboxList, error) {
	trimmed := bytes.TrimSpace(raw.Body)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return parsedAppleAccountMailboxList{}, errCode("apple_account_mailbox_list_incomplete", "Apple Account 隐私邮箱列表响应为空", true)
	}
	if trimmed[0] == '[' {
		items, err := parseAppleAccountMailboxListItems(trimmed)
		if err != nil {
			return parsedAppleAccountMailboxList{}, err
		}
		return parsedAppleAccountMailboxList{items: items, responseBody: append([]byte(nil), trimmed...)}, nil
	}
	var response appleAccountMailboxListResponse
	if err := json.Unmarshal(trimmed, &response); err != nil {
		return parsedAppleAccountMailboxList{}, errCode("apple_account_mailbox_list_bad_response", "Apple Account 隐私邮箱列表返回无法解析；"+appleAccountRawResponseDetail("读取隐私邮箱列表", raw), true)
	}
	page := mergeAppleAccountMailboxListPage(response.appleAccountMailboxListPage, response.Result)
	page = mergeAppleAccountMailboxListPage(page, response.Data)
	page = mergeAppleAccountMailboxListPage(page, response.HideMyEmail)
	page = mergeAppleAccountMailboxListPage(page, response.HideMyEmailBootData)
	if !appleAccountMailboxListHasCollection(page) {
		if response.Success != nil && !*response.Success {
			return parsedAppleAccountMailboxList{}, errCode("apple_account_api_failed", "Apple Account 隐私邮箱列表接口返回失败；"+appleAccountRawResponseDetail("读取隐私邮箱列表", raw), true)
		}
		return parsedAppleAccountMailboxList{}, errCode("apple_account_mailbox_list_incomplete", "Apple Account 隐私邮箱列表响应缺少 hmeEmails / privateEmailList，未执行本地远端缺失标记；"+appleAccountRawResponseDetail("读取隐私邮箱列表", raw), true)
	}
	items, err := collectAppleAccountMailboxListItems(page)
	if err != nil {
		return parsedAppleAccountMailboxList{}, err
	}
	hasMore := page.HasMore != nil && *page.HasMore
	if page.HasMoreSnake != nil {
		hasMore = hasMore || *page.HasMoreSnake
	}
	nextCursorParam, nextCursor, more, cursorErr := mailboxListNextCursor(
		hasMore,
		page.NextCursor,
		page.NextCursorSnake,
		page.NextPageToken,
		page.ContinuationToken,
	)
	if cursorErr != nil {
		return parsedAppleAccountMailboxList{}, errCode("apple_account_mailbox_list_incomplete", "Apple Account 隐私邮箱列表标记仍有下一页但未返回下一页游标，未执行本地远端缺失标记", true)
	}
	return parsedAppleAccountMailboxList{
		items:           items,
		hasMore:         more,
		hasNextPage:     more,
		nextCursorParam: nextCursorParam,
		nextCursor:      nextCursor,
		responseBody:    append([]byte(nil), trimmed...),
	}, nil
}

func mergeAppleAccountMailboxListPage(primary, nested appleAccountMailboxListPage) appleAccountMailboxListPage {
	if !appleAccountJSONFieldPresent(primary.HMEEmails) {
		primary.HMEEmails = nested.HMEEmails
	}
	if !appleAccountJSONFieldPresent(primary.PrivateEmailList) {
		primary.PrivateEmailList = nested.PrivateEmailList
	}
	if !appleAccountJSONFieldPresent(primary.InactivePrivateEmailList) {
		primary.InactivePrivateEmailList = nested.InactivePrivateEmailList
	}
	if primary.HasMore == nil {
		primary.HasMore = nested.HasMore
	}
	if primary.HasMoreSnake == nil {
		primary.HasMoreSnake = nested.HasMoreSnake
	}
	if strings.TrimSpace(primary.NextCursor) == "" {
		primary.NextCursor = nested.NextCursor
	}
	if strings.TrimSpace(primary.NextCursorSnake) == "" {
		primary.NextCursorSnake = nested.NextCursorSnake
	}
	if strings.TrimSpace(primary.NextPageToken) == "" {
		primary.NextPageToken = nested.NextPageToken
	}
	if strings.TrimSpace(primary.ContinuationToken) == "" {
		primary.ContinuationToken = nested.ContinuationToken
	}
	return primary
}

func appleAccountJSONFieldPresent(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func appleAccountMailboxListHasCollection(page appleAccountMailboxListPage) bool {
	return appleAccountJSONFieldPresent(page.HMEEmails) ||
		appleAccountJSONFieldPresent(page.PrivateEmailList) ||
		appleAccountJSONFieldPresent(page.InactivePrivateEmailList)
}

func parseAppleAccountMailboxListItems(raw json.RawMessage) ([]appleAccountMailboxListItem, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, errCode("apple_account_mailbox_list_incomplete", "Apple Account 隐私邮箱列表响应缺少 hmeEmails，未执行本地远端缺失标记", true)
	}
	var items []appleAccountMailboxListItem
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return nil, errCode("apple_account_mailbox_list_bad_response", "Apple Account 隐私邮箱列表返回无法解析", true)
	}
	return items, nil
}

func collectAppleAccountMailboxListItems(page appleAccountMailboxListPage) ([]appleAccountMailboxListItem, error) {
	var items []appleAccountMailboxListItem
	appendGroup := func(raw json.RawMessage, defaultActive bool) error {
		if !appleAccountJSONFieldPresent(raw) {
			return nil
		}
		group, err := parseAppleAccountMailboxListItems(raw)
		if err != nil {
			return err
		}
		for i := range group {
			if group[i].Active == nil && group[i].IsActive == nil {
				value := defaultActive
				group[i].IsActive = &value
			}
		}
		items = append(items, group...)
		return nil
	}
	official := appleAccountJSONFieldPresent(page.PrivateEmailList) || appleAccountJSONFieldPresent(page.InactivePrivateEmailList)
	if official {
		if err := appendGroup(page.PrivateEmailList, true); err != nil {
			return nil, err
		}
		if err := appendGroup(page.InactivePrivateEmailList, false); err != nil {
			return nil, err
		}
		if len(items) > 0 || !appleAccountJSONFieldPresent(page.HMEEmails) {
			return items, nil
		}
		items = items[:0]
	}
	if err := appendGroup(page.HMEEmails, true); err != nil {
		return nil, err
	}
	return items, nil
}

func appleAccountMailboxListPageIncomplete(page parsedAppleAccountMailboxList) error {
	if page.hasMore || page.hasNextPage {
		return errors.New("Apple Account 隐私邮箱列表仍有未读取的分页，未执行本地远端缺失标记")
	}
	return nil
}

func mailboxListNextCursor(hasMore bool, nextCursor, nextCursorSnake, nextPageToken, continuationToken string) (string, string, bool, error) {
	candidates := []struct {
		param string
		value string
	}{
		{param: "cursor", value: nextCursor},
		{param: "next_cursor", value: nextCursorSnake},
		{param: "pageToken", value: nextPageToken},
		{param: "continuationToken", value: continuationToken},
	}
	for _, candidate := range candidates {
		if value := strings.TrimSpace(candidate.value); value != "" {
			return candidate.param, value, true, nil
		}
	}
	if hasMore {
		return "", "", true, errors.New("隐私邮箱列表标记仍有下一页但未返回下一页游标")
	}
	return "", "", false, nil
}

func appendURLQuery(rawPath, key, value string) string {
	u, err := url.Parse(rawPath)
	if err != nil {
		return rawPath
	}
	q := u.Query()
	q.Set(strings.TrimSpace(key), value)
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *ICloudClient) DeactivatePrivacyMailbox(ctx context.Context, session ICloudSession, anonymousID string) error {
	anonymousID = strings.TrimSpace(anonymousID)
	if anonymousID == "" {
		return errCode("icloud_mailbox_anonymous_id_missing", "隐私邮箱匿名 ID 为空", false)
	}
	return c.call(ctx, session, http.MethodPost, "/v1/hme/deactivate", map[string]string{
		"anonymousId": anonymousID,
	}, nil)
}

func (c *ICloudClient) DeletePrivacyMailbox(ctx context.Context, session ICloudSession, anonymousID string) error {
	_, err := c.deletePrivacyMailboxWeb(ctx, session, anonymousID)
	return err
}

func (c *ICloudClient) deletePrivacyMailboxWeb(ctx context.Context, session ICloudSession, anonymousID string) (privacyMailboxDeleteOutcome, error) {
	anonymousID = strings.TrimSpace(anonymousID)
	outcome := privacyMailboxDeleteOutcome{}
	if anonymousID == "" {
		return outcome, errCode("icloud_mailbox_anonymous_id_missing", "隐私邮箱匿名 ID 为空", false)
	}
	if err := c.call(ctx, session, http.MethodPost, "/v1/hme/deactivate", map[string]string{
		"anonymousId": anonymousID,
	}, nil); err != nil && !isRemoteMailboxAlreadyInactive(err) && !isICloudHMEDeleteGone(err) {
		return outcome, err
	}
	outcome.Deactivated = true
	if err := c.call(ctx, session, http.MethodPost, "/v1/hme/delete", map[string]string{
		"anonymousId": anonymousID,
	}, nil); err != nil && !isICloudHMEDeleteGone(err) {
		if isCodedError(err, "icloud_hme_still_active") {
			outcome.Deactivated = false
		}
		return outcome, err
	}
	return outcome, nil
}

func isAppleAccountRemoveGone(raw appleAccountRawResponse, err error) bool {
	if raw.StatusCode != http.StatusNotFound && raw.StatusCode != http.StatusGone {
		return false
	}
	if looksLikeHTML(raw.Body) {
		return false
	}
	return err != nil
}

func isAppleAccountStopContinue(raw appleAccountRawResponse, err error) bool {
	if err == nil {
		return true
	}
	return isAppleAccountRemoveGone(raw, err) || isRemoteMailboxAlreadyInactive(err)
}

func isICloudHMEDeleteGone(err error) bool {
	if err == nil {
		return false
	}
	var coded codedError
	if !errors.As(err, &coded) {
		return false
	}
	lower := strings.ToLower(coded.code + " " + coded.message)
	if strings.Contains(lower, "<html") {
		return false
	}
	switch coded.code {
	case "icloud_http_error":
		return strings.Contains(lower, "http 404") || strings.Contains(lower, "http 410")
	case "icloud_api_failed":
		return isICloudHMEAlreadyGoneMessage(coded.message)
	}
	return false
}

func isICloudHMEAlreadyGoneMessage(message string) bool {
	lower := strings.ToLower(strings.TrimSpace(message))
	for _, token := range []string{"already deleted", "already removed", "does not exist", "no longer exist"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func isRemoteMailboxAlreadyInactive(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(strings.TrimSpace(err.Error()))
	var coded codedError
	if errors.As(err, &coded) {
		text = strings.ToLower(strings.TrimSpace(coded.code + " " + coded.message))
	}
	if strings.Contains(text, "http 404") || strings.Contains(text, "http 410") || strings.Contains(text, "<html") {
		return false
	}
	for _, token := range []string{
		"already inactive",
		"already_inactive",
		"already-inactive",
		"already deactivated",
		"already_deactivated",
		"hme_already_inactive",
	} {
		if strings.Contains(text, token) {
			return true
		}
	}
	return false
}

func looksLikeHTML(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return false
	}
	lower := bytes.ToLower(trimmed)
	return bytes.HasPrefix(lower, []byte("<!")) || bytes.Contains(lower[:min(len(lower), 256)], []byte("<html"))
}

func (c *ICloudClient) generate(ctx context.Context, session ICloudSession) (string, error) {
	var out struct {
		HME string `json:"hme"`
	}
	if err := c.call(ctx, session, http.MethodPost, "/v1/hme/generate", map[string]string{
		"langCode": "zh-cn",
	}, &out); err != nil {
		return "", err
	}
	if strings.TrimSpace(out.HME) == "" {
		return "", errCode("icloud_generate_empty", "iCloud 未返回候选隐私邮箱", true)
	}
	return strings.TrimSpace(out.HME), nil
}

func (c *ICloudClient) reserve(ctx context.Context, session ICloudSession, hme, label, note string) (ICloudRemoteMailbox, error) {
	var out struct {
		HME struct {
			AnonymousID    string `json:"anonymousId"`
			HME            string `json:"hme"`
			Label          string `json:"label"`
			Note           string `json:"note"`
			ForwardToEmail string `json:"forwardToEmail"`
			Active         *bool  `json:"active"`
			IsActive       *bool  `json:"isActive"`
		} `json:"hme"`
	}
	if err := c.call(ctx, session, http.MethodPost, "/v1/hme/reserve", map[string]string{
		"hme":   hme,
		"label": label,
		"note":  note,
	}, &out); err != nil {
		return ICloudRemoteMailbox{}, errCode(
			"icloud_create_uncertain",
			"iCloud 已提交隐私邮箱确认请求，但未收到可确认的结果；请先同步远端隐私邮箱列表确认后再重试",
			true,
		)
	}
	isActive := true
	if out.HME.Active != nil {
		isActive = *out.HME.Active
	} else if out.HME.IsActive != nil {
		isActive = *out.HME.IsActive
	}
	return ICloudRemoteMailbox{
		AnonymousID:    out.HME.AnonymousID,
		Email:          out.HME.HME,
		Label:          out.HME.Label,
		Note:           out.HME.Note,
		ForwardToEmail: out.HME.ForwardToEmail,
		IsActive:       isActive,
		Origin:         "ICLOUD_WEB",
	}, nil
}

func (c *ICloudClient) callAppleAccount(ctx context.Context, loginState *LoginState, apiKey, method, path string, body any, result any) error {
	_, err := c.callAppleAccountRaw(ctx, loginState, apiKey, method, path, body, result)
	return err
}

type appleAccountRawResponse struct {
	StatusCode int
	Body       []byte
}

func (c *ICloudClient) fetchAppleAccountManageTokenScnt(ctx context.Context, loginState LoginState, result any) (string, error) {
	var scnt string
	err := retryAppleTransient(ctx, func() error {
		next, err := c.fetchAppleAccountManageTokenScntOnce(ctx, loginState, result)
		if strings.TrimSpace(next) != "" {
			scnt = next
		}
		if err != nil {
			return err
		}
		return nil
	})
	return scnt, err
}

func (c *ICloudClient) fetchAppleAccountManageTokenScntOnce(ctx context.Context, loginState LoginState, result any) (string, error) {
	base, err := url.Parse(strings.TrimRight(appleAccountManageBaseForState(loginState), "/") + "/")
	if err != nil {
		return "", err
	}
	rawURL := base.ResolveReference(&url.URL{Path: "account/manage/gs/ws/token"}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	origin := strings.TrimRight(firstNonEmpty(loginState.Origin, appleAccountManageOriginForHost(loginState.Host), appleAccountManageOrigin), "/")
	userAgent := firstNonEmpty(loginState.UserAgent, appleAccountManageUserAgent)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept-Language", appleAccountManageLanguage+",en;q=0.9")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-CH-UA-Platform", appleAccountManagePlatform)
	req.Header.Set("Sec-CH-UA", `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("X-Apple-I-FD-Client-Info", appleAccountFDClientInfo(userAgent))
	req.Header.Set("X-Apple-I-Request-Context", appleAccountManageRequestCtx)
	req.Header.Set("X-Apple-I-TimeZone", appleAccountManageTimeZone)
	if cookie := cookieHeader(loginState.Cookies, rawURL); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	httpClient, err := httpClientWithProxy(c.client, loginState.ProxyURL)
	if err != nil {
		return "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	scnt := strings.TrimSpace(resp.Header.Get("scnt"))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return scnt, appleAccountAPIError(resp.StatusCode, data, appleAccountRequestStage(http.MethodGet, "/account/manage/gs/ws/token"))
	}
	if result != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, result); err != nil {
			return scnt, errCode("apple_account_bad_response", "Apple Account 返回无法解析；"+appleAccountResponseDetail(appleAccountRequestStage(http.MethodGet, "/account/manage/gs/ws/token"), data), true)
		}
	}
	return scnt, nil
}

func (c *ICloudClient) callAppleAccountRaw(ctx context.Context, loginState *LoginState, apiKey, method, path string, body any, result any) (appleAccountRawResponse, error) {
	var raw appleAccountRawResponse
	err := retryAppleTransient(ctx, func() error {
		next, callErr := c.callAppleAccountRawOnce(ctx, loginState, apiKey, method, path, body, result)
		raw = next
		return callErr
	})
	return raw, err
}

func (c *ICloudClient) callAppleAccountRawOnce(ctx context.Context, loginState *LoginState, apiKey, method, path string, body any, result any) (appleAccountRawResponse, error) {
	if loginState == nil {
		return appleAccountRawResponse{}, errCode("apple_account_session_missing", "当前登录态缺少 Apple Account 管理态，请重新协议登录", true)
	}
	base, err := url.Parse(strings.TrimRight(appleAccountManageBaseForState(*loginState), "/") + "/")
	if err != nil {
		return appleAccountRawResponse{}, err
	}
	rel, err := url.Parse(strings.TrimLeft(path, "/"))
	if err != nil {
		return appleAccountRawResponse{}, err
	}
	if rel.IsAbs() || rel.Host != "" {
		return appleAccountRawResponse{}, errCode("apple_account_invalid_endpoint", "Apple Account 接口路径无效", false)
	}
	rawURL := base.ResolveReference(rel).String()

	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return appleAccountRawResponse{}, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return appleAccountRawResponse{}, err
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if appleAccountShouldSetJSONContentType(method, body) {
		req.Header.Set("Content-Type", "application/json")
	}
	origin := strings.TrimRight(firstNonEmpty(loginState.Origin, appleAccountManageOriginForHost(loginState.Host), appleAccountManageOrigin), "/")
	userAgent := firstNonEmpty(loginState.UserAgent, appleAccountManageUserAgent)
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept-Language", appleAccountManageLanguage+",en;q=0.9")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-CH-UA-Platform", appleAccountManagePlatform)
	req.Header.Set("Sec-CH-UA", `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	if scnt := strings.TrimSpace(loginState.Scnt); scnt != "" {
		req.Header.Set("scnt", scnt)
	}
	if apiKey = strings.TrimSpace(apiKey); apiKey != "" {
		req.Header.Set("X-Apple-Api-Key", apiKey)
	}
	req.Header.Set("X-Apple-I-FD-Client-Info", appleAccountFDClientInfo(userAgent))
	req.Header.Set("X-Apple-I-Request-Context", appleAccountManageRequestCtx)
	req.Header.Set("X-Apple-I-TimeZone", appleAccountManageTimeZone)
	if cookie := cookieHeader(loginState.Cookies, rawURL); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	httpClient, err := httpClientWithProxy(c.client, loginState.ProxyURL)
	if err != nil {
		return appleAccountRawResponse{}, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return appleAccountRawResponse{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	raw := appleAccountRawResponse{StatusCode: resp.StatusCode, Body: data}
	if err != nil {
		return raw, err
	}
	if os.Getenv("IPM_DEBUG_APPLE_ACCOUNT") == "1" {
		fmt.Fprintf(os.Stderr, "APPLE_ACCOUNT_DEBUG method=%s path=%s status=%d req_cookie_len=%d req_scnt=%s res_scnt=%s res_session=%s set_cookie=%d body=%q\n",
			method,
			path,
			resp.StatusCode,
			len(req.Header.Get("Cookie")),
			appleDebugFingerprint(req.Header.Get("scnt")),
			appleDebugFingerprint(resp.Header.Get("scnt")),
			appleDebugFingerprint(resp.Header.Get("X-Apple-ID-Session-Id")),
			len(resp.Cookies()),
			appleDebugBody(data),
		)
	}
	if !appleAccountHTTPStatusIsSuccess(method, path, resp.StatusCode) {
		if os.Getenv("IPM_DEBUG_APPLE_ACCOUNT") == "1" {
			fmt.Fprintf(os.Stderr, "APPLE_ACCOUNT_DEBUG method=%s path=%s status=%d body=%q\n", method, path, resp.StatusCode, appleDebugBody(data))
		}
		return raw, appleAccountAPIError(resp.StatusCode, data, appleAccountRequestStage(method, path))
	}
	mergeSessionCookies(&loginState.Cookies, resp.Request.URL, resp.Cookies())
	updateAppleAccountLoginStateFromHeaders(loginState, resp.Header)
	if result != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, result); err != nil {
			return raw, errCode("apple_account_bad_response", "Apple Account 返回无法解析；"+appleAccountRawResponseDetail(appleAccountRequestStage(method, path), raw), true)
		}
	}
	return raw, nil
}

func updateAppleAccountLoginStateFromHeaders(loginState *LoginState, header http.Header) {
	if loginState == nil {
		return
	}
	if scnt := strings.TrimSpace(header.Get("scnt")); scnt != "" {
		loginState.Scnt = scnt
	}
	if sessionID := strings.TrimSpace(header.Get("X-Apple-ID-Session-Id")); sessionID != "" {
		loginState.SessionID = sessionID
	}
	if token := strings.TrimSpace(firstNonEmpty(header.Get("X-Apple-I-DA-Token"), header.Get("X-Apple-I-Cont-X-Apple-I-DA-Token"))); token != "" {
		loginState.DataAccessToken = token
	}
	loginState.SavedAt = time.Now()
}

func appleAccountJSLogEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("ipm-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4],
		b[4:6],
		b[6:8],
		b[8:10],
		b[10:16],
	)
}

func appleAccountFDClientInfo(userAgent string) string {
	info := map[string]string{
		"U": firstNonEmpty(userAgent, appleAccountManageUserAgent),
		"L": appleAccountManageLanguage,
		"Z": appleAccountManageGMTOffset,
		"V": "1.1",
		"F": appleAccountCompressedFingerprint(time.Now()),
	}
	data, _ := json.Marshal(info)
	return string(data)
}

func appleAccountCompressedFingerprint(now time.Time) string {
	raw := appleAccountFingerprintPayload(now.In(time.FixedZone("apple-account", appleAccountManageTZOffset)))
	replaced := raw
	for idx, token := range appleAccountFingerprintDictionary {
		replaced = strings.ReplaceAll(replaced, token, string(rune(idx+1)))
	}
	encoded, ok := appleAccountFingerprintHuffman(replaced)
	if !ok {
		return raw
	}
	checksum := 65535
	for _, b := range []byte(raw) {
		checksum = ((checksum >> 8) | (checksum << 8)) & 0xffff
		checksum ^= int(b) & 0xff
		checksum ^= (checksum & 0xff) >> 4
		checksum ^= (checksum << 12) & 0xffff
		checksum ^= ((checksum & 0xff) << 5) & 0xffff
	}
	return encoded +
		string(appleAccountFingerprintAlphabet[(checksum>>12)&63]) +
		string(appleAccountFingerprintAlphabet[(checksum>>6)&63]) +
		string(appleAccountFingerprintAlphabet[checksum&63])
}

func appleAccountFingerprintPayload(now time.Time) string {
	values := []string{
		"TF1", "020",
	}
	for i := 0; i < 39; i++ {
		values = append(values, "")
	}
	values = append(values,
		"true",
		"true",
		strconv.FormatInt(now.UnixMilli(), 10),
		"-6",
		"6/7/2005, 9:33:44 PM",
		"", "", "", "", "", "",
		strconv.FormatInt(now.UnixMilli(), 10),
		"0",
		appleAccountUSLocaleString(now),
	)
	for i := 0; i < 34; i++ {
		values = append(values, "")
	}
	values = append(values, "5.6.1-0", "")

	var b strings.Builder
	for _, value := range values {
		b.WriteString(appleAccountJSEscape(value))
		b.WriteByte(';')
	}
	return b.String()
}

func appleAccountUSLocaleString(t time.Time) string {
	hour := t.Hour()
	ampm := "AM"
	if hour >= 12 {
		ampm = "PM"
	}
	hour12 := hour % 12
	if hour12 == 0 {
		hour12 = 12
	}
	return fmt.Sprintf("%d/%d/%d, %d:%02d:%02d %s", int(t.Month()), t.Day(), t.Year(), hour12, t.Minute(), t.Second(), ampm)
}

func appleAccountJSEscape(value string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for _, r := range value {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '@' || r == '*' || r == '_' || r == '+' || r == '-' || r == '.' || r == '/' {
			b.WriteRune(r)
			continue
		}
		if r <= 0xff {
			b.WriteByte('%')
			b.WriteByte(hex[(r>>4)&0xf])
			b.WriteByte(hex[r&0xf])
			continue
		}
		b.WriteString("%u")
		b.WriteByte(hex[(r>>12)&0xf])
		b.WriteByte(hex[(r>>8)&0xf])
		b.WriteByte(hex[(r>>4)&0xf])
		b.WriteByte(hex[r&0xf])
	}
	return b.String()
}

func appleAccountFingerprintHuffman(value string) (string, bool) {
	var b strings.Builder
	bitBuffer := 0
	bitCount := 0
	push := func(width, code int) {
		bitBuffer = (bitBuffer << width) | code
		bitCount += width
		for bitCount >= 6 {
			idx := (bitBuffer >> (bitCount - 6)) & 63
			b.WriteByte(appleAccountFingerprintAlphabet[idx])
			bitCount -= 6
			bitBuffer ^= idx << bitCount
		}
	}
	push(6, (len(value)&7)<<3)
	push(6, (len(value)&56)|1)
	for _, r := range value {
		code, ok := appleAccountFingerprintCodes[int(r)]
		if !ok {
			return "", false
		}
		push(code.width, code.value)
	}
	code := appleAccountFingerprintCodes[0]
	push(code.width, code.value)
	if bitCount > 0 {
		push(6-bitCount, 0)
	}
	return b.String(), true
}

type appleAccountFingerprintCode struct {
	width int
	value int
}

var appleAccountFingerprintDictionary = []string{
	"%20", ";;;", "%3B", "%2C", "und", "fin", "ed;", "%28", "%29", "%3A", "/53", "ike", "Web", "0;", ".0", "e;", "on", "il", "ck", "01", "in", "Mo", "fa", "00", "32", "la", ".1", "ri", "it", "%u", "le",
}

const appleAccountFingerprintAlphabet = ".0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"

var appleAccountFingerprintCodes = map[int]appleAccountFingerprintCode{
	1: {4, 15}, 110: {8, 239}, 74: {8, 238}, 57: {7, 118}, 56: {7, 117}, 71: {8, 233},
	25: {8, 232}, 101: {5, 28}, 104: {7, 111}, 4: {7, 110}, 105: {6, 54}, 5: {7, 107},
	109: {7, 106}, 103: {9, 423}, 82: {9, 422}, 26: {8, 210}, 6: {7, 104}, 46: {6, 51},
	97: {6, 50}, 111: {6, 49}, 7: {7, 97}, 45: {7, 96}, 59: {5, 23}, 15: {7, 91},
	11: {8, 181}, 72: {8, 180}, 27: {8, 179}, 28: {8, 178}, 16: {7, 88}, 88: {10, 703},
	113: {11, 1405}, 89: {12, 2809}, 107: {13, 5617}, 90: {14, 11233}, 42: {15, 22465},
	64: {16, 44929}, 0: {16, 44928}, 81: {9, 350}, 29: {8, 174}, 118: {8, 173}, 30: {8, 172},
	98: {8, 171}, 12: {8, 170}, 99: {7, 84}, 117: {6, 41}, 112: {6, 40}, 102: {9, 319},
	68: {9, 318}, 31: {8, 158}, 100: {7, 78}, 84: {6, 38}, 55: {6, 37}, 17: {7, 73},
	8: {7, 72}, 9: {7, 71}, 77: {7, 70}, 18: {7, 69}, 65: {7, 68}, 48: {6, 33},
	116: {6, 32}, 10: {7, 63}, 121: {8, 125}, 78: {8, 124}, 80: {7, 61}, 69: {7, 60},
	119: {7, 59}, 13: {8, 117}, 79: {8, 116}, 19: {7, 57}, 67: {7, 56}, 114: {6, 27},
	83: {6, 26}, 115: {6, 25}, 14: {6, 24}, 122: {8, 95}, 95: {8, 94}, 76: {7, 46},
	24: {7, 45}, 37: {7, 44}, 50: {5, 10}, 51: {5, 9}, 108: {6, 17}, 22: {7, 33},
	120: {8, 65}, 66: {8, 64}, 21: {7, 31}, 106: {7, 30}, 47: {6, 14}, 53: {5, 6},
	49: {5, 5}, 86: {8, 39}, 85: {8, 38}, 23: {7, 18}, 75: {7, 17}, 20: {7, 16},
	2: {5, 3}, 73: {8, 23}, 43: {9, 45}, 87: {9, 44}, 70: {7, 10}, 3: {6, 4},
	52: {5, 1}, 54: {5, 0},
}

func appleAccountAPIError(status int, data []byte, stage string) error {
	detail := appleAccountErrorDetail(status, data, stage)
	msg := strings.TrimSpace(appleDebugBody(data))
	if msg == "" {
		msg = "空响应"
	}
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "limit") || strings.Contains(lower, "too many") || strings.Contains(lower, "rate") {
		return errCode("apple_account_hme_limit", "Apple Account 已达到当前隐私邮箱创建上限，请稍后再试；"+detail, true)
	}
	if status == appleAccountHTTPStatusSessionTimeout || ((status == http.StatusUnauthorized || status == http.StatusForbidden) && appleAccountUnauthorizedLooksAuthFailed(data, lower)) {
		return errCode("apple_account_auth_failed", "Apple Account 管理态已失效，请重新协议登录；"+detail, true)
	}
	return errCode("apple_account_api_failed", "Apple Account 接口失败；"+detail, true)
}

func appleAccountUnauthorizedLooksAuthFailed(data []byte, lower string) bool {
	if appleAccountBodyLooksAuthExpired(lower) {
		return true
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return true
	}
	return bytes.Contains(trimmed, []byte("service_errors")) || bytes.Contains(trimmed, []byte("serviceErrors"))
}

func appleAccountBodyLooksAuthExpired(lower string) bool {
	lower = strings.ToLower(strings.TrimSpace(lower))
	if lower == "" {
		return false
	}
	authTokens := []string{
		"authentication_failed",
		"authentication failed",
		"auth_failed",
		"auth failed",
		"gsa_invalid_session",
		"invalid session",
		"scnt_expired",
		"session expired",
		"session has expired",
	}
	for _, token := range authTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return strings.Contains(lower, "authentication") && (strings.Contains(lower, "failed") || strings.Contains(lower, "expired"))
}

func appleAccountShouldSetJSONContentType(method string, body any) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodDelete:
		return false
	default:
		return body != nil
	}
}

func appleAccountHTTPStatusIsSuccess(method, path string, status int) bool {
	if appleAccountHMERequiresOK(method, path) {
		if status == http.StatusOK {
			return true
		}
		return status == http.StatusPreconditionFailed && appleAccountAllowsPreconditionFailed(method, path)
	}
	return status >= 200 && status < 300
}

func appleAccountManagePath(path string) string {
	parsed, err := url.Parse(strings.TrimSpace(path))
	if err != nil {
		return ""
	}
	clean := strings.TrimRight(parsed.Path, "/")
	if clean == "" {
		return "/"
	}
	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}
	return clean
}

func appleAccountHMERequiresOK(method, path string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	clean := appleAccountManagePath(path)
	switch {
	case method == http.MethodGet && clean == "/account/manage/email/private":
		return true
	case method == http.MethodGet && strings.HasPrefix(clean, "/account/manage/email/private/") && strings.HasSuffix(clean, ".em"):
		return true
	case method == http.MethodPost && clean == "/account/manage/email/private/add":
		return true
	case method == http.MethodPut && clean == "/account/manage/email/private/add/complete":
		return true
	case method == http.MethodDelete && strings.HasPrefix(clean, "/account/manage/email/private/") && (strings.HasSuffix(clean, "/stop") || strings.HasSuffix(clean, "/remove")):
		return true
	case method == http.MethodPost && strings.HasPrefix(clean, "/account/manage/email/private/") && (strings.HasSuffix(clean, "/reactivate") || strings.HasSuffix(clean, "/note")):
		return true
	default:
		return false
	}
}

func appleAccountAllowsPreconditionFailed(method, path string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	clean := appleAccountManagePath(path)
	switch {
	case method == http.MethodGet && clean == "/account/manage/email/private":
		return true
	case method == http.MethodPost && clean == "/account/manage/email/private/add":
		return true
	case method == http.MethodPut && clean == "/account/manage/email/private/add/complete":
		return true
	default:
		return false
	}
}

func appleAccountSanitizeErrorCode(code string) string {
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 64 {
		return ""
	}
	lower := strings.ToLower(code)
	if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "cookie") {
		return ""
	}
	for _, r := range code {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return ""
	}
	return code
}

func appleAccountAnyErrorCode(value any) string {
	switch v := value.(type) {
	case string:
		return appleAccountSanitizeErrorCode(v)
	case float64:
		if v == float64(int64(v)) {
			return appleAccountSanitizeErrorCode(strconv.FormatInt(int64(v), 10))
		}
	case json.Number:
		return appleAccountSanitizeErrorCode(v.String())
	}
	return ""
}

func appleAccountSafeErrorCode(data []byte) string {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || looksLikeHTML(trimmed) || trimmed[0] != '{' {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal(trimmed, &payload); err != nil {
		return ""
	}
	if code := appleAccountAnyErrorCode(payload["errorCode"]); code != "" {
		return code
	}
	if code := appleAccountAnyErrorCode(payload["code"]); code != "" {
		return code
	}
	if errObj, ok := payload["error"].(map[string]any); ok {
		if code := appleAccountAnyErrorCode(errObj["errorCode"]); code != "" {
			return code
		}
		if code := appleAccountAnyErrorCode(errObj["code"]); code != "" {
			return code
		}
	}
	for _, key := range []string{"serviceErrors", "service_errors", "errors"} {
		list, ok := payload[key].([]any)
		if !ok || len(list) == 0 {
			continue
		}
		first, ok := list[0].(map[string]any)
		if !ok {
			continue
		}
		if code := appleAccountAnyErrorCode(first["code"]); code != "" {
			return code
		}
		if code := appleAccountAnyErrorCode(first["errorCode"]); code != "" {
			return code
		}
	}
	return ""
}

func appleAccountErrorDetail(status int, data []byte, stage string) string {
	stage = strings.TrimSpace(stage)
	if stage == "" {
		stage = "未知阶段"
	}
	detail := fmt.Sprintf("阶段：%s；HTTP %d", stage, status)
	if code := appleAccountSafeErrorCode(data); code != "" {
		detail += "；错误码：" + code
	}
	return detail
}

func appleAccountResponseDetail(stage string, data []byte) string {
	stage = strings.TrimSpace(stage)
	if stage == "" {
		stage = "未知阶段"
	}
	detail := "阶段：" + stage
	if code := appleAccountSafeErrorCode(data); code != "" {
		detail += "；错误码：" + code
	}
	return detail
}

func appleAccountRawResponseDetail(stage string, raw appleAccountRawResponse) string {
	if raw.StatusCode > 0 {
		return appleAccountErrorDetail(raw.StatusCode, raw.Body, stage)
	}
	return appleAccountResponseDetail(stage, raw.Body)
}

func appleAccountRequestStage(method, path string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = strings.TrimSpace(path)
	switch {
	case path == "/account/manage/gs/ws/token":
		return "刷新管理 token"
	case path == "/account/manage":
		return "读取管理入口"
	case path == "/account/manage/section/privacy":
		return "打开隐私页面"
	case path == "/bootstrap/portal":
		return "预热门户"
	case method == http.MethodPost && path == "/v2/jslogs":
		return "新接口保活"
	case method == http.MethodGet && path == "/account/manage/forwardemail":
		return "读取转发邮箱"
	case method == http.MethodGet && path == "/account/manage/email/private":
		return "读取隐私邮箱列表"
	case method == http.MethodPost && path == "/account/manage/email/private/add":
		return "生成候选隐私邮箱"
	case method == http.MethodPut && path == "/account/manage/email/private/add/complete":
		return "确认创建隐私邮箱"
	case method == http.MethodGet && strings.HasPrefix(path, "/account/manage/email/private/") && strings.HasSuffix(path, ".em"):
		return "确认隐私邮箱详情"
	case method == http.MethodDelete && strings.HasPrefix(path, "/account/manage/email/private/") && strings.HasSuffix(path, "/stop"):
		return "停用隐私邮箱"
	case method == http.MethodDelete && strings.HasPrefix(path, "/account/manage/email/private/") && strings.HasSuffix(path, "/remove"):
		return "删除隐私邮箱"
	default:
		return strings.TrimSpace(method + " " + path)
	}
}

func isCodedError(err error, code string) bool {
	var coded codedError
	return errors.As(err, &coded) && coded.code == code
}

func (c *ICloudClient) call(ctx context.Context, session ICloudSession, method, path string, body any, result any) error {
	var ok bool
	if session, ok = iCloudWebSessionForClient(session); !ok {
		return errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true)
	}
	u, err := c.endpoint(session, path)
	if err != nil {
		return err
	}
	return c.callEnvelope(ctx, session, method, u, body, result)
}

func (c *ICloudClient) callEnvelope(ctx context.Context, session ICloudSession, method, rawURL string, body any, result any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return err
	}
	contentType := "text/plain;charset=UTF-8"
	if body == nil {
		contentType = ""
	}
	setICloudFetchHeaders(req, session, "application/json", contentType)
	if cookie := cookieHeader(session.Cookies, rawURL); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	httpClient, err := httpClientWithProxy(c.client, session.ProxyURL)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		stage := iCloudHMERequestStage(rawURL)
		if looksLikeHTML(data) {
			return errCode("icloud_html_response", fmt.Sprintf("iCloud HTTP %d 返回了网页而不是接口结果；阶段：%s", resp.StatusCode, stage), true)
		}
		return errCode("icloud_http_error", fmt.Sprintf("iCloud HTTP %d；阶段：%s", resp.StatusCode, stage), true)
	}
	var envelope struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
		Error   *struct {
			Code    string `json:"errorCode"`
			Message string `json:"errorMessage"`
		} `json:"error"`
		Timestamp int64 `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return errCode("icloud_bad_response", "iCloud 返回无法解析", true)
	}
	if !envelope.Success {
		code := ""
		msg := "iCloud 接口返回失败"
		if envelope.Error != nil {
			code = strings.TrimSpace(envelope.Error.Code)
			if strings.TrimSpace(envelope.Error.Message) != "" {
				msg = envelope.Error.Message
			}
		}
		return iCloudAPIErrorAt(iCloudHMERequestStage(rawURL), code, msg)
	}
	if result != nil {
		if err := json.Unmarshal(envelope.Result, result); err != nil {
			return errCode("icloud_bad_result", "iCloud 结果无法解析", true)
		}
	}
	return nil
}

func iCloudAPIError(message string) error {
	return iCloudAPIErrorAt("", "", message)
}

func iCloudAPIErrorAt(stage, code, message string) error {
	message = strings.TrimSpace(message)
	if message == "" {
		message = "iCloud 接口返回失败"
	}
	if isICloudHMELimitMessage(message) {
		return errCode("icloud_hme_limit", "iCloud 已达到当前隐私邮箱创建上限，请稍后再试", true)
	}
	if isRemoteMailboxAlreadyInactive(errors.New(message)) || isICloudHMEAlreadyGoneMessage(message) {
		return errCode("icloud_api_failed", "iCloud 接口返回失败："+message, true)
	}
	safeCode := appleAccountSanitizeErrorCode(code)
	if isICloudHMEStillActive(safeCode, message) {
		detail := "iCloud 隐私邮箱仍在使用中，需要先停用"
		if strings.TrimSpace(stage) != "" {
			detail += "；阶段：" + strings.TrimSpace(stage)
		}
		if safeCode != "" {
			detail += "；错误码：" + safeCode
		}
		return errCode("icloud_hme_still_active", detail, true)
	}
	detail := "iCloud 接口返回失败"
	if strings.TrimSpace(stage) != "" {
		detail += "；阶段：" + strings.TrimSpace(stage)
	}
	if safeCode != "" {
		detail += "；错误码：" + safeCode
	}
	return errCode("icloud_api_failed", detail, true)
}

func isICloudHMEStillActive(code, message string) bool {
	compact := strings.TrimSpace(code)
	if compact == "-41000" || compact == "41000" {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(message))
	if strings.Contains(lower, "-41000") {
		return true
	}
	for _, token := range []string{
		"still active",
		"still in use",
		"must deactivate",
		"deactivate first",
		"deactivate before",
		"cannot delete an active",
		"cannot delete active",
		"needs to be deactivated",
		"need to deactivate",
	} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func iCloudHMERequestStage(rawURL string) string {
	path := rawURL
	if parsed, err := url.Parse(rawURL); err == nil {
		path = parsed.Path
	}
	switch {
	case strings.HasSuffix(path, "/v1/hme/deactivate"):
		return "停用隐私邮箱"
	case strings.HasSuffix(path, "/v1/hme/delete"):
		return "删除隐私邮箱"
	case strings.HasSuffix(path, "/v1/hme/reactivate"):
		return "重新启用隐私邮箱"
	case strings.HasSuffix(path, "/v2/hme/list"), strings.HasSuffix(path, "/v1/hme/list"):
		return "读取隐私邮箱列表"
	default:
		return "调用 iCloud 接口"
	}
}

func isICloudHMELimitMessage(message string) bool {
	normalized := strings.ToLower(strings.TrimSpace(message))
	return strings.Contains(normalized, "reached the limit of addresses") ||
		(strings.Contains(normalized, "limit") && strings.Contains(normalized, "try again later")) ||
		strings.Contains(message, "创建上限")
}

func (c *ICloudClient) SyncMailboxMessages(ctx context.Context, session ICloudSession, mailbox Mailbox, after time.Time, keyword string, maxThreads int) ([]ICloudSyncedMessage, error) {
	var ok bool
	if session, ok = iCloudWebSessionForClient(session); !ok || strings.TrimSpace(session.DSID) == "" {
		return nil, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true)
	}
	if strings.TrimSpace(mailbox.Email) == "" {
		return nil, errCode("mailbox_email_missing", "邮箱地址为空", false)
	}
	if maxThreads <= 0 || maxThreads > 50 {
		maxThreads = 20
	}
	if keyword = strings.TrimSpace(keyword); keyword == "" {
		keyword = "OpenAI"
	}
	queryAfter := mailboxSyncAfter(mailbox, after, time.Now())
	folders, err := c.mailFolders(ctx, session)
	if err != nil {
		return nil, err
	}
	folders = preferredMailFolders(folders)
	var out []ICloudSyncedMessage
	for _, folder := range folders {
		threads, err := c.searchThreads(ctx, session, folder, maxThreads)
		if err != nil {
			return out, err
		}
		for _, thread := range threads {
			if shouldSkipSyncedThread(thread, queryAfter) {
				continue
			}
			text := thread.Subject + "\n" + thread.Preview
			if !looksLikeVerificationText(text, keyword) {
				continue
			}
			messages, err := c.threadMessages(ctx, session, folder, thread.ThreadID, mailbox.Email, queryAfter)
			if err != nil {
				return out, err
			}
			out = append(out, messages...)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].ReceivedAt.After(out[j].ReceivedAt)
	})
	return out, nil
}

func (c *ICloudClient) SyncMailboxMessagesBatch(ctx context.Context, session ICloudSession, mailboxes []Mailbox, after time.Time, keyword string, maxThreads int) (map[string][]ICloudSyncedMessage, error) {
	var ok bool
	if session, ok = iCloudWebSessionForClient(session); !ok || strings.TrimSpace(session.DSID) == "" {
		return nil, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true)
	}
	if maxThreads <= 0 || maxThreads > 50 {
		maxThreads = 50
	}
	if keyword = strings.TrimSpace(keyword); keyword == "" {
		keyword = "OpenAI"
	}
	now := time.Now()
	aliases := make(map[string]string)
	afterByMailbox := make(map[string]time.Time)
	var queryAfter time.Time
	for _, mailbox := range mailboxes {
		email := strings.ToLower(strings.TrimSpace(mailbox.Email))
		if strings.TrimSpace(mailbox.ID) == "" || email == "" {
			continue
		}
		aliases[mailbox.ID] = email
		mailboxAfter := mailboxSyncAfter(mailbox, after, now)
		afterByMailbox[mailbox.ID] = mailboxAfter
		if queryAfter.IsZero() || mailboxAfter.Before(queryAfter) {
			queryAfter = mailboxAfter
		}
	}
	if len(aliases) == 0 {
		return map[string][]ICloudSyncedMessage{}, nil
	}
	folders, err := c.mailFolders(ctx, session)
	if err != nil {
		return nil, err
	}
	folders = preferredMailFolders(folders)
	out := make(map[string][]ICloudSyncedMessage, len(aliases))
	for _, folder := range folders {
		threads, err := c.searchThreads(ctx, session, folder, maxThreads)
		if err != nil {
			return out, err
		}
		for _, thread := range threads {
			if shouldSkipSyncedThread(thread, queryAfter) {
				continue
			}
			text := thread.Subject + "\n" + thread.Preview
			if !looksLikeVerificationText(text, keyword) {
				continue
			}
			messagesByMailbox, err := c.threadMessagesForAliases(ctx, session, folder, thread.ThreadID, aliases, afterByMailbox)
			if err != nil {
				return out, err
			}
			for mailboxID, messages := range messagesByMailbox {
				out[mailboxID] = append(out[mailboxID], messages...)
			}
		}
	}
	for mailboxID := range out {
		sort.SliceStable(out[mailboxID], func(i, j int) bool {
			return out[mailboxID][i].ReceivedAt.After(out[mailboxID][j].ReceivedAt)
		})
	}
	return out, nil
}

func mailboxSyncAfter(mailbox Mailbox, after time.Time, now time.Time) time.Time {
	queryAfter := after
	if !mailbox.LastSyncAt.IsZero() {
		cursor := mailbox.LastSyncAt.Add(-mailboxSyncCursorOverlap)
		if cursor.After(queryAfter) {
			queryAfter = cursor
		}
	}
	if queryAfter.After(now) {
		return now.Add(-mailboxSyncCursorOverlap)
	}
	return queryAfter
}

func shouldSkipSyncedThread(thread mailThread, after time.Time) bool {
	return !after.IsZero() && !thread.ReceivedAt.IsZero() && thread.ReceivedAt.Before(after)
}

func looksLikeVerificationText(text, keyword string) bool {
	if extractOTP(text) != "" {
		return true
	}
	needles := []string{"openai", "chatgpt", "code", "otp", "verification", "verify", "验证码", "验证", "代码"}
	if strings.TrimSpace(keyword) != "" {
		needles = append(needles, strings.ToLower(strings.TrimSpace(keyword)))
	}
	lower := strings.ToLower(text)
	for _, needle := range needles {
		if needle != "" && strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func (c *ICloudClient) CheckMailSession(ctx context.Context, session ICloudSession) error {
	var ok bool
	if session, ok = iCloudWebSessionForClient(session); !ok || strings.TrimSpace(session.DSID) == "" {
		return errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true)
	}
	if _, err := mailGatewayBaseURL(session); err != nil {
		return err
	}
	_, err := c.mailFolders(ctx, session)
	return err
}

type mailFolder struct {
	ID           string `json:"identifier"`
	Name         string `json:"name"`
	MessageCount int    `json:"messageCount"`
}

type mailThread struct {
	ThreadID   string
	Subject    string
	Preview    string
	ReceivedAt time.Time
}

func (c *ICloudClient) mailFolders(ctx context.Context, session ICloudSession) ([]mailFolder, error) {
	var out struct {
		DomainObjects []mailFolder `json:"domainObjects"`
	}
	body := map[string]any{
		"domain":        "mailbox",
		"includeLabels": true,
		"predicate": map[string]any{
			"type": "eq",
			"expression": map[string]any{
				"type":     "property",
				"property": "isMboxDeleted",
			},
			"value": false,
		},
		"properties": []string{"identifier", "name", "uidValidity", "unseenCount", "seenDeletedCount", "unseenDeletedCount", "messageCount", "flags"},
	}
	if err := c.callMail(ctx, session, "/mailws2/v1/geqs/query", body, "fetchMailboxCountQuery", &out); err != nil {
		return nil, err
	}
	return out.DomainObjects, nil
}

func preferredMailFolders(folders []mailFolder) []mailFolder {
	if len(folders) == 0 {
		return []mailFolder{{Name: "INBOX"}}
	}
	var out []mailFolder
	seen := map[string]bool{}
	add := func(folder mailFolder) {
		name := strings.TrimSpace(folder.Name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, folder)
	}
	for _, folder := range folders {
		if folder.Name == "INBOX" || strings.HasPrefix(folder.Name, "INBOX/$category$_") {
			add(folder)
		}
	}
	for _, folder := range folders {
		if folder.MessageCount > 0 && !strings.Contains(folder.Name, "Deleted") && folder.Name != "Sent Messages" && folder.Name != "Drafts" {
			add(folder)
		}
	}
	if len(out) == 0 {
		out = append(out, mailFolder{Name: "INBOX"})
	}
	return out
}

func (c *ICloudClient) searchThreads(ctx context.Context, session ICloudSession, folder mailFolder, maxThreads int) ([]mailThread, error) {
	var out struct {
		ThreadList []struct {
			ThreadID  string          `json:"threadId"`
			Subject   string          `json:"subject"`
			Preview   string          `json:"preview"`
			Timestamp json.RawMessage `json:"timestamp"`
		} `json:"threadList"`
	}
	body := map[string]any{
		"responseType":        "THREAD_DIGEST",
		"includeFolderStatus": false,
		"maxResults":          maxThreads,
		"sessionHeaders":      mailSessionHeaders(folder.Name, false),
	}
	if err := c.callMail(ctx, session, "/mailws2/v1/thread/search", body, "", &out); err != nil {
		return nil, err
	}
	threads := make([]mailThread, 0, len(out.ThreadList))
	for _, item := range out.ThreadList {
		threads = append(threads, mailThread{
			ThreadID:   item.ThreadID,
			Subject:    item.Subject,
			Preview:    item.Preview,
			ReceivedAt: parseMailTime(item.Timestamp),
		})
	}
	return threads, nil
}

func (c *ICloudClient) threadMessages(ctx context.Context, session ICloudSession, folder mailFolder, threadID, alias string, after time.Time) ([]ICloudSyncedMessage, error) {
	messagesByAlias, err := c.threadMessagesForAliases(ctx, session, folder, threadID, map[string]string{"single": alias}, map[string]time.Time{"single": after})
	if err != nil {
		return nil, err
	}
	return messagesByAlias["single"], nil
}

func (c *ICloudClient) threadMessagesForAliases(ctx context.Context, session ICloudSession, folder mailFolder, threadID string, aliases map[string]string, afterByMailbox map[string]time.Time) (map[string][]ICloudSyncedMessage, error) {
	var out struct {
		MessageMetadataList []struct {
			UID       json.RawMessage `json:"uid"`
			Folder    string          `json:"folder"`
			MessageID string          `json:"messageId"`
			Subject   string          `json:"subject"`
			Preview   string          `json:"preview"`
			Date      json.RawMessage `json:"date"`
			From      json.RawMessage `json:"from"`
			To        json.RawMessage `json:"to"`
			CC        json.RawMessage `json:"cc"`
			BCC       json.RawMessage `json:"bcc"`
			Parts     []struct {
				PartID      string `json:"partId"`
				ContentType string `json:"contentType"`
				IsAttach    bool   `json:"isAttach"`
				FileName    string `json:"fileName"`
				Disposition string `json:"disposition"`
			} `json:"parts"`
		} `json:"messageMetadataList"`
	}
	body := map[string]any{
		"threadId":       threadID,
		"sessionHeaders": mailSessionHeaders(folder.Name, false),
	}
	if err := c.callMail(ctx, session, "/mailws2/v1/thread/get", body, "", &out); err != nil {
		return nil, err
	}
	messages := make(map[string][]ICloudSyncedMessage)
	for _, meta := range out.MessageMetadataList {
		uid := rawScalarString(meta.UID)
		if uid == "" {
			continue
		}
		receivedAt := firstNonZeroTime(parseMailTime(meta.Date), time.Now())
		folderName := firstNonEmpty(cleanMailFolder(meta.Folder), folder.Name)
		from := addressSummary(meta.From)
		recipients := string(meta.To) + "\n" + string(meta.CC) + "\n" + string(meta.BCC)
		bodyText := meta.Subject + "\n" + meta.Preview
		partIDs := textPartIDs(meta.Parts)
		if len(partIDs) > 0 {
			detail, err := c.messageBody(ctx, session, folderName, uid, partIDs)
			if err != nil {
				return messages, err
			}
			recipients += "\n" + detail.LongHeader
			bodyText += "\n" + detail.Body
		}
		matchedMailboxIDs := matchingMailboxIDs(recipients, aliases)
		if len(matchedMailboxIDs) == 0 {
			continue
		}
		message := ICloudSyncedMessage{
			RemoteID:   "icloud:" + folderName + ":" + uid,
			UID:        uid,
			Subject:    meta.Subject,
			From:       from,
			Body:       normalizeMailBody(bodyText),
			ReceivedAt: receivedAt,
		}
		for _, mailboxID := range matchedMailboxIDs {
			after := afterByMailbox[mailboxID]
			if !after.IsZero() && receivedAt.Before(after) {
				continue
			}
			messages[mailboxID] = append(messages[mailboxID], message)
		}
	}
	return messages, nil
}

func matchingMailboxIDs(recipients string, aliases map[string]string) []string {
	if len(aliases) == 0 {
		return nil
	}
	var ids []string
	for mailboxID, alias := range aliases {
		if strings.TrimSpace(mailboxID) == "" || strings.TrimSpace(alias) == "" {
			continue
		}
		if containsFold(recipients, alias) {
			ids = append(ids, mailboxID)
		}
	}
	sort.Strings(ids)
	return ids
}

type mailMessageDetail struct {
	LongHeader string
	Body       string
}

func (c *ICloudClient) messageBody(ctx context.Context, session ICloudSession, folderName, uid string, partIDs []string) (mailMessageDetail, error) {
	var out struct {
		LongHeader string `json:"longHeader"`
		Parts      []struct {
			GUID    string `json:"guid"`
			Content string `json:"content"`
		} `json:"parts"`
	}
	body := map[string]any{
		"uid":            uid,
		"parts":          partIDs,
		"dontMarkAsRead": true,
		"sessionHeaders": mailSessionHeaders(folderName, false),
	}
	if err := c.callMail(ctx, session, "/mailws2/v1/message/get", body, "", &out); err != nil {
		return mailMessageDetail{}, err
	}
	var parts []string
	for _, part := range out.Parts {
		parts = append(parts, part.Content)
	}
	return mailMessageDetail{LongHeader: out.LongHeader, Body: strings.Join(parts, "\n")}, nil
}

func (c *ICloudClient) MoveRemoteMessagesToTrash(ctx context.Context, session ICloudSession, remoteIDs []string) (ICloudMailCleanupResult, error) {
	var result ICloudMailCleanupResult
	var ok bool
	if session, ok = iCloudWebSessionForClient(session); !ok || strings.TrimSpace(session.DSID) == "" {
		return result, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true)
	}
	folders, err := c.mailFolders(ctx, session)
	if err != nil {
		return result, err
	}
	trash, ok := trashMailFolder(folders)
	if !ok || strings.TrimSpace(trash.ID) == "" {
		return result, errCode("icloud_trash_not_found", "未找到 iCloud 废纸篓文件夹", true)
	}

	byFolder := make(map[string][]string)
	for _, remoteID := range remoteIDs {
		folderName, uid, ok := parseICloudRemoteID(remoteID)
		if !ok {
			result.Skipped++
			continue
		}
		if strings.EqualFold(folderName, trash.Name) {
			result.Skipped++
			continue
		}
		byFolder[folderName] = append(byFolder[folderName], uid)
	}
	for folderName, uids := range byFolder {
		folder, ok := findMailFolderByName(folders, folderName)
		if !ok || strings.TrimSpace(folder.ID) == "" {
			result.Skipped += len(uids)
			continue
		}
		ids, err := c.mailMessageIdentifiers(ctx, session, folder, uids)
		if err != nil {
			return result, err
		}
		for _, uid := range uniqueStrings(uids) {
			if strings.TrimSpace(ids[uid]) == "" {
				result.Skipped++
			}
		}
		moved, err := c.moveMailIdentifiersToTrash(ctx, session, mapValues(ids), trash.ID)
		result.MovedToTrash += moved
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func (c *ICloudClient) EmptyTrash(ctx context.Context, session ICloudSession) (int, error) {
	var ok bool
	if session, ok = iCloudWebSessionForClient(session); !ok || strings.TrimSpace(session.DSID) == "" {
		return 0, errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true)
	}
	folders, err := c.mailFolders(ctx, session)
	if err != nil {
		return 0, err
	}
	trash, ok := trashMailFolder(folders)
	if !ok || strings.TrimSpace(trash.ID) == "" {
		return 0, errCode("icloud_trash_not_found", "未找到 iCloud 废纸篓文件夹", true)
	}

	total := 0
	for i := 0; i < 20; i++ {
		ids, err := c.mailFolderMessageIdentifiers(ctx, session, trash, 1000)
		if err != nil {
			return total, err
		}
		if len(ids) == 0 {
			return total, nil
		}
		destroyed, err := c.destroyMailIdentifiers(ctx, session, ids)
		total += destroyed
		if err != nil {
			return total, err
		}
		if len(ids) < 1000 {
			return total, nil
		}
	}
	return total, errCode("icloud_trash_not_empty", "废纸篓邮件过多，本次已分批清理一部分，请再点一次", true)
}

type mailEmailObject struct {
	UID        json.RawMessage `json:"uid"`
	Identifier string          `json:"identifier"`
	MboxRef    struct {
		ID string `json:"id"`
	} `json:"mboxRef"`
}

func (c *ICloudClient) mailMessageIdentifiers(ctx context.Context, session ICloudSession, folder mailFolder, uids []string) (map[string]string, error) {
	out := make(map[string]string)
	for _, chunk := range chunkStrings(uniqueStrings(uids), 200) {
		var resp struct {
			DomainObjects []mailEmailObject `json:"domainObjects"`
		}
		body := map[string]any{
			"domain": "email",
			"predicate": map[string]any{
				"type":       "in",
				"expression": map[string]any{"property": "uid"},
				"value":      mailUIDValues(chunk),
				"and": []any{
					map[string]any{
						"type": "eq",
						"expression": map[string]any{
							"type":     "fieldOf",
							"property": "flags",
							"value":    "DELETED",
						},
						"value": false,
					},
					map[string]any{
						"type":       "eq",
						"expression": map[string]any{"property": "mboxRef"},
						"value":      folder.ID,
					},
				},
			},
			"properties": []string{"uid", "identifier", "mboxRef"},
		}
		if err := c.callMail(ctx, session, "/mailws2/v1/message/list", body, "", &resp); err != nil {
			return out, err
		}
		for _, item := range resp.DomainObjects {
			uid := rawScalarString(item.UID)
			identifier := strings.TrimSpace(item.Identifier)
			if uid == "" || identifier == "" {
				continue
			}
			out[uid] = identifier
		}
	}
	return out, nil
}

func (c *ICloudClient) mailFolderMessageIdentifiers(ctx context.Context, session ICloudSession, folder mailFolder, limit int) ([]string, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var resp struct {
		DomainObjects []mailEmailObject `json:"domainObjects"`
	}
	body := map[string]any{
		"domain":     "email",
		"properties": []string{"uid", "identifier", "stateInternalDate", "mboxRef"},
		"limit":      limit,
		"predicate": map[string]any{
			"type":       "eq",
			"expression": map[string]any{"property": "mboxRef"},
			"value":      folder.ID,
			"and": []any{
				map[string]any{
					"type": "eq",
					"expression": map[string]any{
						"type":     "fieldOf",
						"property": "flags",
						"value":    "DELETED",
					},
					"value": false,
				},
			},
		},
		"orderby": map[string]any{
			"expressions": []any{map[string]any{"property": "stateInternalDate", "type": "property"}},
			"ascending":   false,
		},
	}
	if err := c.callMail(ctx, session, "/mailws2/v1/message/list", body, "", &resp); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(resp.DomainObjects))
	for _, item := range resp.DomainObjects {
		if identifier := strings.TrimSpace(item.Identifier); identifier != "" {
			ids = append(ids, identifier)
		}
	}
	return ids, nil
}

type mailSetResponse struct {
	Updated      map[string]json.RawMessage `json:"updated"`
	Destroyed    []string                   `json:"destroyed"`
	NotUpdated   map[string]json.RawMessage `json:"notUpdated"`
	NotDestroyed map[string]json.RawMessage `json:"notDestroyed"`
}

func (c *ICloudClient) moveMailIdentifiersToTrash(ctx context.Context, session ICloudSession, identifiers []string, trashFolderID string) (int, error) {
	identifiers = uniqueStrings(identifiers)
	if len(identifiers) == 0 {
		return 0, nil
	}
	moved := 0
	for _, chunk := range chunkStrings(identifiers, 200) {
		var resp mailSetResponse
		body := map[string]any{
			"domain": "email",
			"batchUpdate": []any{
				map[string]any{
					"ids": chunk,
					"patch": map[string]any{
						"flags":   map[string]any{"set": []string{"seen"}},
						"mboxRef": map[string]any{"replace": []string{trashFolderID}},
					},
				},
			},
		}
		if err := c.callMail(ctx, session, "/mailws2/v1/email/set", body, "", &resp); err != nil {
			return moved, err
		}
		if len(resp.NotUpdated) > 0 {
			return moved + len(resp.Updated), fmt.Errorf("icloud mail move notUpdated=%d", len(resp.NotUpdated))
		}
		if len(resp.Updated) > 0 {
			moved += len(resp.Updated)
		} else {
			moved += len(chunk)
		}
	}
	return moved, nil
}

func (c *ICloudClient) destroyMailIdentifiers(ctx context.Context, session ICloudSession, identifiers []string) (int, error) {
	identifiers = uniqueStrings(identifiers)
	if len(identifiers) == 0 {
		return 0, nil
	}
	destroyed := 0
	for _, chunk := range chunkStrings(identifiers, 200) {
		var resp mailSetResponse
		body := map[string]any{
			"domain":  "email",
			"destroy": chunk,
		}
		if err := c.callMail(ctx, session, "/mailws2/v1/email/set", body, "", &resp); err != nil {
			return destroyed, err
		}
		if len(resp.NotDestroyed) > 0 {
			return destroyed + len(resp.Destroyed), fmt.Errorf("icloud mail destroy notDestroyed=%d", len(resp.NotDestroyed))
		}
		if len(resp.Destroyed) > 0 {
			destroyed += len(resp.Destroyed)
		} else {
			destroyed += len(chunk)
		}
	}
	return destroyed, nil
}

func parseICloudRemoteID(remoteID string) (string, string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(remoteID), "icloud:")
	if !ok {
		return "", "", false
	}
	folderName, uid, ok := strings.Cut(rest, ":")
	if !ok || strings.TrimSpace(folderName) == "" || strings.TrimSpace(uid) == "" {
		return "", "", false
	}
	return strings.TrimSpace(folderName), strings.TrimSpace(uid), true
}

func findMailFolderByName(folders []mailFolder, name string) (mailFolder, bool) {
	name = strings.TrimSpace(name)
	for _, folder := range folders {
		if strings.EqualFold(strings.TrimSpace(folder.Name), name) {
			return folder, true
		}
	}
	return mailFolder{}, false
}

func trashMailFolder(folders []mailFolder) (mailFolder, bool) {
	for _, folder := range folders {
		name := strings.ToLower(strings.TrimSpace(folder.Name))
		if name == "deleted messages" || name == "trash" || strings.Contains(name, "deleted") || strings.Contains(name, "trash") || strings.Contains(name, "废纸") {
			return folder, true
		}
	}
	return mailFolder{}, false
}

func mailUIDValues(uids []string) []any {
	out := make([]any, 0, len(uids))
	for _, uid := range uids {
		uid = strings.TrimSpace(uid)
		if uid == "" {
			continue
		}
		if n, err := strconv.Atoi(uid); err == nil {
			out = append(out, n)
			continue
		}
		out = append(out, uid)
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func chunkStrings(values []string, size int) [][]string {
	if size <= 0 {
		size = len(values)
	}
	var chunks [][]string
	for len(values) > 0 {
		n := size
		if len(values) < n {
			n = len(values)
		}
		chunks = append(chunks, values[:n])
		values = values[n:]
	}
	return chunks
}

func (c *ICloudClient) callMail(ctx context.Context, session ICloudSession, path string, body any, clientIntent string, result any) error {
	var ok bool
	if session, ok = iCloudWebSessionForClient(session); !ok {
		return errCode("icloud_session_missing", "未保存 iCloud 登录态，请先协议登录", true)
	}
	base, err := mailGatewayBaseURL(session)
	if err != nil {
		return err
	}
	u, err := c.endpointWithBase(session, base, path)
	if err != nil {
		return err
	}
	if clientIntent != "" {
		parsed, _ := url.Parse(u)
		q := parsed.Query()
		q.Set("clientIntent", clientIntent)
		parsed.RawQuery = q.Encode()
		u = parsed.String()
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, reader)
	if err != nil {
		return err
	}
	if clientIntent != "" {
		req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	setICloudFetchHeaders(req, session, "*/*", req.Header.Get("Content-Type"))
	if cookie := cookieHeader(session.Cookies, u); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	httpClient, err := httpClientWithProxy(c.client, session.ProxyURL)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errCode("icloud_mail_http_error", fmt.Sprintf("iCloud 邮件接口 HTTP %d", resp.StatusCode), true)
	}
	if result != nil {
		if err := json.Unmarshal(data, result); err != nil {
			return errCode("icloud_mail_bad_response", "iCloud 邮件返回无法解析", true)
		}
	}
	return nil
}

func (c *ICloudClient) endpoint(session ICloudSession, path string) (string, error) {
	return c.endpointWithBase(session, session.PremiumMailBaseURL, path)
}

func (c *ICloudClient) endpointWithBase(session ICloudSession, baseURL, path string) (string, error) {
	base, err := url.Parse(strings.TrimRight(baseURL, "/") + "/")
	if err != nil {
		return "", err
	}
	rel, err := url.Parse(strings.TrimLeft(path, "/"))
	if err != nil {
		return "", err
	}
	if rel.IsAbs() || rel.Host != "" {
		return "", errCode("icloud_invalid_endpoint", "iCloud 接口路径无效", false)
	}
	u := base.ResolveReference(rel)
	q := u.Query()
	q.Set("clientBuildNumber", firstNonEmpty(session.ClientBuildNumber, "2622Build20"))
	q.Set("clientMasteringNumber", firstNonEmpty(session.MasteringNumber, session.ClientBuildNumber, "2622Build20"))
	q.Set("clientId", firstNonEmpty(session.ClientID, "local-panel"))
	q.Set("dsid", session.DSID)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func mailGatewayBaseURL(session ICloudSession) (string, error) {
	if strings.TrimSpace(session.MailGatewayBaseURL) != "" {
		return strings.TrimRight(strings.TrimSpace(session.MailGatewayBaseURL), "/"), nil
	}
	if strings.TrimSpace(session.MailBaseURL) != "" {
		base := strings.TrimRight(strings.TrimSpace(session.MailBaseURL), "/")
		base = strings.Replace(base, "-mailws.", "-mccgateway.", 1)
		return base, nil
	}
	if strings.TrimSpace(session.PremiumMailBaseURL) != "" {
		base := strings.TrimRight(strings.TrimSpace(session.PremiumMailBaseURL), "/")
		base = strings.Replace(base, "-maildomainws.", "-mccgateway.", 1)
		return base, nil
	}
	return "", errCode("icloud_mail_missing", "未保存 iCloud 邮件服务地址，请重新保存登录态", true)
}

func mailSessionHeaders(folder string, reset bool) map[string]any {
	headers := map[string]any{
		"folder":       folder,
		"modseq":       nil,
		"threadmodseq": nil,
		"condstore":    1,
		"qresync":      1,
		"threadmode":   1,
	}
	if reset {
		headers["modseq"] = nil
		headers["threadmodseq"] = nil
	}
	return headers
}

func textPartIDs(parts []struct {
	PartID      string `json:"partId"`
	ContentType string `json:"contentType"`
	IsAttach    bool   `json:"isAttach"`
	FileName    string `json:"fileName"`
	Disposition string `json:"disposition"`
}) []string {
	var ids []string
	for _, part := range parts {
		if part.PartID == "" || part.IsAttach || part.FileName != "" {
			continue
		}
		contentType := strings.ToLower(part.ContentType)
		if strings.Contains(contentType, "text/plain") || strings.Contains(contentType, "text/html") {
			ids = append(ids, strings.TrimSpace(part.PartID))
		}
	}
	return ids
}

func parseMailTime(raw json.RawMessage) time.Time {
	value := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if value == "" || value == "null" {
		return time.Time{}
	}
	if n, err := strconv.ParseInt(value, 10, 64); err == nil {
		if n > 1_000_000_000_000 {
			return time.UnixMilli(n)
		}
		if n > 1_000_000_000 {
			return time.Unix(n, 0)
		}
	}
	if f, err := strconv.ParseFloat(value, 64); err == nil {
		n := int64(f)
		if n > 1_000_000_000_000 {
			return time.UnixMilli(n)
		}
		if n > 1_000_000_000 {
			return time.Unix(n, 0)
		}
	}
	for _, layout := range []string{time.RFC3339, time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822} {
		if t, err := time.Parse(layout, value); err == nil {
			return t
		}
	}
	return time.Time{}
}

func rawScalarString(raw json.RawMessage) string {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return strings.TrimSpace(text)
	}
	var number json.Number
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err == nil {
		return number.String()
	}
	return strings.Trim(strings.TrimSpace(string(raw)), `"`)
}

func addressSummary(raw json.RawMessage) string {
	var values []any
	if err := json.Unmarshal(raw, &values); err != nil {
		return strings.Trim(strings.TrimSpace(string(raw)), `"`)
	}
	var out []string
	for _, value := range values {
		switch v := value.(type) {
		case string:
			out = append(out, v)
		case map[string]any:
			email, _ := v["email"].(string)
			name, _ := v["name"].(string)
			out = append(out, strings.TrimSpace(name+" <"+email+">"))
		}
	}
	return strings.Join(out, ", ")
}

func cleanMailFolder(value string) string {
	value = strings.TrimSpace(value)
	if idx := strings.Index(value, ":"); idx >= 0 && idx+1 < len(value) {
		return value[idx+1:]
	}
	return value
}

func containsFold(text, needle string) bool {
	return strings.Contains(strings.ToLower(text), strings.ToLower(strings.TrimSpace(needle)))
}

var htmlTagRegex = regexp.MustCompile(`<[^>]+>`)

func normalizeMailBody(value string) string {
	value = html.UnescapeString(value)
	value = htmlTagRegex.ReplaceAllString(value, " ")
	value = strings.Join(strings.Fields(value), " ")
	return value
}

func cookieHeader(cookies []SessionCookie, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	nowUnix := float64(time.Now().Unix())
	type cookiePair struct {
		name  string
		value string
		order int
		index int
	}
	var pairs []cookiePair
	for i, cookie := range cookies {
		if cookie.Name == "" || cookie.Value == "" {
			continue
		}
		if cookie.Expires > 0 && cookie.Expires < nowUnix {
			continue
		}
		if !cookieDomainMatch(host, cookie.Domain) {
			continue
		}
		if cookie.Path != "" && !strings.HasPrefix(path, cookie.Path) {
			continue
		}
		pairs = append(pairs, cookiePair{
			name:  cookie.Name,
			value: cookie.Value,
			order: preferredICloudCookieOrder(cookie.Name),
			index: i,
		})
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].order != pairs[j].order {
			return pairs[i].order < pairs[j].order
		}
		return pairs[i].index < pairs[j].index
	})
	out := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		out = append(out, pair.name+"="+pair.value)
	}
	return strings.Join(out, "; ")
}

func mergeSessionCookies(cookies *[]SessionCookie, requestURL *url.URL, setCookies []*http.Cookie) {
	if cookies == nil {
		return
	}
	for _, c := range setCookies {
		domain := strings.TrimSpace(c.Domain)
		if domain == "" && requestURL != nil {
			domain = requestURL.Hostname()
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		next := SessionCookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   domain,
			Path:     path,
			Secure:   c.Secure,
			HTTPOnly: c.HttpOnly,
		}
		if !c.Expires.IsZero() {
			next.Expires = float64(c.Expires.Unix())
		}
		replaced := false
		for i, old := range *cookies {
			if old.Name == next.Name && strings.EqualFold(strings.TrimPrefix(old.Domain, "."), strings.TrimPrefix(next.Domain, ".")) && old.Path == next.Path {
				if next.Value == "" {
					*cookies = append((*cookies)[:i], (*cookies)[i+1:]...)
				} else {
					(*cookies)[i] = next
				}
				replaced = true
				break
			}
		}
		if !replaced && next.Value != "" {
			*cookies = append(*cookies, next)
		}
	}
}

func preferredICloudCookieOrder(name string) int {
	for i, candidate := range preferredICloudCookies {
		if candidate == "X_APPLE_WEB_KB-" && strings.HasPrefix(name, candidate) {
			return i
		}
		if candidate != "X_APPLE_WEB_KB-" && name == candidate {
			return i
		}
	}
	return len(preferredICloudCookies) + 100
}

var preferredICloudCookies = []string{
	"X-APPLE-UNIQUE-CLIENT-ID",
	"X-APPLE-WEBAUTH-USER",
	"X_APPLE_WEB_KB-",
	"X-Apple-GCBD-Cookie",
	"X-APPLE-WEBAUTH-HSA-TRUST",
	"X-APPLE-WEBAUTH-PCS-Documents",
	"X-APPLE-WEBAUTH-PCS-Photos",
	"X-APPLE-WEBAUTH-PCS-Cloudkit",
	"X-APPLE-WEBAUTH-PCS-Safari",
	"X-APPLE-WEBAUTH-PCS-Mail",
	"X-APPLE-WEBAUTH-PCS-Notes",
	"X-APPLE-WEBAUTH-PCS-News",
	"X-APPLE-WEBAUTH-PCS-Sharing",
	"X-APPLE-WEBAUTH-LOGIN",
	"X-APPLE-DS-WEB-SESSION-TOKEN",
	"X-APPLE-WEB-ID",
	"X-APPLE-WEBAUTH-VALIDATE",
	"X-APPLE-WEBAUTH-TOKEN",
}

func cookieDomainMatch(host, domain string) bool {
	domain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return false
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func trimForError(data []byte) string {
	text := strings.TrimSpace(string(data))
	if len(text) > 240 {
		return text[:240] + "..."
	}
	return text
}

func appleDebugBody(data []byte) string {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return ""
	}
	var value any
	if err := json.Unmarshal(trimmed, &value); err == nil {
		redacted := redactAppleDebugJSON(value)
		var buf bytes.Buffer
		encoder := json.NewEncoder(&buf)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(redacted); err == nil {
			return trimForError(bytes.TrimSpace(buf.Bytes()))
		}
	}
	return trimForError(trimmed)
}

func redactAppleDebugJSON(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			if appleDebugSecretKey(key) {
				out[key] = "<redacted>"
				continue
			}
			out[key] = redactAppleDebugJSON(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactAppleDebugJSON(item)
		}
		return out
	default:
		return value
	}
}

func appleDebugSecretKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, marker := range []string{"apikey", "api_key", "token", "secret", "password", "scnt", "session", "email", "accountname", "appleid", "dsid"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func setICloudFetchHeaders(req *http.Request, session ICloudSession, accept, contentType string) {
	if strings.TrimSpace(accept) == "" {
		accept = "*/*"
	}
	req.Header.Set("Accept", accept)
	if strings.TrimSpace(contentType) != "" {
		req.Header.Set("Content-Type", contentType)
	}
	origin := iCloudOrigin(session)
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
	req.Header.Set("Sec-CH-UA", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36")
}

func iCloudOrigin(session ICloudSession) string {
	host := strings.ToLower(session.Host)
	if strings.Contains(host, "icloud.com.cn") {
		return "https://www.icloud.com.cn"
	}
	return "https://www.icloud.com"
}
