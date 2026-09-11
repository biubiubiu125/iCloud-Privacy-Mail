package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
)

type FileStore struct {
	mu    sync.Mutex
	path  string
	state State
}

type DeleteUserResult struct {
	UserID         string `json:"user_id"`
	Username       string `json:"username"`
	Accounts       int    `json:"accounts"`
	Mailboxes      int    `json:"mailboxes"`
	Messages       int    `json:"messages"`
	ICloudSessions int    `json:"icloud_sessions"`
	WebSessions    int    `json:"web_sessions"`
}

func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		path = filepath.Join("data", "state.json")
	}
	s := &FileStore{path: path, state: State{NextID: 1}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s.saveLocked()
		}
		return err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return s.saveLocked()
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return err
	}
	if s.state.NextID <= 0 {
		s.state.NextID = 1
	}
	changed := s.migrateLegacyMailboxAccountIDsLocked()
	if s.migrateLegacyICloudSessionLocked() {
		changed = true
	}
	if s.normalizeInterruptedRemoteDeletesLocked() {
		changed = true
	}
	if changed {
		return s.saveLocked()
	}
	if err := restrictFilePermissions(s.path, 0o600); err != nil {
		return fmt.Errorf("restrict state file permissions: %w", err)
	}
	return nil
}

func (s *FileStore) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneState(s.state)
}

func (s *FileStore) SnapshotForOwner(ownerID string) State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return filterStateByOwnerLocked(s.state, strings.TrimSpace(ownerID))
}

func (s *FileStore) SnapshotForGlobal() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return filterStateByOwnerLocked(s.state, "__global")
}

func (s *FileStore) CreateSettingsForOwner(ownerID string) CreateSettings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return createSettingsForOwnerLocked(s.state, strings.TrimSpace(ownerID))
}

func (s *FileStore) SaveCreateSettingsForOwner(ownerID string, settings CreateSettings) (CreateSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	settings = normalizeCreateSettings(ownerID, settings)
	settings.UpdatedAt = time.Now()
	previousSettings := cloneCreateSettings(s.state.CreateSettings)
	for i := range s.state.CreateSettings {
		if constantTimeEqual(ownerID, s.state.CreateSettings[i].OwnerID) {
			s.state.CreateSettings[i] = settings
			if err := s.saveLocked(); err != nil {
				s.state.CreateSettings = previousSettings
				return CreateSettings{}, errCode("create_settings_persist_failed", "创建配置写入失败："+err.Error(), true)
			}
			return settings, nil
		}
	}
	s.state.CreateSettings = append(s.state.CreateSettings, settings)
	if err := s.saveLocked(); err != nil {
		s.state.CreateSettings = previousSettings
		return CreateSettings{}, errCode("create_settings_persist_failed", "创建配置写入失败："+err.Error(), true)
	}
	return settings, nil
}

func (s *FileStore) Users() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]User(nil), s.state.Users...)
}

func (s *FileStore) CreateUser(username, password string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	username = normalizeUsername(username)
	if err := validateUsername(username); err != nil {
		return User{}, err
	}
	if err := validatePassword(password); err != nil {
		return User{}, err
	}
	for _, user := range s.state.Users {
		if strings.EqualFold(user.Username, username) {
			return User{}, errCode("user_exists", "账号已存在", false)
		}
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	now := time.Now()
	user := User{
		ID:           s.nextIDLocked("usr"),
		Username:     username,
		PasswordHash: passwordHash,
		IsAdmin:      len(s.state.Users) == 0,
		Status:       StatusActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	previousUsers := append([]User(nil), s.state.Users...)
	previousNextID := s.state.NextID
	s.state.Users = append(s.state.Users, user)
	if err := s.saveLocked(); err != nil {
		s.state.Users = previousUsers
		s.state.NextID = previousNextID
		return User{}, errCode("user_create_persist_failed", "账号写入失败："+err.Error(), true)
	}
	return user, nil
}

func (s *FileStore) AuthenticateUser(username, password string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	username = normalizeUsername(username)
	for i, user := range s.state.Users {
		if !strings.EqualFold(user.Username, username) {
			continue
		}
		if user.Status != StatusActive {
			return User{}, errCode("user_disabled", "账号已停用", false)
		}
		if !verifyPassword(password, user.PasswordHash) {
			return User{}, errCode("invalid_login", "账号或密码错误", false)
		}
		now := time.Now()
		previousUser := s.state.Users[i]
		s.state.Users[i].LastLoginAt = now
		s.state.Users[i].UpdatedAt = now
		if err := s.saveLocked(); err != nil {
			s.state.Users[i] = previousUser
			return User{}, errCode("user_login_persist_failed", "登录时间写入失败："+err.Error(), true)
		}
		return s.state.Users[i], nil
	}
	return User{}, errCode("invalid_login", "账号或密码错误", false)
}

func (s *FileStore) UserByID(id string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.userByIDLocked(id)
}

func (s *FileStore) DeleteUser(id string) (DeleteUserResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return DeleteUserResult{}, errCode("user_not_found", "账号不存在", false)
	}
	idx := -1
	var user User
	for i, candidate := range s.state.Users {
		if candidate.ID == id {
			idx = i
			user = candidate
			break
		}
	}
	if idx < 0 {
		return DeleteUserResult{}, errCode("user_not_found", "账号不存在", false)
	}
	if user.IsAdmin {
		return DeleteUserResult{}, errCode("cannot_delete_admin_user", "不能删除管理员账号", false)
	}

	previousState := cloneStateForRollback(s.state)
	result := DeleteUserResult{
		UserID:   user.ID,
		Username: user.Username,
	}
	s.state.Users = append(s.state.Users[:idx], s.state.Users[idx+1:]...)

	accounts := s.state.Accounts[:0]
	for _, account := range s.state.Accounts {
		if constantTimeEqual(id, account.OwnerID) {
			result.Accounts++
			continue
		}
		accounts = append(accounts, account)
	}
	s.state.Accounts = accounts

	deletedMailboxIDs := make(map[string]struct{})
	mailboxes := s.state.Mailboxes[:0]
	for _, mailbox := range s.state.Mailboxes {
		if constantTimeEqual(id, mailbox.OwnerID) {
			result.Mailboxes++
			deletedMailboxIDs[mailbox.ID] = struct{}{}
			continue
		}
		mailboxes = append(mailboxes, mailbox)
	}
	s.state.Mailboxes = mailboxes

	messages := s.state.Messages[:0]
	for _, msg := range s.state.Messages {
		_, mailboxDeleted := deletedMailboxIDs[msg.MailboxID]
		if mailboxDeleted || constantTimeEqual(id, msg.OwnerID) {
			result.Messages++
			continue
		}
		messages = append(messages, msg)
	}
	s.state.Messages = messages

	icloudSessions := s.state.ICloudSessions[:0]
	for _, session := range s.state.ICloudSessions {
		if constantTimeEqual(id, session.OwnerID) {
			result.ICloudSessions++
			continue
		}
		icloudSessions = append(icloudSessions, session)
	}
	s.state.ICloudSessions = icloudSessions
	if s.state.ICloudSession != nil && constantTimeEqual(id, s.state.ICloudSession.OwnerID) {
		result.ICloudSessions++
		s.state.ICloudSession = nil
	}

	webSessions := s.state.WebSessions[:0]
	for _, session := range s.state.WebSessions {
		if constantTimeEqual(id, session.UserID) {
			result.WebSessions++
			continue
		}
		webSessions = append(webSessions, session)
	}
	s.state.WebSessions = webSessions

	createSettings := s.state.CreateSettings[:0]
	for _, settings := range s.state.CreateSettings {
		if constantTimeEqual(id, settings.OwnerID) {
			continue
		}
		createSettings = append(createSettings, settings)
	}
	s.state.CreateSettings = createSettings

	if err := s.saveLocked(); err != nil {
		s.state = previousState
		return DeleteUserResult{}, errCode("user_delete_persist_failed", "账号及其归属数据删除失败："+err.Error(), true)
	}
	return result, nil
}

func (s *FileStore) CreateWebSession(userID string, isAdmin bool, ttl time.Duration) (string, WebSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	userID = strings.TrimSpace(userID)
	if _, ok := s.userByIDLocked(userID); !ok {
		return "", WebSession{}, errCode("user_not_found", "账号不存在", false)
	}
	token, err := randomToken(32)
	if err != nil {
		return "", WebSession{}, err
	}
	now := time.Now()
	session := WebSession{
		TokenHash:  sessionTokenHash(token),
		UserID:     userID,
		IsAdmin:    isAdmin,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(ttl),
	}
	s.state.WebSessions = append(s.state.WebSessions, session)
	if err := s.saveLocked(); err != nil {
		s.state.WebSessions = s.state.WebSessions[:len(s.state.WebSessions)-1]
		return "", WebSession{}, errCode("web_session_create_persist_failed", "登录会话写入失败："+err.Error(), true)
	}
	return token, session, nil
}

func (s *FileStore) WebSessionByToken(token string) (WebSession, User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tokenHash := sessionTokenHash(token)
	if strings.TrimSpace(token) == "" {
		return WebSession{}, User{}, false
	}
	now := time.Now()
	for _, session := range s.state.WebSessions {
		if !constantTimeEqual(tokenHash, session.TokenHash) || !session.ExpiresAt.After(now) {
			continue
		}
		user, ok := s.userByIDLocked(session.UserID)
		if !ok || user.Status != StatusActive {
			return WebSession{}, User{}, false
		}
		return session, user, true
	}
	return WebSession{}, User{}, false
}

func (s *FileStore) DeleteWebSession(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tokenHash := sessionTokenHash(token)
	previousSessions := append([]WebSession(nil), s.state.WebSessions...)
	filtered := s.state.WebSessions[:0]
	for _, session := range s.state.WebSessions {
		if constantTimeEqual(tokenHash, session.TokenHash) {
			continue
		}
		filtered = append(filtered, session)
	}
	s.state.WebSessions = filtered
	if err := s.saveLocked(); err != nil {
		s.state.WebSessions = previousSessions
		return errCode("web_session_delete_persist_failed", "退出登录状态写入失败："+err.Error(), true)
	}
	return nil
}

func (s *FileStore) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

func (s *FileStore) SetPath(path string) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path = strings.TrimSpace(path)
	if path == "" {
		path = filepath.Join("data", "state.json")
	}
	if strings.EqualFold(filepath.Ext(path), ".json") {
		path = filepath.Clean(path)
	} else {
		path = filepath.Join(path, "state.json")
	}
	previousState := cloneStateForRollback(s.state)
	previousPath := s.path
	current := cloneStateForRollback(s.state)
	data, err := os.ReadFile(path)
	switch {
	case err == nil && len(strings.TrimSpace(string(data))) > 0:
		var next State
		if err := json.Unmarshal(data, &next); err != nil {
			return State{}, err
		}
		if next.NextID <= 0 {
			next.NextID = 1
		}
		s.state = next
		// Apply the same legacy ownership migrations used during initial load.
		// The switched state is persisted below after the path update.
		s.migrateLegacyMailboxAccountIDsLocked()
		s.migrateLegacyICloudSessionLocked()
		s.normalizeInterruptedRemoteDeletesLocked()
	case err == nil:
		s.state = current
	case errors.Is(err, os.ErrNotExist):
		s.state = current
	default:
		return State{}, err
	}
	s.path = path
	if err := s.saveLocked(); err != nil {
		s.state = previousState
		s.path = previousPath
		return State{}, err
	}
	return cloneState(s.state), nil
}

func (s *FileStore) AddAccount(label, appleID, note string) (Account, error) {
	return s.AddAccountForOwner("", label, appleID, note)
}

func (s *FileStore) AddAccountForOwner(ownerID, label, appleID, note string) (Account, error) {
	return s.AddAccountForOwnerWithProxy(ownerID, label, appleID, note, "")
}

func (s *FileStore) AddAccountForOwnerWithProxy(ownerID, label, appleID, note, proxyURL string) (Account, error) {
	proxyURL, err := normalizeProxyURL(proxyURL)
	if err != nil {
		return Account{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	if err := s.appleIDConflictLocked(ownerID, appleID); err != nil {
		return Account{}, err
	}

	now := time.Now()
	account := Account{
		ID:           s.nextIDLocked("acc"),
		OwnerID:      ownerID,
		Label:        strings.TrimSpace(label),
		AppleID:      strings.TrimSpace(appleID),
		ProxyURL:     proxyURL,
		Status:       StatusActive,
		ICloudStatus: ICloudStatusNeedLogin,
		Note:         strings.TrimSpace(note),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if account.Label == "" {
		account.Label = account.ID
	}
	previousAccounts := append([]Account(nil), s.state.Accounts...)
	previousNextID := s.state.NextID
	s.state.Accounts = append(s.state.Accounts, account)
	if err := s.saveLocked(); err != nil {
		s.state.Accounts = previousAccounts
		s.state.NextID = previousNextID
		return Account{}, errCode("account_create_persist_failed", "Apple 账号写入失败："+err.Error(), true)
	}
	return account, nil
}

func (s *FileStore) UpdateAccountProxyForOwner(ownerID, accountID, proxyURL string) (Account, error) {
	proxyURL, err := normalizeProxyURL(proxyURL)
	if err != nil {
		return Account{}, err
	}
	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return Account{}, errCode("account_id_missing", "缺少 Apple 账号 ID", false)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	accountIndex := -1
	for i, account := range s.state.Accounts {
		if account.ID != accountID {
			continue
		}
		if ownerID != "" && !constantTimeEqual(ownerID, account.OwnerID) {
			return Account{}, errCode("account_forbidden", "无权操作该 Apple 账号", false)
		}
		accountIndex = i
		break
	}
	if accountIndex < 0 {
		return Account{}, errCode("account_not_found", "Apple 账号不存在", false)
	}
	s.migrateLegacyICloudSessionLocked()

	previousAccounts := append([]Account(nil), s.state.Accounts...)
	previousSessions := make([]ICloudSession, len(s.state.ICloudSessions))
	for i, session := range s.state.ICloudSessions {
		previousSessions[i] = cloneICloudSession(session)
	}
	var previousLegacySession *ICloudSession
	if s.state.ICloudSession != nil {
		legacySession := cloneICloudSession(*s.state.ICloudSession)
		previousLegacySession = &legacySession
	}
	s.state.Accounts[accountIndex].ProxyURL = proxyURL
	s.state.Accounts[accountIndex].UpdatedAt = time.Now()
	for i, session := range s.state.ICloudSessions {
		if session.AccountID != accountID || (ownerID != "" && !constantTimeEqual(ownerID, session.OwnerID)) {
			continue
		}
		s.state.ICloudSessions[i].ProxyURL = proxyURL
		for j := range s.state.ICloudSessions[i].LoginStates {
			s.state.ICloudSessions[i].LoginStates[j].ProxyURL = proxyURL
		}
	}
	if s.state.ICloudSession != nil && s.state.ICloudSession.AccountID == accountID && (ownerID == "" || s.state.ICloudSession.OwnerID == ownerID) {
		s.state.ICloudSession.ProxyURL = proxyURL
		for j := range s.state.ICloudSession.LoginStates {
			s.state.ICloudSession.LoginStates[j].ProxyURL = proxyURL
		}
	}
	if err := s.saveLocked(); err != nil {
		s.state.Accounts = previousAccounts
		s.state.ICloudSessions = previousSessions
		s.state.ICloudSession = previousLegacySession
		return Account{}, errCode("account_proxy_persist_failed", "账号代理配置写入失败："+err.Error(), true)
	}
	return s.state.Accounts[accountIndex], nil
}

func (s *FileStore) SaveAccountApplePasswordForOwner(ownerID, accountID, appleID, password string) error {
	password = strings.TrimSpace(password)
	if password == "" {
		return nil
	}
	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	appleID = strings.TrimSpace(appleID)
	if accountID == "" && appleID == "" {
		return errCode("account_not_found", "Apple 账号不存在", false)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	index := -1
	if accountID != "" {
		for i, account := range s.state.Accounts {
			if account.ID != accountID {
				continue
			}
			if ownerID != "" && !constantTimeEqual(ownerID, account.OwnerID) {
				return errCode("account_forbidden", "无权操作该 Apple 账号", false)
			}
			index = i
			break
		}
	}
	if index < 0 && appleID != "" {
		for i, account := range s.state.Accounts {
			if ownerID != "" && !constantTimeEqual(ownerID, account.OwnerID) {
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(account.AppleID), appleID) {
				continue
			}
			index = i
			break
		}
	}
	if index < 0 {
		return errCode("account_not_found", "Apple 账号不存在", false)
	}
	if s.state.Accounts[index].ApplePassword == password {
		return nil
	}
	previous := s.state.Accounts[index]
	s.state.Accounts[index].ApplePassword = password
	s.state.Accounts[index].UpdatedAt = time.Now()
	if err := s.saveLocked(); err != nil {
		s.state.Accounts[index] = previous
		return errCode("account_password_persist_failed", "Apple ID 密码写入失败："+err.Error(), true)
	}
	return nil
}

func (s *FileStore) MarkAccountMailboxCreateReconciliationRequired(ownerID, accountID, message string, at time.Time) error {
	return s.MarkAccountMailboxCreateReconciliationRequiredForOrigin(ownerID, accountID, "", message, at)
}

func (s *FileStore) MarkAccountMailboxCreateReconciliationRequiredForOrigin(ownerID, accountID, origin, message string, at time.Time) error {
	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	origin = strings.ToUpper(strings.TrimSpace(origin))
	if accountID == "" {
		return errCode("account_id_missing", "缺少 Apple 账号 ID，无法记录邮箱创建待核对状态", false)
	}
	message = strings.TrimSpace(message)
	if message == "" {
		message = "邮箱创建后的远端结果不确定，请先同步 iCloud 远端邮箱列表"
	}
	if at.IsZero() {
		at = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	accountIndex := -1
	for i, account := range s.state.Accounts {
		if account.ID != accountID {
			continue
		}
		if ownerID != "" && !constantTimeEqual(ownerID, account.OwnerID) {
			return errCode("account_forbidden", "无权记录该 Apple 账号的邮箱创建状态", false)
		}
		accountIndex = i
		break
	}
	if accountIndex < 0 {
		return errCode("account_not_found", "Apple 账号不存在，无法记录邮箱创建待核对状态", false)
	}

	account := &s.state.Accounts[accountIndex]
	account.MailboxCreateReconciliationRequired = true
	account.MailboxCreateReconciliationAt = at
	account.MailboxCreateReconciliationError = message
	account.MailboxCreateReconciliationOrigin = origin
	account.UpdatedAt = time.Now()
	if err := s.saveLocked(); err != nil {
		// Keep the in-memory gate when persistence fails. The provider result is
		// already uncertain, so allowing another create in this process could
		// create a duplicate remote mailbox.
		return errCode("account_reconciliation_persist_failed", "邮箱创建待核对状态写入失败："+err.Error(), true)
	}
	return nil
}

func (s *FileStore) ClearAccountMailboxCreateReconciliationRequired(ownerID, accountID string) error {
	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return errCode("account_id_missing", "缺少 Apple 账号 ID，无法清除邮箱创建待核对状态", false)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	accountIndex := -1
	for i, account := range s.state.Accounts {
		if account.ID != accountID {
			continue
		}
		if ownerID != "" && !constantTimeEqual(ownerID, account.OwnerID) {
			return errCode("account_forbidden", "无权清除该 Apple 账号的邮箱创建状态", false)
		}
		accountIndex = i
		break
	}
	if accountIndex < 0 {
		return errCode("account_not_found", "Apple 账号不存在，无法清除邮箱创建待核对状态", false)
	}

	account := &s.state.Accounts[accountIndex]
	if !account.MailboxCreateReconciliationRequired &&
		account.MailboxCreateReconciliationAt.IsZero() &&
		strings.TrimSpace(account.MailboxCreateReconciliationError) == "" {
		return nil
	}
	previousAccounts := append([]Account(nil), s.state.Accounts...)
	account.MailboxCreateReconciliationRequired = false
	account.MailboxCreateReconciliationAt = time.Time{}
	account.MailboxCreateReconciliationError = ""
	account.MailboxCreateReconciliationOrigin = ""
	account.UpdatedAt = time.Now()
	if err := s.saveLocked(); err != nil {
		s.state.Accounts = previousAccounts
		return errCode("account_reconciliation_persist_failed", "邮箱创建待核对状态清除失败："+err.Error(), true)
	}
	return nil
}

func (s *FileStore) AccountMailboxCreateReconciliationOriginForOwner(ownerID, accountID string) (string, bool) {
	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return "", false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, account := range s.state.Accounts {
		if account.ID != accountID {
			continue
		}
		if ownerID != "" && !constantTimeEqual(ownerID, account.OwnerID) {
			return "", false
		}
		if !account.MailboxCreateReconciliationRequired {
			return "", false
		}
		return strings.ToUpper(strings.TrimSpace(account.MailboxCreateReconciliationOrigin)), true
	}
	return "", false
}

func (s *FileStore) AccountMailboxCreateReconciliationForOwner(ownerID, accountID string) (string, bool) {
	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return "", false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, account := range s.state.Accounts {
		if account.ID != accountID {
			continue
		}
		if ownerID != "" && !constantTimeEqual(ownerID, account.OwnerID) {
			return "", false
		}
		if !account.MailboxCreateReconciliationRequired {
			return "", false
		}
		message := strings.TrimSpace(account.MailboxCreateReconciliationError)
		if message == "" {
			message = "邮箱创建后的远端结果不确定，请先同步 iCloud 远端邮箱列表"
		}
		return message, true
	}
	return "", false
}

func (s *FileStore) AddMailbox(accountID, label, email string) (Mailbox, error) {
	return s.AddMailboxForOwner("", accountID, label, email)
}

func (s *FileStore) AddMailboxForOwner(ownerID, accountID, label, email string) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.addMailboxForOwnerLocked(ownerID, accountID, label, email, nil, "")
}

func (s *FileStore) AddMailboxForOwnerWithRemote(ownerID, accountID string, remote ICloudRemoteMailbox, defaultNote string) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.addMailboxForOwnerLocked(ownerID, accountID, remote.Label, remote.Email, &remote, defaultNote)
}

func (s *FileStore) addMailboxForOwnerLocked(ownerID, accountID, label, email string, remote *ICloudRemoteMailbox, defaultNote string) (Mailbox, error) {
	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return Mailbox{}, errCode("provider_not_configured", "当前 MVP 需要先手动填入已创建的隐私邮箱；自动创建接口留给后续 iCloud Provider 接入", false)
	}
	for _, mailbox := range s.state.Mailboxes {
		if strings.EqualFold(mailbox.Email, email) {
			return Mailbox{}, errCode("mailbox_exists", "邮箱已存在", false)
		}
	}
	if remote != nil {
		remoteID := strings.TrimSpace(remote.AnonymousID)
		if remoteID != "" {
			for _, mailbox := range s.state.Mailboxes {
				if strings.EqualFold(strings.TrimSpace(mailbox.RemoteAnonymousID), remoteID) {
					return Mailbox{}, errCode("mailbox_remote_identity_conflict", "iCloud 远端邮箱身份已存在，已拒绝创建重复本地记录", false)
				}
			}
		}
	}

	now := time.Now()
	token, err := randomToken(24)
	if err != nil {
		return Mailbox{}, err
	}
	if strings.TrimSpace(label) == "" {
		label = fmt.Sprintf("UPI-%s", time.Now().Format("0102-150405"))
	}
	icloudActive := true
	status := StatusAvailable
	note := ""
	remoteAnonymousID := ""
	remoteOrigin := ""
	if remote != nil {
		icloudActive = remote.IsActive
		if !icloudActive {
			status = StatusDisabled
		}
		remoteAnonymousID = strings.TrimSpace(remote.AnonymousID)
		remoteOrigin = strings.TrimSpace(remote.Origin)
		note = strings.TrimSpace(remote.Note)
		if note == "" {
			note = strings.TrimSpace(defaultNote)
		}
	}
	mailbox := Mailbox{
		ID:                s.nextIDLocked("mbx"),
		OwnerID:           strings.TrimSpace(ownerID),
		AccountID:         strings.TrimSpace(accountID),
		RemoteAnonymousID: remoteAnonymousID,
		RemoteOrigin:      remoteOrigin,
		Label:             strings.TrimSpace(label),
		Email:             email,
		APIToken:          token,
		APIActive:         true,
		ICloudActive:      icloudActive,
		Status:            status,
		Note:              note,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	previousMailboxes := append([]Mailbox(nil), s.state.Mailboxes...)
	previousNextID := s.state.NextID
	s.state.Mailboxes = append(s.state.Mailboxes, mailbox)
	if err := s.saveLocked(); err != nil {
		s.state.Mailboxes = previousMailboxes
		s.state.NextID = previousNextID
		return Mailbox{}, errCode("mailbox_create_persist_failed", "邮箱写入失败："+err.Error(), true)
	}
	return mailbox, nil
}

func (s *FileStore) UpsertMailboxFromRemote(ownerID, accountID string, remote ICloudRemoteMailbox, defaultNote string) (Mailbox, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	email := strings.ToLower(strings.TrimSpace(remote.Email))
	remoteID := strings.TrimSpace(remote.AnonymousID)
	remoteOrigin := strings.TrimSpace(remote.Origin)
	if email == "" {
		return Mailbox{}, false, errCode("mailbox_email_missing", "iCloud 返回的邮箱地址为空", false)
	}
	now := time.Now()

	emailIndex := -1
	for i, mailbox := range s.state.Mailboxes {
		if !strings.EqualFold(mailbox.Email, email) {
			continue
		}
		if strings.TrimSpace(mailbox.OwnerID) != ownerID {
			return Mailbox{}, false, errCode("mailbox_exists_other_owner", "邮箱已存在于其他登录账号的数据中，已跳过导入", false)
		}
		emailIndex = i
		break
	}

	identityIndex := -1
	for i, mailbox := range s.state.Mailboxes {
		if remoteID == "" || !strings.EqualFold(strings.TrimSpace(mailbox.RemoteAnonymousID), remoteID) {
			continue
		}
		if strings.TrimSpace(mailbox.OwnerID) != ownerID {
			if emailIndex == i {
				return Mailbox{}, false, errCode("mailbox_exists_other_owner", "邮箱已存在于其他登录账号的数据中，已跳过导入", false)
			}
			return Mailbox{}, false, errCode("mailbox_remote_identity_conflict", "iCloud 远端邮箱身份已归属于其他数据，已拒绝覆盖", false)
		}
		existingAccountID := strings.TrimSpace(mailbox.AccountID)
		if accountID != "" && existingAccountID != "" && existingAccountID != accountID {
			return Mailbox{}, false, errCode("mailbox_remote_identity_conflict", "iCloud 远端邮箱身份已绑定其他账号，已拒绝覆盖", false)
		}
		existingOrigin := strings.TrimSpace(mailbox.RemoteOrigin)
		if remoteOrigin != "" && existingOrigin != "" && !strings.EqualFold(existingOrigin, remoteOrigin) {
			return Mailbox{}, false, errCode("mailbox_remote_identity_conflict", "iCloud 远端邮箱来源与本地记录冲突，已拒绝覆盖", false)
		}
		identityIndex = i
		break
	}

	if identityIndex >= 0 && emailIndex >= 0 && identityIndex != emailIndex {
		return Mailbox{}, false, errCode("mailbox_remote_identity_conflict", "邮箱地址与远端邮箱身份分别对应不同本地记录，已拒绝合并", false)
	}
	previousMailboxes := append([]Mailbox(nil), s.state.Mailboxes...)
	previousNextID := s.state.NextID
	if emailIndex >= 0 {
		existing := s.state.Mailboxes[emailIndex]
		existingID := strings.TrimSpace(existing.RemoteAnonymousID)
		if remoteID != "" && existingID != "" && !strings.EqualFold(existingID, remoteID) {
			return Mailbox{}, false, errCode("mailbox_remote_identity_conflict", "邮箱地址已绑定其他 iCloud 远端身份，已拒绝覆盖", false)
		}
		existingAccountID := strings.TrimSpace(existing.AccountID)
		if accountID != "" && existingAccountID != "" && existingAccountID != accountID {
			return Mailbox{}, false, errCode("mailbox_remote_identity_conflict", "邮箱地址已绑定其他账号，已拒绝覆盖", false)
		}
		existingOrigin := strings.TrimSpace(existing.RemoteOrigin)
		if remoteOrigin != "" && existingOrigin != "" && !strings.EqualFold(existingOrigin, remoteOrigin) {
			return Mailbox{}, false, errCode("mailbox_remote_identity_conflict", "邮箱地址对应的远端来源与本地记录冲突，已拒绝覆盖", false)
		}
		identityIndex = emailIndex
	}

	if identityIndex >= 0 &&
		strings.EqualFold(strings.TrimSpace(s.state.Mailboxes[identityIndex].RemoteDeleteStatus), "succeeded") {
		// A confirmed remote deletion is terminal for this local identity. A
		// stale provider list (or an externally reused response) must not
		// silently reactivate the mailbox; the user must explicitly create or
		// re-import a new local record.
		return s.state.Mailboxes[identityIndex], false, nil
	}

	if identityIndex >= 0 {
		mailbox := &s.state.Mailboxes[identityIndex]
		wasRemoteMissing := !mailbox.RemoteMissingAt.IsZero()
		remoteDeleteStatus := strings.ToLower(strings.TrimSpace(mailbox.RemoteDeleteStatus))
		wasRemoteDeleted := remoteDeleteStatus == "succeeded"
		hasUnresolvedRemoteDelete := remoteDeleteStatus == "pending" ||
			remoteDeleteStatus == "unknown" ||
			remoteDeleteStatus == "failed"
		if strings.TrimSpace(remote.Label) != "" {
			mailbox.Label = strings.TrimSpace(remote.Label)
		}
		if accountID != "" && strings.TrimSpace(mailbox.AccountID) == "" {
			mailbox.AccountID = accountID
		}
		if remoteID != "" && strings.TrimSpace(mailbox.RemoteAnonymousID) == "" {
			mailbox.RemoteAnonymousID = remoteID
		}
		if remoteOrigin != "" && strings.TrimSpace(mailbox.RemoteOrigin) == "" {
			mailbox.RemoteOrigin = remoteOrigin
		}
		if emailIndex < 0 {
			mailbox.Email = email
		}
		mailbox.RemoteMissingAt = time.Time{}
		if !hasUnresolvedRemoteDelete {
			mailbox.RemoteDeleteStatus = ""
			mailbox.RemoteDeleteError = ""
			mailbox.RemoteDeleteAt = time.Time{}
		}
		mailbox.ICloudActive = remote.IsActive
		if !remote.IsActive {
			mailbox.Status = StatusDisabled
		} else if (wasRemoteMissing || wasRemoteDeleted) && mailbox.APIActive {
			mailbox.Status = StatusAvailable
		}
		note := strings.TrimSpace(remote.Note)
		if note == "" {
			note = strings.TrimSpace(defaultNote)
		}
		if note != "" && strings.TrimSpace(mailbox.Note) == "" {
			mailbox.Note = note
		}
		mailbox.UpdatedAt = now
		if err := s.saveLocked(); err != nil {
			s.state.Mailboxes = previousMailboxes
			s.state.NextID = previousNextID
			return Mailbox{}, false, errCode("mailbox_sync_persist_failed", "邮箱同步状态写入失败："+err.Error(), true)
		}
		return *mailbox, false, nil
	}

	token, err := randomToken(24)
	if err != nil {
		return Mailbox{}, false, err
	}
	label := strings.TrimSpace(remote.Label)
	if label == "" {
		label = fmt.Sprintf("HME-%s", now.Format("0102-150405"))
	}
	note := strings.TrimSpace(remote.Note)
	if note == "" {
		note = strings.TrimSpace(defaultNote)
	}
	status := StatusAvailable
	if !remote.IsActive {
		status = StatusDisabled
	}
	mailbox := Mailbox{
		ID:                s.nextIDLocked("mbx"),
		OwnerID:           ownerID,
		AccountID:         accountID,
		RemoteAnonymousID: remoteID,
		RemoteOrigin:      remoteOrigin,
		Label:             label,
		Email:             email,
		APIToken:          token,
		APIActive:         true,
		ICloudActive:      remote.IsActive,
		Status:            status,
		Note:              note,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	s.state.Mailboxes = append(s.state.Mailboxes, mailbox)
	if err := s.saveLocked(); err != nil {
		s.state.Mailboxes = previousMailboxes
		s.state.NextID = previousNextID
		return Mailbox{}, false, errCode("mailbox_sync_persist_failed", "邮箱同步状态写入失败："+err.Error(), true)
	}
	return mailbox, true, nil
}

func (s *FileStore) MarkMailboxesRemoteMissing(ownerID, accountID string, seenEmails map[string]struct{}, checkedAt time.Time) (int, error) {
	return s.markMailboxesRemoteMissingForOrigin(ownerID, accountID, "", seenEmails, checkedAt)
}

func (s *FileStore) MarkMailboxesRemoteMissingForOrigin(ownerID, accountID, remoteOrigin string, seenEmails map[string]struct{}, checkedAt time.Time) (int, error) {
	return s.markMailboxesRemoteMissingForOrigin(ownerID, accountID, remoteOrigin, seenEmails, checkedAt)
}

func (s *FileStore) markMailboxesRemoteMissingForOrigin(ownerID, accountID, remoteOrigin string, seenEmails map[string]struct{}, checkedAt time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	remoteOrigin = strings.ToUpper(strings.TrimSpace(remoteOrigin))
	if checkedAt.IsZero() {
		checkedAt = time.Now()
	}
	previousMailboxes := append([]Mailbox(nil), s.state.Mailboxes...)
	updated := 0
	for i := range s.state.Mailboxes {
		mailbox := &s.state.Mailboxes[i]
		if strings.TrimSpace(mailbox.OwnerID) != ownerID || strings.TrimSpace(mailbox.AccountID) != accountID {
			continue
		}
		if strings.TrimSpace(mailbox.RemoteAnonymousID) == "" && strings.TrimSpace(mailbox.RemoteOrigin) == "" {
			continue
		}
		if remoteOrigin != "" {
			mailboxOrigin := strings.ToUpper(strings.TrimSpace(mailbox.RemoteOrigin))
			if mailboxOrigin == "" {
				// Records created before RemoteOrigin was introduced are
				// legacy iCloud Web records. They can be checked by the
				// legacy provider, but never by the Apple Account provider.
				if remoteOrigin != mailboxRemoteOriginICloudWeb {
					continue
				}
			} else if mailboxOrigin != remoteOrigin {
				continue
			}
		}
		email := strings.ToLower(strings.TrimSpace(mailbox.Email))
		if _, ok := seenEmails[email]; ok {
			continue
		}
		if mailbox.RemoteMissingAt.Equal(checkedAt) && !mailbox.ICloudActive && mailbox.Status == StatusDisabled {
			continue
		}
		mailbox.RemoteMissingAt = checkedAt
		mailbox.ICloudActive = false
		mailbox.Status = StatusDisabled
		mailbox.UpdatedAt = checkedAt
		updated++
	}
	if updated == 0 {
		return 0, nil
	}
	if err := s.saveLocked(); err != nil {
		s.state.Mailboxes = previousMailboxes
		return updated, errCode("mailbox_sync_persist_failed", "邮箱同步状态写入失败："+err.Error(), true)
	}
	return updated, nil
}

func (s *FileStore) BeginMailboxRemoteDelete(id string, attemptedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return errCode("mailbox_not_found", "邮箱不存在", false)
	}
	if attemptedAt.IsZero() {
		attemptedAt = time.Now()
	}
	mailbox := &s.state.Mailboxes[idx]
	switch strings.ToLower(strings.TrimSpace(mailbox.RemoteDeleteStatus)) {
	case "pending":
		return errCode("remote_delete_in_progress", "该邮箱已有远端删除操作进行中，请稍后重试", true)
	}
	previousStatus := mailbox.RemoteDeleteStatus
	previousError := mailbox.RemoteDeleteError
	previousAt := mailbox.RemoteDeleteAt
	previousUpdatedAt := mailbox.UpdatedAt
	mailbox.RemoteDeleteStatus = "pending"
	mailbox.RemoteDeleteError = ""
	mailbox.RemoteDeleteAt = attemptedAt
	mailbox.UpdatedAt = attemptedAt
	if err := s.saveLocked(); err != nil {
		mailbox.RemoteDeleteStatus = previousStatus
		mailbox.RemoteDeleteError = previousError
		mailbox.RemoteDeleteAt = previousAt
		mailbox.UpdatedAt = previousUpdatedAt
		return err
	}
	return nil
}

func (s *FileStore) ConfirmMailboxRemoteDeleteState(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return errCode("mailbox_not_found", "邮箱不存在", false)
	}
	mailbox := &s.state.Mailboxes[idx]
	if !strings.EqualFold(strings.TrimSpace(mailbox.RemoteDeleteStatus), "unknown") {
		return nil
	}
	previousStatus := mailbox.RemoteDeleteStatus
	previousError := mailbox.RemoteDeleteError
	previousAt := mailbox.RemoteDeleteAt
	previousUpdatedAt := mailbox.UpdatedAt
	confirmedAt := time.Now()
	mailbox.RemoteDeleteStatus = ""
	mailbox.RemoteDeleteError = ""
	mailbox.RemoteDeleteAt = time.Time{}
	mailbox.UpdatedAt = confirmedAt
	if err := s.saveLocked(); err != nil {
		mailbox.RemoteDeleteStatus = previousStatus
		mailbox.RemoteDeleteError = previousError
		mailbox.RemoteDeleteAt = previousAt
		mailbox.UpdatedAt = previousUpdatedAt
		return errCode("mailbox_remote_delete_state_persist_failed", "远端删除重试状态写入失败："+err.Error(), true)
	}
	return nil
}

func (s *FileStore) MarkMailboxRemoteDeleteFailed(id, message string, attemptedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return errCode("mailbox_not_found", "邮箱不存在", false)
	}
	if attemptedAt.IsZero() {
		attemptedAt = time.Now()
	}
	previousMailbox := s.state.Mailboxes[idx]
	s.state.Mailboxes[idx].RemoteDeleteStatus = "failed"
	s.state.Mailboxes[idx].RemoteDeleteError = strings.TrimSpace(message)
	s.state.Mailboxes[idx].RemoteDeleteAt = attemptedAt
	s.state.Mailboxes[idx].UpdatedAt = attemptedAt
	if err := s.saveLocked(); err != nil {
		uncertain := previousMailbox
		uncertain.RemoteDeleteStatus = "unknown"
		uncertain.RemoteDeleteError = strings.TrimSpace(message) + "；远端删除结果状态写入失败，请核对 iCloud 远端状态后再重试：" + err.Error()
		uncertain.RemoteDeleteAt = attemptedAt
		uncertain.UpdatedAt = attemptedAt
		s.state.Mailboxes[idx] = uncertain
		return errCode("mailbox_remote_delete_state_persist_failed", "远端删除失败状态写入失败："+err.Error(), true)
	}
	return nil
}

func (s *FileStore) MarkMailboxRemoteDeleteUnknown(id, message string, attemptedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return errCode("mailbox_not_found", "邮箱不存在", false)
	}
	if attemptedAt.IsZero() {
		attemptedAt = time.Now()
	}
	previousMailbox := s.state.Mailboxes[idx]
	s.state.Mailboxes[idx].RemoteDeleteStatus = "unknown"
	s.state.Mailboxes[idx].RemoteDeleteError = strings.TrimSpace(message)
	s.state.Mailboxes[idx].RemoteDeleteAt = attemptedAt
	s.state.Mailboxes[idx].UpdatedAt = attemptedAt
	if err := s.saveLocked(); err != nil {
		uncertain := previousMailbox
		uncertain.RemoteDeleteStatus = "unknown"
		uncertain.RemoteDeleteError = strings.TrimSpace(message) + "；远端删除结果状态写入失败，请核对 iCloud 远端状态后再重试：" + err.Error()
		uncertain.RemoteDeleteAt = attemptedAt
		uncertain.UpdatedAt = attemptedAt
		s.state.Mailboxes[idx] = uncertain
		return errCode("mailbox_remote_delete_state_persist_failed", "远端删除结果状态写入失败："+err.Error(), true)
	}
	return nil
}

func (s *FileStore) MarkMailboxRemoteDeleteSucceeded(id string, completedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return errCode("mailbox_not_found", "邮箱不存在", false)
	}
	if completedAt.IsZero() {
		completedAt = time.Now()
	}
	previousMailbox := s.state.Mailboxes[idx]
	s.state.Mailboxes[idx].RemoteDeleteStatus = "succeeded"
	s.state.Mailboxes[idx].RemoteDeleteError = ""
	s.state.Mailboxes[idx].RemoteDeleteAt = completedAt
	s.state.Mailboxes[idx].ICloudActive = false
	s.state.Mailboxes[idx].Status = StatusDisabled
	s.state.Mailboxes[idx].UpdatedAt = completedAt
	if err := s.saveLocked(); err != nil {
		uncertain := previousMailbox
		uncertain.RemoteDeleteStatus = "unknown"
		uncertain.RemoteDeleteError = "远端删除已成功，但本地成功状态写入失败，请核对 iCloud 远端状态后再决定是否清理本地记录：" + err.Error()
		uncertain.RemoteDeleteAt = completedAt
		uncertain.UpdatedAt = completedAt
		s.state.Mailboxes[idx] = uncertain
		return errCode("mailbox_remote_delete_state_persist_failed", "远端删除成功状态写入失败："+err.Error(), true)
	}
	return nil
}

func (s *FileStore) UnmarkMailboxesAPIExportedAt(ids []string, exportedAt time.Time) (int, error) {
	return s.UnmarkMailboxesAPIExportedAtForOwner("", ids, exportedAt)
}

func (s *FileStore) UnmarkMailboxesAPIExportedAtForOwner(ownerID string, ids []string, exportedAt time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	if exportedAt.IsZero() || len(ids) == 0 {
		return 0, nil
	}
	lookup := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			lookup[id] = struct{}{}
		}
	}
	if len(lookup) == 0 {
		return 0, nil
	}
	previousMailboxes := append([]Mailbox(nil), s.state.Mailboxes...)
	updated := 0
	now := time.Now()
	for i := range s.state.Mailboxes {
		if _, ok := lookup[s.state.Mailboxes[i].ID]; !ok {
			continue
		}
		if ownerID != "" && strings.TrimSpace(s.state.Mailboxes[i].OwnerID) != ownerID {
			continue
		}
		if s.state.Mailboxes[i].APIExportedAt.IsZero() || s.state.Mailboxes[i].APIExportedAt.UnixNano() != exportedAt.UnixNano() {
			continue
		}
		s.state.Mailboxes[i].APIExportedAt = time.Time{}
		s.state.Mailboxes[i].UpdatedAt = now
		updated++
	}
	if updated == 0 {
		return 0, nil
	}
	if err := s.saveLocked(); err != nil {
		s.state.Mailboxes = previousMailboxes
		return updated, errCode("mailbox_export_state_persist_failed", "邮箱 API 导出状态写入失败："+err.Error(), true)
	}
	return updated, nil
}

func (s *FileStore) MarkMailboxesAPIExported(ids []string, exportedAt time.Time) (int, error) {
	return s.MarkMailboxesAPIExportedForOwner("", ids, exportedAt)
}

func (s *FileStore) MarkMailboxesAPIExportedForOwner(ownerID string, ids []string, exportedAt time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	if len(ids) == 0 {
		return 0, nil
	}
	if exportedAt.IsZero() {
		exportedAt = time.Now()
	}
	lookup := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			lookup[id] = struct{}{}
		}
	}
	if len(lookup) == 0 {
		return 0, nil
	}
	previousMailboxes := append([]Mailbox(nil), s.state.Mailboxes...)
	updated := 0
	for i := range s.state.Mailboxes {
		if _, ok := lookup[s.state.Mailboxes[i].ID]; !ok {
			continue
		}
		if ownerID != "" && strings.TrimSpace(s.state.Mailboxes[i].OwnerID) != ownerID {
			continue
		}
		s.state.Mailboxes[i].APIExportedAt = exportedAt
		s.state.Mailboxes[i].UpdatedAt = exportedAt
		updated++
	}
	if updated == 0 {
		return 0, nil
	}
	if err := s.saveLocked(); err != nil {
		s.state.Mailboxes = previousMailboxes
		return updated, errCode("mailbox_export_state_persist_failed", "邮箱 API 导出状态写入失败："+err.Error(), true)
	}
	return updated, nil
}

type mailboxAPIExportState struct {
	APIExportedAt time.Time
	UpdatedAt     time.Time
}

func (s *FileStore) ClearMailboxesAPIExported(ids []string) (int, error) {
	return s.ClearMailboxesAPIExportedForOwner("", ids)
}

func (s *FileStore) ClearMailboxesAPIExportedForOwner(ownerID string, ids []string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	if len(ids) == 0 {
		return 0, nil
	}
	lookup := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			lookup[id] = struct{}{}
		}
	}
	if len(lookup) == 0 {
		return 0, nil
	}
	previousMailboxes := append([]Mailbox(nil), s.state.Mailboxes...)
	updated := 0
	now := time.Now()
	for i := range s.state.Mailboxes {
		if _, ok := lookup[s.state.Mailboxes[i].ID]; !ok {
			continue
		}
		if ownerID != "" && strings.TrimSpace(s.state.Mailboxes[i].OwnerID) != ownerID {
			continue
		}
		if s.state.Mailboxes[i].APIExportedAt.IsZero() {
			continue
		}
		s.state.Mailboxes[i].APIExportedAt = time.Time{}
		s.state.Mailboxes[i].UpdatedAt = now
		updated++
	}
	if updated == 0 {
		return 0, nil
	}
	if err := s.saveLocked(); err != nil {
		s.state.Mailboxes = previousMailboxes
		return updated, errCode("mailbox_export_state_persist_failed", "邮箱 API 导出状态写入失败："+err.Error(), true)
	}
	return updated, nil
}

func (s *FileStore) RestoreMailboxesAPIExportState(previous map[string]mailboxAPIExportState) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(previous) == 0 {
		return 0, nil
	}
	previousMailboxes := append([]Mailbox(nil), s.state.Mailboxes...)
	updated := 0
	for i := range s.state.Mailboxes {
		state, ok := previous[s.state.Mailboxes[i].ID]
		if !ok {
			continue
		}
		s.state.Mailboxes[i].APIExportedAt = state.APIExportedAt
		s.state.Mailboxes[i].UpdatedAt = state.UpdatedAt
		updated++
	}
	if updated == 0 {
		return 0, nil
	}
	if err := s.saveLocked(); err != nil {
		s.state.Mailboxes = previousMailboxes
		return updated, errCode("mailbox_export_state_persist_failed", "邮箱 API 导出状态写入失败："+err.Error(), true)
	}
	return updated, nil
}

const interruptedRemoteDeleteMessage = "上次远端删除在进程退出前未确认结果，请先核对 iCloud 远端状态后再重试"

func (s *FileStore) normalizeInterruptedRemoteDeletesLocked() bool {
	changed := false
	for i := range s.state.Mailboxes {
		if !strings.EqualFold(strings.TrimSpace(s.state.Mailboxes[i].RemoteDeleteStatus), "pending") {
			continue
		}
		s.state.Mailboxes[i].RemoteDeleteStatus = "unknown"
		s.state.Mailboxes[i].RemoteDeleteError = interruptedRemoteDeleteMessage
		if s.state.Mailboxes[i].UpdatedAt.IsZero() {
			s.state.Mailboxes[i].UpdatedAt = time.Now()
		}
		changed = true
	}
	return changed
}

func (s *FileStore) ClaimAvailableMailbox(note string) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, mailbox := range s.state.Mailboxes {
		if !mailboxClaimable(mailbox) {
			continue
		}
		return s.claimMailboxLocked(i, note)
	}
	return Mailbox{}, errCode("no_available_mailbox", "没有可用隐私邮箱", false)
}

func (s *FileStore) AvailableMailboxCandidates() []Mailbox {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Mailbox, 0)
	for _, mailbox := range s.state.Mailboxes {
		if mailboxClaimable(mailbox) {
			out = append(out, mailbox)
		}
	}
	return out
}

func (s *FileStore) ClaimAvailableMailboxForID(id, note string) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return Mailbox{}, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	if !mailboxClaimable(s.state.Mailboxes[idx]) {
		return Mailbox{}, errCode("mailbox_not_available", "邮箱已不可领取，请重新获取可用邮箱", true)
	}
	return s.claimMailboxLocked(idx, note)
}

func mailboxClaimable(mailbox Mailbox) bool {
	if !mailbox.APIActive || !mailbox.ICloudActive || mailbox.Status != StatusAvailable {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(mailbox.RemoteDeleteStatus)) {
	case "pending", "unknown", "failed", "succeeded":
		return false
	default:
		return true
	}
}

func (s *FileStore) claimMailboxLocked(index int, note string) (Mailbox, error) {
	previousMailbox := s.state.Mailboxes[index]
	s.state.Mailboxes[index].Status = StatusUsed
	if strings.TrimSpace(note) != "" {
		s.state.Mailboxes[index].Note = strings.TrimSpace(note)
	}
	s.state.Mailboxes[index].UpdatedAt = time.Now()
	if err := s.saveLocked(); err != nil {
		s.state.Mailboxes[index] = previousMailbox
		return Mailbox{}, errCode("mailbox_claim_persist_failed", "邮箱领取状态写入失败："+err.Error(), true)
	}
	return s.state.Mailboxes[index], nil
}

func (s *FileStore) SaveICloudSession(session ICloudSession) error {
	return s.SaveICloudSessionForOwner("", session)
}

func (s *FileStore) SaveICloudSessionForOwner(ownerID string, session ICloudSession) error {
	return s.saveICloudSessionForOwner(ownerID, session, false)
}

func (s *FileStore) SaveICloudSessionForOwnerUpdatingProxy(ownerID string, session ICloudSession) error {
	return s.saveICloudSessionForOwner(ownerID, session, true)
}

func (s *FileStore) saveICloudSessionForOwner(ownerID string, session ICloudSession, updateAccountProxy bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Never retain slices owned by the caller. Login-state refreshes and
	// provider response handling often mutate nested cookies/cursors after the
	// save call returns; keeping those slices here would race with readers and
	// silently change persisted in-memory state without a save.
	session = cloneICloudSession(session)
	previousState := cloneStateForRollback(s.state)
	save := func() error {
		if err := s.saveLocked(); err != nil {
			s.state = previousState
			return errCode("icloud_session_persist_failed", "iCloud 登录态写入失败："+err.Error(), true)
		}
		return nil
	}
	ownerID = strings.TrimSpace(ownerID)
	session.OwnerID = ownerID
	if session.SavedAt.IsZero() {
		session.SavedAt = time.Now()
	}
	s.migrateLegacyICloudSessionLocked()
	if ownerID != "" {
		if strings.TrimSpace(session.AccountID) == "" {
			accountID, err := s.ensureICloudAccountLocked(ownerID, session, updateAccountProxy)
			if err != nil {
				return err
			}
			session.AccountID = accountID
		} else {
			s.touchICloudAccountLocked(ownerID, session.AccountID, session, updateAccountProxy)
		}
		session = s.sessionWithAccountProxyForSaveLocked(ownerID, session, updateAccountProxy)
		for i, existing := range s.state.ICloudSessions {
			if constantTimeEqual(ownerID, existing.OwnerID) && sameICloudSessionIdentity(existing, session) {
				merged := mergeICloudSession(existing, session)
				merged = s.sessionWithAccountProxyForSaveLocked(ownerID, merged, updateAccountProxy)
				s.state.ICloudSessions[i] = merged
				if strings.TrimSpace(merged.AccountID) != "" {
					s.touchICloudAccountLocked(ownerID, merged.AccountID, merged, updateAccountProxy)
				}
				s.pruneDuplicateIMAPOnlySessionsLocked(ownerID, merged, i)
				return save()
			}
		}
		s.state.ICloudSessions = append(s.state.ICloudSessions, session)
		s.pruneDuplicateIMAPOnlySessionsLocked(ownerID, session, len(s.state.ICloudSessions)-1)
		return save()
	}
	session = s.sessionWithAccountProxyForSaveLocked(ownerID, session, updateAccountProxy)
	for i, existing := range s.state.ICloudSessions {
		if strings.TrimSpace(existing.OwnerID) == "" && sameICloudSessionIdentity(existing, session) {
			merged := mergeICloudSession(existing, session)
			merged = s.sessionWithAccountProxyForSaveLocked(ownerID, merged, updateAccountProxy)
			s.state.ICloudSessions[i] = merged
			if strings.TrimSpace(merged.AccountID) != "" {
				s.touchICloudAccountLocked(ownerID, merged.AccountID, merged, updateAccountProxy)
			}
			s.pruneDuplicateIMAPOnlySessionsLocked(ownerID, merged, i)
			s.state.ICloudSession = nil
			return save()
		}
	}
	s.state.ICloudSessions = append(s.state.ICloudSessions, session)
	s.pruneDuplicateIMAPOnlySessionsLocked(ownerID, session, len(s.state.ICloudSessions)-1)
	s.state.ICloudSession = nil
	return save()
}

func (s *FileStore) sessionWithAccountProxyForSaveLocked(ownerID string, session ICloudSession, updateAccountProxy bool) ICloudSession {
	accountID := strings.TrimSpace(session.AccountID)
	if accountID == "" {
		return session
	}
	incomingProxy := strings.TrimSpace(session.ProxyURL)
	if updateAccountProxy && incomingProxy != "" {
		s.touchICloudAccountLocked(ownerID, accountID, session, true)
		return sessionWithProxyURL(session, incomingProxy)
	}
	if accountProxy, ok := s.findAccountProxyForSessionLocked(ownerID, accountID); ok {
		return sessionWithProxyURL(session, accountProxy)
	}
	return session
}

func sessionWithProxyURL(session ICloudSession, proxyURL string) ICloudSession {
	session = cloneICloudSession(session)
	proxyURL = strings.TrimSpace(proxyURL)
	session.ProxyURL = proxyURL
	for i := range session.LoginStates {
		session.LoginStates[i].ProxyURL = proxyURL
	}
	return session
}

func (s *FileStore) accountProxyForSessionLocked(ownerID, accountID string) string {
	proxyURL, _ := s.findAccountProxyForSessionLocked(ownerID, accountID)
	return proxyURL
}

func (s *FileStore) findAccountProxyForSessionLocked(ownerID, accountID string) (string, bool) {
	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return "", false
	}
	for _, account := range s.state.Accounts {
		if account.ID != accountID {
			continue
		}
		if ownerID != "" && !constantTimeEqual(ownerID, account.OwnerID) {
			continue
		}
		return strings.TrimSpace(account.ProxyURL), true
	}
	return "", false
}

func (s *FileStore) ICloudSession() (ICloudSession, bool) {
	return s.ICloudSessionForOwner("")
}

func (s *FileStore) ICloudSessionForOwner(ownerID string) (ICloudSession, bool) {
	sessions := s.ICloudSessionsForOwner(ownerID)
	if len(sessions) == 0 {
		return ICloudSession{}, false
	}
	return sessions[0], true
}

func (s *FileStore) ICloudSessionsForOwner(ownerID string) []ICloudSession {
	s.mu.Lock()
	defer s.mu.Unlock()

	proxyByAccountID := accountProxyMap(s.state.Accounts)
	ownerID = strings.TrimSpace(ownerID)
	out := make([]ICloudSession, 0, len(s.state.ICloudSessions)+1)
	appendSession := func(session ICloudSession) {
		var ok bool
		session, ok = s.usableICloudSessionLocked(session)
		if !ok {
			return
		}
		session = cloneICloudSession(resolveICloudSessionProxy(session, proxyByAccountID))
		for i := range out {
			if !sameICloudSessionIdentity(out[i], session) {
				continue
			}
			out[i] = mergeICloudSession(out[i], session)
			return
		}
		out = append(out, session)
	}
	if ownerID != "" {
		if s.state.ICloudSession != nil && constantTimeEqual(ownerID, s.state.ICloudSession.OwnerID) {
			appendSession(*s.state.ICloudSession)
		}
		for _, session := range s.state.ICloudSessions {
			if constantTimeEqual(ownerID, session.OwnerID) {
				appendSession(session)
			}
		}
		return out
	}
	if s.state.ICloudSession != nil {
		appendSession(*s.state.ICloudSession)
	}
	for _, session := range s.state.ICloudSessions {
		if strings.TrimSpace(session.OwnerID) == "" {
			appendSession(session)
		}
	}
	return out
}

func (s *FileStore) ICloudSessionsForAllOwners() []ICloudSession {
	s.mu.Lock()
	defer s.mu.Unlock()

	proxyByAccountID := accountProxyMap(s.state.Accounts)
	out := make([]ICloudSession, 0, len(s.state.ICloudSessions)+1)
	appendSession := func(session ICloudSession) {
		var ok bool
		session, ok = s.usableICloudSessionLocked(session)
		if !ok {
			return
		}
		session = cloneICloudSession(resolveICloudSessionProxy(session, proxyByAccountID))
		for i := range out {
			if !constantTimeEqual(strings.TrimSpace(out[i].OwnerID), strings.TrimSpace(session.OwnerID)) ||
				!sameICloudSessionIdentity(out[i], session) {
				continue
			}
			out[i] = mergeICloudSession(out[i], session)
			return
		}
		out = append(out, session)
	}
	if s.state.ICloudSession != nil {
		appendSession(*s.state.ICloudSession)
	}
	for _, session := range s.state.ICloudSessions {
		appendSession(session)
	}
	return out
}

func (s *FileStore) ICloudSessionForOwnerAccount(ownerID, accountID string) (ICloudSession, bool) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return s.ICloudSessionForOwner(ownerID)
	}
	for _, session := range s.ICloudSessionsForOwner(ownerID) {
		if constantTimeEqual(accountID, session.AccountID) {
			return session, true
		}
	}
	return ICloudSession{}, false
}

func (s *FileStore) FindAccountByID(id string) (Account, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id = strings.TrimSpace(id)
	for _, account := range s.state.Accounts {
		if account.ID == id {
			return account, true
		}
	}
	return Account{}, false
}

func (s *FileStore) FindAccountForOwnerAppleID(ownerID, appleID string) (Account, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	appleID = strings.TrimSpace(appleID)
	if appleID == "" {
		return Account{}, false
	}
	for _, account := range s.state.Accounts {
		if ownerID != "" && !constantTimeEqual(ownerID, account.OwnerID) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(account.AppleID), appleID) {
			continue
		}
		return account, true
	}
	return Account{}, false
}

func (s *FileStore) AccountProxyForOwnerAppleID(ownerID, appleID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	appleID = strings.ToLower(strings.TrimSpace(appleID))
	proxyURL, matched := accountProxyConfigForOwnerAppleIDLocked(s.state.Accounts, ownerID, appleID)
	return proxyURL, matched && proxyURL != ""
}

func (s *FileStore) AccountProxyConfigForOwnerAppleID(ownerID, appleID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	appleID = strings.ToLower(strings.TrimSpace(appleID))
	return accountProxyConfigForOwnerAppleIDLocked(s.state.Accounts, ownerID, appleID)
}

func accountProxyConfigForOwnerAppleIDLocked(accounts []Account, ownerID, appleID string) (string, bool) {
	if appleID == "" {
		return "", false
	}
	var (
		matched    bool
		configured string
	)
	for _, account := range accounts {
		if strings.TrimSpace(account.OwnerID) != ownerID {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(account.AppleID), appleID) {
			continue
		}
		proxyURL := strings.TrimSpace(account.ProxyURL)
		if !matched {
			matched = true
			configured = proxyURL
			continue
		}
		if configured != proxyURL {
			return "", false
		}
	}
	return configured, matched
}

func (s *FileStore) AccountProxyForAppleID(appleID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	appleID = strings.ToLower(strings.TrimSpace(appleID))
	proxyURL, matched := accountProxyConfigForAppleIDLocked(s.state.Accounts, appleID)
	return proxyURL, matched && proxyURL != ""
}

func (s *FileStore) AccountProxyConfigForAppleID(appleID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	appleID = strings.ToLower(strings.TrimSpace(appleID))
	return accountProxyConfigForAppleIDLocked(s.state.Accounts, appleID)
}

func accountProxyConfigForAppleIDLocked(accounts []Account, appleID string) (string, bool) {
	if appleID == "" {
		return "", false
	}
	var (
		matched    bool
		configured string
	)
	for _, account := range accounts {
		if !strings.EqualFold(strings.TrimSpace(account.AppleID), appleID) {
			continue
		}
		proxyURL := strings.TrimSpace(account.ProxyURL)
		if !matched {
			matched = true
			configured = proxyURL
			continue
		}
		if configured != proxyURL {
			return "", false
		}
	}
	return configured, matched
}

func (s *FileStore) AddMessage(mailboxID, subject, from, body string, receivedAt time.Time) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(mailboxID)
	if idx < 0 {
		return Message{}, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	previousMessages := append([]Message(nil), s.state.Messages...)
	previousMailbox := s.state.Mailboxes[idx]
	previousNextID := s.state.NextID
	msg := Message{
		ID:         s.nextIDLocked("msg"),
		OwnerID:    s.state.Mailboxes[idx].OwnerID,
		MailboxID:  mailboxID,
		Subject:    strings.TrimSpace(subject),
		From:       strings.TrimSpace(from),
		Body:       body,
		ReceivedAt: receivedAt,
		CreatedAt:  time.Now(),
	}
	s.state.Messages = append(s.state.Messages, msg)
	s.state.Mailboxes[idx].ReceiveCount++
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	if err := s.saveLocked(); err != nil {
		s.state.Messages = previousMessages
		s.state.Mailboxes[idx] = previousMailbox
		s.state.NextID = previousNextID
		return Message{}, errCode("message_persist_failed", "邮件写入失败："+err.Error(), true)
	}
	return msg, nil
}

func (s *FileStore) UpsertMessage(mailboxID, remoteID, source, subject, from, body string, receivedAt time.Time) (Message, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(mailboxID)
	if idx < 0 {
		return Message{}, false, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	previousMessages := append([]Message(nil), s.state.Messages...)
	previousMailbox := s.state.Mailboxes[idx]
	previousNextID := s.state.NextID
	save := func() error {
		if err := s.saveLocked(); err != nil {
			s.state.Messages = previousMessages
			s.state.Mailboxes[idx] = previousMailbox
			s.state.NextID = previousNextID
			return errCode("message_persist_failed", "邮件写入失败："+err.Error(), true)
		}
		return nil
	}
	remoteID = strings.TrimSpace(remoteID)
	if remoteID != "" {
		for i, msg := range s.state.Messages {
			if msg.MailboxID == mailboxID && msg.RemoteID == remoteID {
				s.state.Messages[i].OwnerID = s.state.Mailboxes[idx].OwnerID
				s.state.Messages[i].Source = strings.TrimSpace(source)
				s.state.Messages[i].Subject = strings.TrimSpace(subject)
				s.state.Messages[i].From = strings.TrimSpace(from)
				s.state.Messages[i].Body = body
				if !receivedAt.IsZero() {
					s.state.Messages[i].ReceivedAt = receivedAt
				}
				s.state.Messages[i].CreatedAt = firstNonZeroTime(s.state.Messages[i].CreatedAt, time.Now())
				s.state.Mailboxes[idx].UpdatedAt = time.Now()
				if err := save(); err != nil {
					return Message{}, false, err
				}
				return s.state.Messages[i], false, nil
			}
		}
	}
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	msg := Message{
		ID:         s.nextIDLocked("msg"),
		OwnerID:    s.state.Mailboxes[idx].OwnerID,
		MailboxID:  mailboxID,
		RemoteID:   remoteID,
		Source:     strings.TrimSpace(source),
		Subject:    strings.TrimSpace(subject),
		From:       strings.TrimSpace(from),
		Body:       body,
		ReceivedAt: receivedAt,
		CreatedAt:  time.Now(),
	}
	s.state.Messages = append(s.state.Messages, msg)
	s.state.Mailboxes[idx].ReceiveCount++
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	if err := save(); err != nil {
		return Message{}, false, err
	}
	return msg, true, nil
}

func (s *FileStore) SetMailboxStatus(id string, apiActive *bool, icloudActive *bool, status, note string) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return Mailbox{}, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	previousMailbox := s.state.Mailboxes[idx]
	if mailboxStatusWouldReactivate(s.state.Mailboxes[idx], icloudActive, status) {
		switch strings.ToLower(strings.TrimSpace(s.state.Mailboxes[idx].RemoteDeleteStatus)) {
		case "unknown":
			return Mailbox{}, errCode("remote_delete_unknown", "上次远端删除在进程退出前未确认结果，请先核对 iCloud 远端状态后再重试", true)
		case "pending":
			return Mailbox{}, errCode("remote_delete_in_progress", "该邮箱已有远端删除操作进行中，请稍后重试", true)
		case "failed":
			return Mailbox{}, errCode("remote_delete_failed", "上次远端删除失败，请先核对 iCloud 远端状态后再重试", true)
		case "succeeded":
			return Mailbox{}, errCode("mailbox_remote_deleted", "该邮箱已确认从 iCloud 远端删除，不能直接恢复本地启用状态，请先重新同步或重新创建邮箱", false)
		}
		if !s.state.Mailboxes[idx].RemoteMissingAt.IsZero() {
			return Mailbox{}, errCode("mailbox_remote_missing", "该邮箱已被同步标记为 iCloud 远端不存在，不能直接恢复本地启用状态，请先重新同步", false)
		}
	}
	if apiActive != nil {
		s.state.Mailboxes[idx].APIActive = *apiActive
	}
	if icloudActive != nil {
		s.state.Mailboxes[idx].ICloudActive = *icloudActive
	}
	if strings.TrimSpace(status) != "" {
		s.state.Mailboxes[idx].Status = strings.TrimSpace(status)
	}
	if strings.TrimSpace(note) != "" {
		s.state.Mailboxes[idx].Note = strings.TrimSpace(note)
	}
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	if err := s.saveLocked(); err != nil {
		s.state.Mailboxes[idx] = previousMailbox
		return Mailbox{}, errCode("mailbox_status_persist_failed", "邮箱状态写入失败："+err.Error(), true)
	}
	return s.state.Mailboxes[idx], nil
}

func (s *FileStore) BindMailboxToAccountForOwner(ownerID, mailboxID, accountID string) (Mailbox, error) {
	ownerID = strings.TrimSpace(ownerID)
	mailboxID = strings.TrimSpace(mailboxID)
	accountID = strings.TrimSpace(accountID)
	if mailboxID == "" {
		return Mailbox{}, errCode("mailbox_id_missing", "缺少邮箱 ID", false)
	}
	if accountID == "" {
		return Mailbox{}, errCode("account_id_missing", "缺少 Apple 账号 ID", false)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	mailboxIndex := s.mailboxIndexLocked(mailboxID)
	if mailboxIndex < 0 {
		return Mailbox{}, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	mailbox := s.state.Mailboxes[mailboxIndex]
	if ownerID != "" && !constantTimeEqual(ownerID, mailbox.OwnerID) {
		return Mailbox{}, errCode("mailbox_forbidden", "无权绑定该邮箱", false)
	}

	accountIndex := -1
	for i, account := range s.state.Accounts {
		if account.ID == accountID {
			accountIndex = i
			break
		}
	}
	if accountIndex < 0 {
		return Mailbox{}, errCode("account_not_found", "Apple 账号不存在", false)
	}
	account := s.state.Accounts[accountIndex]
	if ownerID != "" && !constantTimeEqual(ownerID, account.OwnerID) {
		return Mailbox{}, errCode("account_forbidden", "无权绑定到该 Apple 账号", false)
	}
	if strings.TrimSpace(mailbox.OwnerID) != "" &&
		!constantTimeEqual(mailbox.OwnerID, account.OwnerID) {
		return Mailbox{}, errCode("mailbox_account_owner_mismatch", "邮箱和 Apple 账号不属于同一用户", false)
	}
	if existingAccountID := strings.TrimSpace(mailbox.AccountID); existingAccountID != "" {
		if existingAccountID == accountID {
			if strings.TrimSpace(mailbox.OwnerID) == "" && strings.TrimSpace(account.OwnerID) != "" {
				previousMailbox := mailbox
				s.state.Mailboxes[mailboxIndex].OwnerID = strings.TrimSpace(account.OwnerID)
				s.state.Mailboxes[mailboxIndex].UpdatedAt = time.Now()
				if err := s.saveLocked(); err != nil {
					s.state.Mailboxes[mailboxIndex] = previousMailbox
					return Mailbox{}, errCode("mailbox_bind_persist_failed", "邮箱归属写入失败："+err.Error(), true)
				}
				return s.state.Mailboxes[mailboxIndex], nil
			}
			return mailbox, nil
		}
		return Mailbox{}, errCode("mailbox_account_already_bound", "邮箱已经绑定其他 Apple 账号", false)
	}

	previousMailbox := mailbox
	s.state.Mailboxes[mailboxIndex].AccountID = accountID
	if strings.TrimSpace(s.state.Mailboxes[mailboxIndex].OwnerID) == "" {
		s.state.Mailboxes[mailboxIndex].OwnerID = strings.TrimSpace(account.OwnerID)
	}
	s.state.Mailboxes[mailboxIndex].UpdatedAt = time.Now()
	if err := s.saveLocked(); err != nil {
		s.state.Mailboxes[mailboxIndex] = previousMailbox
		return Mailbox{}, errCode("mailbox_bind_persist_failed", "邮箱归属写入失败："+err.Error(), true)
	}
	return s.state.Mailboxes[mailboxIndex], nil
}

func mailboxStatusWouldReactivate(mailbox Mailbox, icloudActive *bool, status string) bool {
	if icloudActive != nil && *icloudActive {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case StatusActive, StatusAvailable:
		return true
	default:
		return false
	}
}

func (s *FileStore) SetMailboxSyncCursor(id string, syncedAt time.Time, lastUID string) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return Mailbox{}, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	previousMailbox := s.state.Mailboxes[idx]
	if syncedAt.IsZero() {
		syncedAt = time.Now()
	}
	s.state.Mailboxes[idx].LastSyncAt = syncedAt
	if strings.TrimSpace(lastUID) != "" {
		s.state.Mailboxes[idx].LastSyncUID = strings.TrimSpace(lastUID)
	}
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	if err := s.saveLocked(); err != nil {
		s.state.Mailboxes[idx] = previousMailbox
		return Mailbox{}, errCode("mailbox_sync_persist_failed", "邮箱同步游标写入失败："+err.Error(), true)
	}
	return s.state.Mailboxes[idx], nil
}

func (s *FileStore) SetICloudIMAPSyncCursor(ownerID, accountID, stateKey string, syncedAt time.Time, lastUID string) (ICloudSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	previousSessions := make([]ICloudSession, len(s.state.ICloudSessions))
	for i, session := range s.state.ICloudSessions {
		previousSessions[i] = cloneICloudSession(session)
	}
	var previousLegacySession *ICloudSession
	if s.state.ICloudSession != nil {
		legacySession := cloneICloudSession(*s.state.ICloudSession)
		previousLegacySession = &legacySession
	}
	save := func() error {
		if err := s.saveLocked(); err != nil {
			s.state.ICloudSessions = previousSessions
			s.state.ICloudSession = previousLegacySession
			return errCode("imap_cursor_persist_failed", "IMAP 同步游标写入失败："+err.Error(), true)
		}
		return nil
	}
	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	stateKey = strings.TrimSpace(stateKey)
	if syncedAt.IsZero() {
		syncedAt = time.Now()
	}
	updateSession := func(session *ICloudSession) bool {
		if session == nil {
			return false
		}
		if ownerID != "" && !constantTimeEqual(ownerID, session.OwnerID) {
			return false
		}
		if accountID != "" && !constantTimeEqual(accountID, session.AccountID) {
			return false
		}
		for i, state := range session.LoginStates {
			if state.Kind != LoginStateICloudIMAP {
				continue
			}
			if accountID == "" && stateKey != "" && imapStateKey(state) != stateKey {
				continue
			}
			session.LoginStates[i].IMAPLastSyncAt = syncedAt
			if strings.TrimSpace(lastUID) != "" {
				session.LoginStates[i].IMAPLastSyncUID = strings.TrimSpace(lastUID)
			}
			return true
		}
		return false
	}
	if s.state.ICloudSession != nil && updateSession(s.state.ICloudSession) {
		updated := cloneICloudSession(*s.state.ICloudSession)
		if err := save(); err != nil {
			return ICloudSession{}, err
		}
		return updated, nil
	}
	for i := range s.state.ICloudSessions {
		if updateSession(&s.state.ICloudSessions[i]) {
			updated := cloneICloudSession(s.state.ICloudSessions[i])
			if err := save(); err != nil {
				return ICloudSession{}, err
			}
			return updated, nil
		}
	}
	return ICloudSession{}, errCode("imap_session_missing", "未找到取码登录态，无法保存 IMAP 同步游标", true)
}

func (s *FileStore) SetMailboxLastCode(id string, messageID string, servedAt time.Time) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return Mailbox{}, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	if err := mailboxCodeAvailabilityError(s.state.Mailboxes[idx]); err != nil {
		return Mailbox{}, err
	}
	previousMailbox := s.state.Mailboxes[idx]
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return Mailbox{}, errCode("message_id_missing", "验证码邮件 ID 为空", false)
	}
	if strings.TrimSpace(s.state.Mailboxes[idx].LastCodeMessageID) == messageID {
		return s.state.Mailboxes[idx], errCode("mailbox_code_already_served", "该验证码已发放", true)
	}
	if servedAt.IsZero() {
		servedAt = time.Now()
	}
	s.state.Mailboxes[idx].LastCodeMessageID = messageID
	s.state.Mailboxes[idx].LastCodeAt = servedAt
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	if err := s.saveLocked(); err != nil {
		s.state.Mailboxes[idx] = previousMailbox
		return Mailbox{}, errCode("mailbox_code_state_persist_failed", "验证码发放记录写入失败："+err.Error(), true)
	}
	return s.state.Mailboxes[idx], nil
}

func mailboxCodeAvailabilityError(mailbox Mailbox) error {
	switch strings.ToLower(strings.TrimSpace(mailbox.RemoteDeleteStatus)) {
	case "pending":
		return errCode("remote_delete_in_progress", "该邮箱已有远端删除操作进行中，请稍后重试", true)
	case "unknown":
		return errCode("remote_delete_unknown", "上次远端删除在进程退出前未确认结果，请先核对 iCloud 远端状态后再重试", true)
	case "failed":
		return errCode("remote_delete_failed", "上次远端删除失败，请先核对 iCloud 远端状态后再重试", true)
	case "succeeded":
		return errCode("mailbox_remote_deleted", "该邮箱已确认从 iCloud 远端删除，不能继续获取验证码", false)
	}
	if !mailbox.APIActive || mailbox.Status == StatusDisabled {
		return errCode("api_disabled", "API 已停用", false)
	}
	if !mailbox.ICloudActive {
		return errCode("icloud_inactive", "邮箱已停用或 iCloud 状态不可用", false)
	}
	return nil
}

func mailboxCanServeCode(mailbox Mailbox) bool {
	return mailboxCodeAvailabilityError(mailbox) == nil
}

func (s *FileStore) DeleteMailbox(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return errCode("mailbox_not_found", "邮箱不存在", false)
	}
	previousMailboxes := append([]Mailbox(nil), s.state.Mailboxes...)
	previousMessages := append([]Message(nil), s.state.Messages...)
	s.state.Mailboxes = append(s.state.Mailboxes[:idx], s.state.Mailboxes[idx+1:]...)
	filtered := s.state.Messages[:0]
	for _, msg := range s.state.Messages {
		if msg.MailboxID != id {
			filtered = append(filtered, msg)
		}
	}
	s.state.Messages = filtered
	if err := s.saveLocked(); err != nil {
		s.state.Mailboxes = previousMailboxes
		s.state.Messages = previousMessages
		return errCode("mailbox_delete_persist_failed", "本地邮箱删除状态写入失败："+err.Error(), true)
	}
	return nil
}

func (s *FileStore) FindMailboxByID(id string) (Mailbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return Mailbox{}, false
	}
	return s.state.Mailboxes[idx], true
}

func (s *FileStore) FindMailboxByEmail(email string) (Mailbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, mailbox := range s.state.Mailboxes {
		if strings.EqualFold(mailbox.Email, email) {
			return mailbox, true
		}
	}
	return Mailbox{}, false
}

func (s *FileStore) MessagesForMailbox(mailboxID string) []Message {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []Message
	for _, msg := range s.state.Messages {
		if msg.MailboxID == mailboxID {
			out = append(out, msg)
		}
	}
	return out
}

func (s *FileStore) nextIDLocked(prefix string) string {
	id := fmt.Sprintf("%s_%06d", prefix, s.state.NextID)
	s.state.NextID++
	return id
}

func (s *FileStore) AppleIDOwnedByOtherOwner(ownerID, appleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appleIDOwnedByOtherLocked(ownerID, appleID)
}

func (s *FileStore) appleIDOwnedByOtherLocked(ownerID, appleID string) error {
	ownerID = strings.TrimSpace(ownerID)
	appleID = strings.ToLower(strings.TrimSpace(appleID))
	if appleID == "" {
		return nil
	}
	for _, account := range s.state.Accounts {
		if !strings.EqualFold(strings.TrimSpace(account.AppleID), appleID) {
			continue
		}
		if constantTimeEqual(strings.TrimSpace(account.OwnerID), ownerID) {
			continue
		}
		return errCode("apple_id_exists_other_owner", "该 Apple ID 已归属其他账号，无法在当前账号下登录", false)
	}
	return nil
}

func (s *FileStore) appleIDConflictLocked(ownerID, appleID string) error {
	ownerID = strings.TrimSpace(ownerID)
	appleID = strings.ToLower(strings.TrimSpace(appleID))
	if appleID == "" {
		return nil
	}
	for _, account := range s.state.Accounts {
		if !strings.EqualFold(strings.TrimSpace(account.AppleID), appleID) {
			continue
		}
		if constantTimeEqual(strings.TrimSpace(account.OwnerID), ownerID) {
			return errCode("apple_id_exists", "该 Apple ID 已存在", false)
		}
		return errCode("apple_id_exists_other_owner", "该 Apple ID 已归属其他账号，无法在当前账号下登录", false)
	}
	return nil
}

func (s *FileStore) ensureICloudAccountLocked(ownerID string, session ICloudSession, updateAccountProxy bool) (string, error) {
	ownerID = strings.TrimSpace(ownerID)
	for _, existing := range s.state.ICloudSessions {
		if constantTimeEqual(ownerID, existing.OwnerID) && sameICloudSessionIdentity(existing, session) && strings.TrimSpace(existing.AccountID) != "" {
			s.touchICloudAccountLocked(ownerID, existing.AccountID, session, updateAccountProxy)
			return existing.AccountID, nil
		}
	}

	appleID := strings.TrimSpace(session.AppleID)
	if appleID != "" {
		for i, account := range s.state.Accounts {
			if constantTimeEqual(ownerID, account.OwnerID) && strings.EqualFold(strings.TrimSpace(account.AppleID), appleID) {
				s.updateICloudAccountFromSessionLocked(i, session, updateAccountProxy)
				return account.ID, nil
			}
		}
	}
	if err := s.appleIDOwnedByOtherLocked(ownerID, appleID); err != nil {
		return "", err
	}

	now := time.Now()
	label := appleID
	if label == "" && strings.TrimSpace(session.DSID) != "" {
		label = "iCloud " + maskSecret(session.DSID, 4)
	}
	if label == "" {
		label = "iCloud " + now.Format("0102-150405")
	}
	account := Account{
		ID:           s.nextIDLocked("acc"),
		OwnerID:      ownerID,
		Label:        label,
		AppleID:      appleID,
		ProxyURL:     strings.TrimSpace(session.ProxyURL),
		Status:       StatusActive,
		ICloudStatus: iCloudStatusFromSession(session),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.state.Accounts = append(s.state.Accounts, account)
	return account.ID, nil
}

func (s *FileStore) touchICloudAccountLocked(ownerID, accountID string, session ICloudSession, updateAccountProxy bool) {
	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return
	}
	for i, account := range s.state.Accounts {
		if account.ID == accountID && constantTimeEqual(ownerID, account.OwnerID) {
			s.updateICloudAccountFromSessionLocked(i, session, updateAccountProxy)
			return
		}
	}
}

func (s *FileStore) updateICloudAccountFromSessionLocked(index int, session ICloudSession, updateProxy bool) {
	if index < 0 || index >= len(s.state.Accounts) {
		return
	}
	account := &s.state.Accounts[index]
	if appleID := strings.TrimSpace(session.AppleID); appleID != "" {
		account.AppleID = appleID
		if strings.TrimSpace(account.Label) == "" || strings.HasPrefix(strings.TrimSpace(account.Label), "iCloud ") {
			account.Label = appleID
		}
	}
	account.Status = StatusActive
	if proxyURL := strings.TrimSpace(session.ProxyURL); updateProxy && proxyURL != "" {
		account.ProxyURL = proxyURL
	}
	account.ICloudStatus = iCloudStatusFromSession(session)
	account.UpdatedAt = time.Now()
}

func sameICloudSessionIdentity(a, b ICloudSession) bool {
	aAccountID := strings.TrimSpace(a.AccountID)
	bAccountID := strings.TrimSpace(b.AccountID)
	if aAccountID != "" && bAccountID != "" {
		return constantTimeEqual(aAccountID, bAccountID)
	}
	if strings.TrimSpace(a.DSID) != "" && constantTimeEqual(a.DSID, b.DSID) {
		return true
	}
	if strings.TrimSpace(a.AppleID) != "" && strings.EqualFold(strings.TrimSpace(a.AppleID), strings.TrimSpace(b.AppleID)) {
		return true
	}
	return false
}

func (s *FileStore) pruneDuplicateIMAPOnlySessionsLocked(ownerID string, target ICloudSession, targetIndex int) {
	ownerID = strings.TrimSpace(ownerID)
	targetIMAPEmail := sessionIMAPEmail(target)
	if targetIMAPEmail == "" {
		return
	}
	targetLocal := emailLocalPart(targetIMAPEmail)
	targetHasCreateLogin := hasCreateLoginState(target)
	removedAccountIDs := map[string]struct{}{}
	next := s.state.ICloudSessions[:0]
	for i, session := range s.state.ICloudSessions {
		if i == targetIndex || !constantTimeEqual(ownerID, session.OwnerID) {
			next = append(next, session)
			continue
		}
		if strings.TrimSpace(session.AccountID) != "" && !targetHasCreateLogin {
			next = append(next, session)
			continue
		}
		if hasCreateLoginState(session) {
			next = append(next, session)
			continue
		}
		imapEmail := sessionIMAPEmail(session)
		sameIMAPEmail := targetIMAPEmail != "" && strings.EqualFold(imapEmail, targetIMAPEmail)
		sameLocalPart := targetLocal != "" && strings.EqualFold(emailLocalPart(imapEmail), targetLocal)
		if sameIMAPEmail || sameLocalPart {
			if accountID := strings.TrimSpace(session.AccountID); accountID != "" {
				removedAccountIDs[accountID] = struct{}{}
			}
			continue
		}
		next = append(next, session)
	}
	s.state.ICloudSessions = next
	if len(removedAccountIDs) > 0 {
		s.removeAccountIDsFromCreateSettingsLocked(ownerID, removedAccountIDs)
		s.pruneRemovedIMAPOnlyAccountsLocked(ownerID, removedAccountIDs)
	}
}

func (s *FileStore) removeAccountIDsFromCreateSettingsLocked(ownerID string, accountIDs map[string]struct{}) {
	for i, settings := range s.state.CreateSettings {
		if !constantTimeEqual(ownerID, settings.OwnerID) {
			continue
		}
		next := settings.AccountIDs[:0]
		for _, accountID := range settings.AccountIDs {
			if _, remove := accountIDs[strings.TrimSpace(accountID)]; remove {
				continue
			}
			next = append(next, accountID)
		}
		s.state.CreateSettings[i].AccountIDs = normalizeAccountIDSelection("", next)
		s.state.CreateSettings[i].UpdatedAt = time.Now()
	}
}

func (s *FileStore) pruneRemovedIMAPOnlyAccountsLocked(ownerID string, accountIDs map[string]struct{}) {
	referenced := map[string]struct{}{}
	for _, session := range s.state.ICloudSessions {
		if constantTimeEqual(ownerID, session.OwnerID) {
			if accountID := strings.TrimSpace(session.AccountID); accountID != "" {
				referenced[accountID] = struct{}{}
			}
		}
	}
	for _, mailbox := range s.state.Mailboxes {
		if constantTimeEqual(ownerID, mailbox.OwnerID) {
			if accountID := strings.TrimSpace(mailbox.AccountID); accountID != "" {
				referenced[accountID] = struct{}{}
			}
		}
	}
	next := s.state.Accounts[:0]
	for _, account := range s.state.Accounts {
		accountID := strings.TrimSpace(account.ID)
		if constantTimeEqual(ownerID, account.OwnerID) {
			if _, wasRemovedSessionAccount := accountIDs[accountID]; wasRemovedSessionAccount {
				if _, stillReferenced := referenced[accountID]; !stillReferenced {
					continue
				}
			}
		}
		next = append(next, account)
	}
	s.state.Accounts = next
}

func hasCreateLoginState(session ICloudSession) bool {
	if len(session.Cookies) > 0 {
		return true
	}
	for _, state := range session.LoginStates {
		if state.Kind == LoginStateICloudWeb && len(state.Cookies) > 0 {
			return true
		}
		if state.Kind == LoginStateAppleAccount && strings.TrimSpace(state.Scnt) != "" {
			return true
		}
	}
	return false
}

func sessionIMAPEmail(session ICloudSession) string {
	for _, state := range session.LoginStates {
		if state.Kind != LoginStateICloudIMAP {
			continue
		}
		email := normalizeICloudIMAPEmail(firstNonEmpty(state.IMAPEmail, state.IMAPUsername, session.AppleID))
		if email != "" && strings.TrimSpace(state.IMAPAppPassword) != "" {
			return email
		}
	}
	return ""
}

func iCloudStatusFromSession(session ICloudSession) string {
	if appleAccountManageReady(session) {
		return ICloudStatusActive
	}
	if _, ok := iCloudWebSessionForClient(session); !ok {
		return ICloudStatusNeedLogin
	}
	if !session.IsICloudPlus {
		return ICloudStatusNoICloudPlus
	}
	if !session.CanCreateHME {
		return ICloudStatusFailed
	}
	return ICloudStatusActive
}

func (s *FileStore) mailboxIndexLocked(id string) int {
	for i, mailbox := range s.state.Mailboxes {
		if mailbox.ID == id {
			return i
		}
	}
	return -1
}

func (s *FileStore) userByIDLocked(id string) (User, bool) {
	id = strings.TrimSpace(id)
	for _, user := range s.state.Users {
		if user.ID == id {
			return user, true
		}
	}
	return User{}, false
}

func (s *FileStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicFile(s.path, data, 0o600)
}

func writeAtomicFile(path string, data []byte, perm os.FileMode) (err error) {
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer func() {
		if file != nil {
			if closeErr := file.Close(); err == nil && closeErr != nil {
				err = closeErr
			}
		}
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err := file.Chmod(perm); err != nil {
		return err
	}
	if err := restrictFilePermissions(tmp, perm); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		file = nil
		return err
	}
	file = nil
	if err := replaceFile(tmp, path); err != nil {
		return err
	}
	return nil
}

func (s *FileStore) migrateLegacyMailboxAccountIDsLocked() bool {
	accountsByOwner := make(map[string][]Account)
	accountsByID := make(map[string][]Account)
	for _, account := range s.state.Accounts {
		ownerID := strings.TrimSpace(account.OwnerID)
		accountsByOwner[ownerID] = append(accountsByOwner[ownerID], account)
		accountID := strings.TrimSpace(account.ID)
		if accountID != "" {
			accountsByID[accountID] = append(accountsByID[accountID], account)
		}
	}

	changed := false
	now := time.Now()
	for i := range s.state.Mailboxes {
		mailbox := &s.state.Mailboxes[i]
		if strings.TrimSpace(mailbox.AccountID) == "" {
			ownerID := strings.TrimSpace(mailbox.OwnerID)
			accounts := accountsByOwner[ownerID]
			if len(accounts) == 1 {
				mailbox.AccountID = accounts[0].ID
				if mailbox.UpdatedAt.IsZero() {
					mailbox.UpdatedAt = now
				}
				changed = true
			}
		}
		if strings.TrimSpace(mailbox.OwnerID) == "" {
			accountID := strings.TrimSpace(mailbox.AccountID)
			accounts := accountsByID[accountID]
			if len(accounts) == 1 && strings.TrimSpace(accounts[0].OwnerID) != "" {
				mailbox.OwnerID = strings.TrimSpace(accounts[0].OwnerID)
				if mailbox.UpdatedAt.IsZero() {
					mailbox.UpdatedAt = now
				}
				changed = true
			}
		}
	}
	return changed
}

func (s *FileStore) migrateLegacyICloudSessionLocked() bool {
	changed := false
	if s.state.ICloudSession != nil {
		s.state.ICloudSessions = append(s.state.ICloudSessions, cloneICloudSession(*s.state.ICloudSession))
		s.state.ICloudSession = nil
		changed = true
	}
	if len(s.state.ICloudSessions) == 0 {
		return changed
	}

	normalized := make([]ICloudSession, 0, len(s.state.ICloudSessions))
	for _, raw := range s.state.ICloudSessions {
		session := cloneICloudSession(raw)
		before := cloneICloudSession(session)
		session = s.bindLegacyICloudSessionLocked(session)
		if !reflect.DeepEqual(before, session) {
			changed = true
		}
		merged := false
		for i := range normalized {
			if strings.TrimSpace(normalized[i].OwnerID) != strings.TrimSpace(session.OwnerID) ||
				!sameICloudSessionIdentity(normalized[i], session) {
				continue
			}
			mergedSession := mergeICloudSession(normalized[i], session)
			if !reflect.DeepEqual(normalized[i], mergedSession) {
				changed = true
			}
			normalized[i] = mergedSession
			merged = true
			break
		}
		if !merged {
			normalized = append(normalized, session)
		} else {
			changed = true
		}
	}
	if !reflect.DeepEqual(s.state.ICloudSessions, normalized) {
		changed = true
	}
	s.state.ICloudSessions = normalized
	return changed
}

func (s *FileStore) bindLegacyICloudSessionLocked(session ICloudSession) ICloudSession {
	accountID := strings.TrimSpace(session.AccountID)
	if accountID != "" {
		for _, account := range s.state.Accounts {
			if strings.TrimSpace(account.ID) != accountID {
				continue
			}
			if strings.TrimSpace(session.OwnerID) != "" &&
				strings.TrimSpace(account.OwnerID) != "" &&
				!constantTimeEqual(session.OwnerID, account.OwnerID) {
				return session
			}
			if strings.TrimSpace(session.OwnerID) == "" && strings.TrimSpace(account.OwnerID) != "" {
				session.OwnerID = strings.TrimSpace(account.OwnerID)
			}
			return sessionWithProxyURL(session, account.ProxyURL)
		}
		return session
	}

	appleID := strings.ToLower(strings.TrimSpace(session.AppleID))
	if appleID == "" {
		return session
	}
	ownerID := strings.TrimSpace(session.OwnerID)
	var matches []Account
	for _, account := range s.state.Accounts {
		if strings.TrimSpace(account.OwnerID) != ownerID ||
			!strings.EqualFold(strings.TrimSpace(account.AppleID), appleID) {
			continue
		}
		matches = append(matches, account)
	}
	if len(matches) != 1 {
		return session
	}
	session.AccountID = strings.TrimSpace(matches[0].ID)
	return sessionWithProxyURL(session, matches[0].ProxyURL)
}

func (s *FileStore) usableICloudSessionLocked(session ICloudSession) (ICloudSession, bool) {
	if strings.TrimSpace(session.AccountID) != "" {
		return session, true
	}
	ownerID := strings.TrimSpace(session.OwnerID)
	appleID := strings.ToLower(strings.TrimSpace(session.AppleID))
	var matches []Account
	hasScopedAccount := false
	for _, account := range s.state.Accounts {
		if strings.TrimSpace(account.OwnerID) != ownerID {
			continue
		}
		hasScopedAccount = true
		if appleID != "" && strings.EqualFold(strings.TrimSpace(account.AppleID), appleID) {
			matches = append(matches, account)
		}
	}
	if len(matches) == 1 {
		session.AccountID = strings.TrimSpace(matches[0].ID)
		return sessionWithProxyURL(session, matches[0].ProxyURL), true
	}
	if len(matches) > 1 || hasScopedAccount {
		return ICloudSession{}, false
	}
	return session, true
}

func cloneState(in State) State {
	proxyByAccountID := accountProxyMap(in.Accounts)
	out := cloneStateForRollback(in)
	for i := range out.ICloudSessions {
		out.ICloudSessions[i] = resolveICloudSessionProxy(out.ICloudSessions[i], proxyByAccountID)
	}
	if out.ICloudSession != nil {
		*out.ICloudSession = resolveICloudSessionProxy(*out.ICloudSession, proxyByAccountID)
	}
	return out
}

func cloneStateForRollback(in State) State {
	out := in
	out.Users = append([]User(nil), in.Users...)
	out.WebSessions = append([]WebSession(nil), in.WebSessions...)
	out.Accounts = append([]Account(nil), in.Accounts...)
	out.Mailboxes = append([]Mailbox(nil), in.Mailboxes...)
	out.Messages = append([]Message(nil), in.Messages...)
	if in.ICloudSession != nil {
		session := cloneICloudSession(*in.ICloudSession)
		out.ICloudSession = &session
	}
	out.ICloudSessions = make([]ICloudSession, 0, len(in.ICloudSessions))
	for _, session := range in.ICloudSessions {
		out.ICloudSessions = append(out.ICloudSessions, cloneICloudSession(session))
	}
	out.CreateSettings = cloneCreateSettings(in.CreateSettings)
	return out
}

func cloneICloudSession(in ICloudSession) ICloudSession {
	out := in
	out.Cookies = append([]SessionCookie(nil), in.Cookies...)
	out.LoginStates = cloneLoginStates(in.LoginStates)
	return out
}

func accountProxyMap(accounts []Account) map[string]string {
	if len(accounts) == 0 {
		return nil
	}
	out := make(map[string]string, len(accounts))
	for _, account := range accounts {
		if id := strings.TrimSpace(account.ID); id != "" {
			out[id] = strings.TrimSpace(account.ProxyURL)
		}
	}
	return out
}

func resolveICloudSessionProxy(session ICloudSession, proxyByAccountID map[string]string) ICloudSession {
	if len(proxyByAccountID) == 0 {
		return session
	}
	if proxyURL, ok := proxyByAccountID[strings.TrimSpace(session.AccountID)]; ok {
		return sessionWithProxyURL(session, proxyURL)
	}
	return session
}

func mergeICloudSession(existing, incoming ICloudSession) ICloudSession {
	out := incoming
	out.OwnerID = firstNonEmpty(incoming.OwnerID, existing.OwnerID)
	out.AccountID = firstNonEmpty(incoming.AccountID, existing.AccountID)
	out.ProxyURL = firstNonEmpty(incoming.ProxyURL, existing.ProxyURL)
	if out.SavedAt.IsZero() {
		out.SavedAt = existing.SavedAt
	}
	out.AppleID = firstNonEmpty(incoming.AppleID, existing.AppleID)
	out.DSID = firstNonEmpty(incoming.DSID, existing.DSID)
	out.ClientID = firstNonEmpty(incoming.ClientID, existing.ClientID)
	out.ClientBuildNumber = firstNonEmpty(incoming.ClientBuildNumber, existing.ClientBuildNumber)
	out.MasteringNumber = firstNonEmpty(incoming.MasteringNumber, existing.MasteringNumber)
	out.PremiumMailBaseURL = firstNonEmpty(incoming.PremiumMailBaseURL, existing.PremiumMailBaseURL)
	out.MailGatewayBaseURL = firstNonEmpty(incoming.MailGatewayBaseURL, existing.MailGatewayBaseURL)
	out.MailBaseURL = firstNonEmpty(incoming.MailBaseURL, existing.MailBaseURL)
	out.Host = firstNonEmpty(incoming.Host, existing.Host)
	out.CapabilitiesAuthoritative = existing.CapabilitiesAuthoritative || incoming.CapabilitiesAuthoritative
	switch {
	case incoming.CapabilitiesAuthoritative:
		out.IsICloudPlus = incoming.IsICloudPlus
		out.CanCreateHME = incoming.CanCreateHME
	case existing.CapabilitiesAuthoritative:
		out.IsICloudPlus = existing.IsICloudPlus
		out.CanCreateHME = existing.CanCreateHME
	default:
		out.IsICloudPlus = incoming.IsICloudPlus || existing.IsICloudPlus
		out.CanCreateHME = incoming.CanCreateHME || existing.CanCreateHME
	}
	if len(out.Cookies) == 0 {
		out.Cookies = append([]SessionCookie(nil), existing.Cookies...)
	}
	out.LoginStates = mergeLoginStates(existing.LoginStates, incoming.LoginStates)
	out.Note = firstNonEmpty(incoming.Note, existing.Note)
	if incoming.LastCheckedAt.IsZero() {
		out.LastCheckedAt = existing.LastCheckedAt
		out.LastCheckOK = existing.LastCheckOK
	}
	out.LastStatusMessage = firstNonEmpty(incoming.LastStatusMessage, existing.LastStatusMessage)
	return out
}

func mergeLoginStates(existing, incoming []LoginState) []LoginState {
	out := cloneLoginStates(existing)
	for _, state := range incoming {
		replaced := false
		for i, current := range out {
			if current.Kind == state.Kind {
				next := state
				next.ProxyURL = firstNonEmpty(state.ProxyURL, current.ProxyURL)
				if len(state.Cookies) > 0 {
					next.Cookies = append([]SessionCookie(nil), state.Cookies...)
				} else {
					next.Cookies = append([]SessionCookie(nil), current.Cookies...)
				}
				out[i] = next
				replaced = true
				break
			}
		}
		if !replaced {
			next := state
			next.Cookies = append([]SessionCookie(nil), state.Cookies...)
			out = append(out, next)
		}
	}
	return out
}

func cloneLoginStates(in []LoginState) []LoginState {
	out := make([]LoginState, 0, len(in))
	for _, state := range in {
		next := state
		next.Cookies = append([]SessionCookie(nil), state.Cookies...)
		out = append(out, next)
	}
	return out
}

func cloneCreateSettings(in []CreateSettings) []CreateSettings {
	out := make([]CreateSettings, 0, len(in))
	for _, settings := range in {
		next := settings
		next.AccountIDs = append([]string(nil), settings.AccountIDs...)
		out = append(out, next)
	}
	return out
}

func filterStateByOwnerLocked(in State, ownerID string) State {
	if ownerID == "" {
		return cloneState(in)
	}
	if ownerID == "__global" {
		out := State{NextID: in.NextID}
		proxyByAccountID := accountProxyMap(in.Accounts)
		for _, account := range in.Accounts {
			if strings.TrimSpace(account.OwnerID) == "" {
				out.Accounts = append(out.Accounts, account)
			}
		}
		allowedMailboxes := make(map[string]struct{})
		for _, mailbox := range in.Mailboxes {
			if strings.TrimSpace(mailbox.OwnerID) != "" {
				continue
			}
			out.Mailboxes = append(out.Mailboxes, mailbox)
			allowedMailboxes[mailbox.ID] = struct{}{}
		}
		for _, msg := range in.Messages {
			if _, ok := allowedMailboxes[msg.MailboxID]; ok {
				out.Messages = append(out.Messages, msg)
			}
		}
		for _, session := range in.ICloudSessions {
			if strings.TrimSpace(session.OwnerID) != "" {
				continue
			}
			cloned := cloneICloudSession(resolveICloudSessionProxy(session, proxyByAccountID))
			if out.ICloudSession == nil {
				first := cloneICloudSession(resolveICloudSessionProxy(session, proxyByAccountID))
				out.ICloudSession = &first
			}
			out.ICloudSessions = append(out.ICloudSessions, cloned)
		}
		for _, settings := range in.CreateSettings {
			if strings.TrimSpace(settings.OwnerID) == "" {
				next := settings
				next.AccountIDs = append([]string(nil), settings.AccountIDs...)
				out.CreateSettings = append(out.CreateSettings, next)
			}
		}
		return out
	}
	out := State{NextID: in.NextID}
	proxyByAccountID := accountProxyMap(in.Accounts)
	for _, user := range in.Users {
		if user.ID == ownerID {
			out.Users = append(out.Users, user)
			break
		}
	}
	for _, account := range in.Accounts {
		if constantTimeEqual(ownerID, account.OwnerID) {
			out.Accounts = append(out.Accounts, account)
		}
	}
	allowedMailboxes := make(map[string]struct{})
	for _, mailbox := range in.Mailboxes {
		if constantTimeEqual(ownerID, mailbox.OwnerID) {
			out.Mailboxes = append(out.Mailboxes, mailbox)
			allowedMailboxes[mailbox.ID] = struct{}{}
		}
	}
	for _, msg := range in.Messages {
		if _, ok := allowedMailboxes[msg.MailboxID]; ok {
			out.Messages = append(out.Messages, msg)
		}
	}
	for _, session := range in.ICloudSessions {
		if constantTimeEqual(ownerID, session.OwnerID) {
			cloned := cloneICloudSession(resolveICloudSessionProxy(session, proxyByAccountID))
			if out.ICloudSession == nil {
				first := cloneICloudSession(resolveICloudSessionProxy(session, proxyByAccountID))
				out.ICloudSession = &first
			}
			out.ICloudSessions = append(out.ICloudSessions, cloned)
		}
	}
	for _, settings := range in.CreateSettings {
		if constantTimeEqual(ownerID, settings.OwnerID) {
			next := settings
			next.AccountIDs = append([]string(nil), settings.AccountIDs...)
			out.CreateSettings = append(out.CreateSettings, next)
		}
	}
	return out
}

func createSettingsForOwnerLocked(state State, ownerID string) CreateSettings {
	ownerID = strings.TrimSpace(ownerID)
	for _, settings := range state.CreateSettings {
		if constantTimeEqual(ownerID, settings.OwnerID) {
			return normalizeCreateSettings(ownerID, settings)
		}
	}
	return defaultCreateSettings(ownerID)
}

func defaultCreateSettings(ownerID string) CreateSettings {
	return CreateSettings{
		OwnerID:                       strings.TrimSpace(ownerID),
		CreateChannel:                 string(mailboxCreateChannelAuto),
		SchedulerCreateChannel:        string(mailboxCreateChannelAuto),
		AppleAccountTwoFactorMethod:   appleTwoFactorMethodTrustedDevice,
		ICloudWebTwoFactorMethod:      appleTwoFactorMethodTrustedDevice,
		SchedulerIntervalMinutes:      int(defaultMailboxSchedulerInterval.Round(time.Minute).Minutes()),
		SchedulerRoundIntervalSeconds: int(defaultMailboxSchedulerRoundInterval.Round(time.Second).Seconds()),
		MailboxPageSize:               10,
	}
}

func normalizeCreateSettings(ownerID string, settings CreateSettings) CreateSettings {
	defaults := defaultCreateSettings(ownerID)
	out := settings
	out.OwnerID = strings.TrimSpace(ownerID)
	out.Label = strings.TrimSpace(settings.Label)
	out.Note = strings.TrimSpace(settings.Note)
	out.AccountIDs = normalizeAccountIDSelection("", settings.AccountIDs)
	out.CreateChannel = string(normalizeMailboxCreateChannel(mailboxCreateChannel(strings.ToLower(strings.TrimSpace(settings.CreateChannel)))))
	out.SchedulerCreateChannel = string(normalizeMailboxCreateChannel(mailboxCreateChannel(strings.ToLower(strings.TrimSpace(settings.SchedulerCreateChannel)))))
	out.AppleAccountTwoFactorMethod = normalizeAppleTwoFactorMethod(settings.AppleAccountTwoFactorMethod)
	out.ICloudWebTwoFactorMethod = normalizeAppleTwoFactorMethod(settings.ICloudWebTwoFactorMethod)
	if out.SchedulerIntervalMinutes < 1 {
		out.SchedulerIntervalMinutes = defaults.SchedulerIntervalMinutes
	}
	if out.SchedulerIntervalMinutes > 1440 {
		out.SchedulerIntervalMinutes = 1440
	}
	if out.SchedulerRoundIntervalSeconds < 1 {
		out.SchedulerRoundIntervalSeconds = defaults.SchedulerRoundIntervalSeconds
	}
	if out.SchedulerRoundIntervalSeconds > 600 {
		out.SchedulerRoundIntervalSeconds = 600
	}
	if out.MailboxPageSize < 1 {
		out.MailboxPageSize = defaults.MailboxPageSize
	}
	if out.MailboxPageSize > 500 {
		out.MailboxPageSize = 500
	}
	return out
}

type codedError struct {
	code      string
	message   string
	retryable bool
}

func (e codedError) Error() string { return e.message }

func errCode(code, message string, retryable bool) error {
	return codedError{code: code, message: message, retryable: retryable}
}

func firstNonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}
