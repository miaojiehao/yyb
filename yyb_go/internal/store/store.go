package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS wechat_accounts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    openid          TEXT    NOT NULL UNIQUE,
    uin             INTEGER,
    alias           TEXT,
    nickname        TEXT,
    avatar          TEXT,
    user_info       TEXT,
    login_buffer    TEXT    NOT NULL,
    credentials     TEXT,
    status          TEXT,
    last_checked_at INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wxacc_uin ON wechat_accounts(uin);

CREATE TABLE IF NOT EXISTS sessions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    wechat_account_id INTEGER NOT NULL REFERENCES wechat_accounts(id) ON DELETE CASCADE,
    uin               INTEGER,
    tcp_proxy         TEXT    NOT NULL DEFAULT '',
    session_blob      TEXT    NOT NULL,
    expires_at        INTEGER NOT NULL,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    UNIQUE(wechat_account_id, tcp_proxy)
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS features (
    code        INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS admin_users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'admin',
    locked_until    INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_login_at   INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    operator    TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    result      TEXT    NOT NULL,
    detail      TEXT,
    source_ip   TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
`

var defaultFeatures = []Feature{
	{Code: 1001, Name: "getCode", Description: stringPtr("wx.login code"), Enabled: true},
	{Code: 1002, Name: "getPhoneNumber", Description: stringPtr("取手机号"), Enabled: true},
	{Code: 1003, Name: "operateWxData", Description: stringPtr("通用云函数代理"), Enabled: true},
}

type DB struct {
	sql *sql.DB
}

type WechatAccount struct {
	ID               int64          `json:"id"`
	OpenID           string         `json:"openid"`
	UIN              *int64         `json:"uin,omitempty"`
	Alias            *string        `json:"alias,omitempty"`
	Nickname         *string        `json:"nickname,omitempty"`
	Avatar           *string        `json:"avatar,omitempty"`
	UserInfo         map[string]any `json:"user_info,omitempty"`
	LoginBuffer      string         `json:"login_buffer,omitempty"`
	Credentials      map[string]any `json:"credentials,omitempty"`
	Status           *string        `json:"status,omitempty"`
	BoundProxy       string         `json:"bound_proxy,omitempty"`
	AllowedSourceIPs string         `json:"allowed_source_ips,omitempty"`
	LastCheckedAt    *int64         `json:"last_checked_at,omitempty"`
	CreatedAt        int64          `json:"created_at"`
	UpdatedAt        int64          `json:"updated_at"`
}

type AccountPublic struct {
	ID            int64   `json:"id"`
	OpenID        string  `json:"openid"`
	UIN           *int64  `json:"uin"`
	Alias         *string `json:"alias"`
	Nickname      *string `json:"nickname"`
	Avatar        *string `json:"avatar"`
	Status        *string `json:"status"`
	LastCheckedAt *int64  `json:"last_checked_at"`
	CreatedAt     int64   `json:"created_at"`
	UpdatedAt     int64   `json:"updated_at"`
}

type SessionRow struct {
	ID              int64
	WechatAccountID int64
	UIN             *int64
	TCPProxy        string
	SessionBlob     map[string]any
	ExpiresAt       int64
	CreatedAt       int64
	UpdatedAt       int64
}

type Feature struct {
	Code        int     `json:"code"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	Enabled     bool    `json:"enabled"`
}

type User struct {
	ID            int64   `json:"id"`
	Username      string  `json:"username"`
	PasswordHash  string  `json:"-"`
	Role          string  `json:"role"`
	LockedUntil   int64   `json:"locked_until"`
	FailedAttempts int64  `json:"failed_attempts"`
	LastLoginAt   *int64  `json:"last_login_at"`
	CreatedAt     int64   `json:"created_at"`
	UpdatedAt     int64   `json:"updated_at"`
}

type AuditEntry struct {
	ID         int64  `json:"id"`
	TS         int64  `json:"ts"`
	Operator   string `json:"operator"`
	Action     string `json:"action"`
	TargetType string `json:"target_type,omitempty"`
	TargetID   string `json:"target_id,omitempty"`
	Result     string `json:"result"`
	Detail     string `json:"detail,omitempty"`
	SourceIP   string `json:"source_ip,omitempty"`
}

func Open(path string) (*DB, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err = db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if path != ":memory:" {
		_, _ = db.ExecContext(ctx, "PRAGMA journal_mode=WAL")
	}
	_, _ = db.ExecContext(ctx, "PRAGMA synchronous=NORMAL")
	_, _ = db.ExecContext(ctx, "PRAGMA foreign_keys=ON")
	if err = migrateSessionsTable(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err = db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err = migrateAccountSecurityColumns(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	out := &DB{sql: db}
	if err = out.EnsureDefaultFeatures(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return out, nil
}

func (db *DB) Close() error {
	if db == nil || db.sql == nil {
		return nil
	}
	return db.sql.Close()
}

func (db *DB) EnsureDefaultFeatures(ctx context.Context) error {
	for _, f := range defaultFeatures {
		desc := nullableString(f.Description)
		if _, err := db.sql.ExecContext(ctx,
			"INSERT OR IGNORE INTO features(code, name, description, enabled) VALUES(?,?,?,1)",
			f.Code, f.Name, desc,
		); err != nil {
			return err
		}
	}
	return nil
}

func migrateSessionsTable(ctx context.Context, db *sql.DB) error {
	oldExists, err := sqliteTableExists(ctx, db, "wmpf_sessions")
	if err != nil {
		return err
	}
	if !oldExists {
		return nil
	}
	newExists, err := sqliteTableExists(ctx, db, "sessions")
	if err != nil {
		return err
	}
	if !newExists {
		if _, err = db.ExecContext(ctx, "DROP INDEX IF EXISTS idx_sess_expires"); err != nil {
			return err
		}
		_, err = db.ExecContext(ctx, "ALTER TABLE wmpf_sessions RENAME TO sessions")
		return err
	}
	if _, err = db.ExecContext(ctx, `
INSERT OR IGNORE INTO sessions
(id, wechat_account_id, uin, tcp_proxy, session_blob, expires_at, created_at, updated_at)
SELECT id, wechat_account_id, uin, tcp_proxy, session_blob, expires_at, created_at, updated_at
FROM wmpf_sessions`); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "DROP TABLE wmpf_sessions")
	return err
}

func sqliteTableExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n)
	return n > 0, err
}

func sqliteColumnExists(ctx context.Context, db *sql.DB, table, column string) (bool, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func migrateAccountSecurityColumns(ctx context.Context, db *sql.DB) error {
	for _, col := range []struct {
		name string
		ddl  string
	}{
		{"bound_proxy", "ALTER TABLE wechat_accounts ADD COLUMN bound_proxy TEXT"},
		{"allowed_source_ips", "ALTER TABLE wechat_accounts ADD COLUMN allowed_source_ips TEXT"},
	} {
		ok, err := sqliteColumnExists(ctx, db, "wechat_accounts", col.name)
		if err != nil {
			return err
		}
		if !ok {
			if _, err := db.ExecContext(ctx, col.ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

func (db *DB) UpsertAccount(ctx context.Context, openid, loginBuffer string, alias, nickname, avatar *string, userInfo map[string]any, credentials map[string]any, status *string) (*WechatAccount, error) {
	now := time.Now().Unix()
	userJSON, err := marshalNullable(userInfo)
	if err != nil {
		return nil, err
	}
	credJSON, err := marshalNullable(credentials)
	if err != nil {
		return nil, err
	}
	_, err = db.sql.ExecContext(ctx,
		`INSERT INTO wechat_accounts
		(openid, login_buffer, alias, nickname, avatar, user_info, credentials, status, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(openid) DO UPDATE SET
		login_buffer=excluded.login_buffer, alias=excluded.alias, nickname=excluded.nickname,
		avatar=excluded.avatar, user_info=excluded.user_info, credentials=excluded.credentials,
		status=excluded.status, updated_at=excluded.updated_at`,
		openid, loginBuffer, nullableString(alias), nullableString(nickname), nullableString(avatar),
		userJSON, credJSON, nullableString(status), now, now,
	)
	if err != nil {
		return nil, err
	}
	return db.GetAccountByOpenID(ctx, openid)
}

func (db *DB) GetAccount(ctx context.Context, id int64) (*WechatAccount, error) {
	return db.scanAccount(db.sql.QueryRowContext(ctx, selectAccountSQL+" WHERE id=?", id))
}

func (db *DB) GetAccountByOpenID(ctx context.Context, openid string) (*WechatAccount, error) {
	return db.scanAccount(db.sql.QueryRowContext(ctx, selectAccountSQL+" WHERE openid=?", openid))
}

func (db *DB) GetAccountByUIN(ctx context.Context, uin int64) (*WechatAccount, error) {
	return db.scanAccount(db.sql.QueryRowContext(ctx, selectAccountSQL+" WHERE uin=?", uin))
}

func (db *DB) ResolveAccount(ctx context.Context, ref string) (*WechatAccount, error) {
	if ref == "" {
		return nil, sql.ErrNoRows
	}
	if isDigits(ref) {
		n, _ := strconv.ParseInt(ref, 10, 64)
		if acc, err := db.GetAccountByUIN(ctx, n); err == nil {
			return acc, nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return db.GetAccount(ctx, n)
	}
	return db.GetAccountByOpenID(ctx, ref)
}

func (db *DB) ListAccounts(ctx context.Context) ([]*WechatAccount, error) {
	rows, err := db.sql.QueryContext(ctx, selectAccountSQL+" ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WechatAccount
	for rows.Next() {
		acc, err := scanAccountRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, acc)
	}
	return out, rows.Err()
}

func (db *DB) SetAccountUIN(ctx context.Context, id, uin int64) error {
	_, err := db.sql.ExecContext(ctx, "UPDATE wechat_accounts SET uin=?, updated_at=? WHERE id=?", uin, time.Now().Unix(), id)
	return err
}

func (db *DB) SetAccountProfile(ctx context.Context, id int64, nickname, avatar *string, userInfo map[string]any) error {
	userJSON, err := marshalNullable(userInfo)
	if err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx,
		"UPDATE wechat_accounts SET nickname=?, avatar=?, user_info=?, updated_at=? WHERE id=?",
		nullableString(nickname), nullableString(avatar), userJSON, time.Now().Unix(), id,
	)
	return err
}

func (db *DB) SetAccountCredential(ctx context.Context, id int64, loginBuffer string, credentials map[string]any) error {
	credJSON, err := marshalNullable(credentials)
	if err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx,
		"UPDATE wechat_accounts SET login_buffer=?, credentials=?, updated_at=? WHERE id=?",
		loginBuffer, credJSON, time.Now().Unix(), id,
	)
	return err
}

func (db *DB) SetAccountStatus(ctx context.Context, id int64, status string) error {
	now := time.Now().Unix()
	_, err := db.sql.ExecContext(ctx,
		"UPDATE wechat_accounts SET status=?, last_checked_at=?, updated_at=? WHERE id=?",
		status, now, now, id,
	)
	return err
}

func (db *DB) DeleteAccount(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx, "DELETE FROM wechat_accounts WHERE id=?", id)
	return err
}

func (db *DB) GetAccountConfig(ctx context.Context, id int64) (*WechatAccount, error) {
	return db.GetAccount(ctx, id)
}

func (db *DB) SetAccountConfig(ctx context.Context, id int64, boundProxy, allowedSourceIPs string) error {
	_, err := db.sql.ExecContext(ctx,
		"UPDATE wechat_accounts SET bound_proxy=?, allowed_source_ips=?, updated_at=? WHERE id=?",
		boundProxy, allowedSourceIPs, time.Now().Unix(), id,
	)
	return err
}

func (db *DB) SetAccountProxy(ctx context.Context, id int64, boundProxy string) error {
	_, err := db.sql.ExecContext(ctx,
		"UPDATE wechat_accounts SET bound_proxy=?, updated_at=? WHERE id=?",
		boundProxy, time.Now().Unix(), id,
	)
	return err
}

func (db *DB) GetUser(ctx context.Context, id int64) (*User, error) {
	return db.scanUser(db.sql.QueryRowContext(ctx, selectUserSQL+" WHERE id=?", id))
}

func (db *DB) GetUserByName(ctx context.Context, username string) (*User, error) {
	return db.scanUser(db.sql.QueryRowContext(ctx, selectUserSQL+" WHERE username=? COLLATE NOCASE", username))
}

func (db *DB) CreateUser(ctx context.Context, username, passwordHash, role string) (*User, error) {
	now := time.Now().Unix()
	_, err := db.sql.ExecContext(ctx,
		"INSERT INTO admin_users(username, password_hash, role, created_at, updated_at) VALUES(?,?,?,?,?)",
		username, passwordHash, role, now, now,
	)
	if err != nil {
		return nil, err
	}
	return db.GetUserByName(ctx, username)
}

func (db *DB) DeleteUser(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx, "DELETE FROM admin_users WHERE id=?", id)
	return err
}

func (db *DB) SetUserRole(ctx context.Context, id int64, role string) error {
	_, err := db.sql.ExecContext(ctx, "UPDATE admin_users SET role=?, updated_at=? WHERE id=?", role, time.Now().Unix(), id)
	return err
}

func (db *DB) SetUserPassword(ctx context.Context, id int64, passwordHash string) error {
	_, err := db.sql.ExecContext(ctx, "UPDATE admin_users SET password_hash=?, updated_at=? WHERE id=?", passwordHash, time.Now().Unix(), id)
	return err
}

func (db *DB) UpdateUserLoginMeta(ctx context.Context, id int64, lockedUntil int64, failedAttempts int64, lastLoginAt *int64) error {
	_, err := db.sql.ExecContext(ctx,
		"UPDATE admin_users SET locked_until=?, failed_attempts=?, last_login_at=?, updated_at=? WHERE id=?",
		lockedUntil, failedAttempts, nullableInt(lastLoginAt), time.Now().Unix(), id,
	)
	return err
}

func (db *DB) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := db.sql.QueryContext(ctx, selectUserSQL+" ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUserRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (db *DB) AppendAudit(ctx context.Context, e AuditEntry) error {
	_, err := db.sql.ExecContext(ctx,
		"INSERT INTO audit_logs(ts, operator, action, target_type, target_id, result, detail, source_ip) VALUES(?,?,?,?,?,?,?,?)",
		e.TS, e.Operator, e.Action, e.TargetType, e.TargetID, e.Result, e.Detail, e.SourceIP,
	)
	return err
}

func (db *DB) QueryAudit(ctx context.Context, operator, action string, from, to int64, limit, offset int) ([]AuditEntry, error) {
	where := make([]string, 0, 3)
	args := make([]any, 0, 6)
	if operator != "" {
		where = append(where, "operator=?")
		args = append(args, operator)
	}
	if action != "" {
		where = append(where, "action=?")
		args = append(args, action)
	}
	if from > 0 {
		where = append(where, "ts>=?")
		args = append(args, from)
	}
	if to > 0 {
		where = append(where, "ts<=?")
		args = append(args, to)
	}
	sqlText := "SELECT id, ts, operator, action, target_type, target_id, result, detail, source_ip FROM audit_logs"
	if len(where) > 0 {
		sqlText += " WHERE " + strings.Join(where, " AND ")
	}
	sqlText += " ORDER BY ts DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	rows, err := db.sql.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		e, err := scanAuditRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (db *DB) GetSession(ctx context.Context, accountID int64, tcpProxy string) (*SessionRow, error) {
	row := db.sql.QueryRowContext(ctx,
		"SELECT id, wechat_account_id, uin, tcp_proxy, session_blob, expires_at, created_at, updated_at FROM sessions WHERE wechat_account_id=? AND tcp_proxy=? AND expires_at>?",
		accountID, tcpProxy, time.Now().Unix(),
	)
	return scanSession(row)
}

func (db *DB) PutSession(ctx context.Context, accountID int64, uin *int64, sessionBlob map[string]any, expiresAt int64, tcpProxy string) error {
	now := time.Now().Unix()
	blob, err := json.Marshal(sessionBlob)
	if err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx,
		`INSERT INTO sessions
		(wechat_account_id, uin, tcp_proxy, session_blob, expires_at, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(wechat_account_id, tcp_proxy) DO UPDATE SET
		uin=excluded.uin, session_blob=excluded.session_blob,
		expires_at=excluded.expires_at, updated_at=excluded.updated_at`,
		accountID, nullableInt(uin), tcpProxy, string(blob), expiresAt, now, now,
	)
	return err
}

func (db *DB) InvalidateSession(ctx context.Context, accountID int64, tcpProxy string) error {
	_, err := db.sql.ExecContext(ctx, "DELETE FROM sessions WHERE wechat_account_id=? AND tcp_proxy=?", accountID, tcpProxy)
	return err
}

func (db *DB) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	res, err := db.sql.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<=?", time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (db *DB) ListFeatures(ctx context.Context, onlyEnabled bool) ([]Feature, error) {
	sqlText := "SELECT code, name, description, enabled FROM features"
	if onlyEnabled {
		sqlText += " WHERE enabled=1"
	}
	sqlText += " ORDER BY code"
	rows, err := db.sql.QueryContext(ctx, sqlText)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Feature
	for rows.Next() {
		f, err := scanFeature(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (db *DB) ResolveFeature(ctx context.Context, ref any) (*Feature, error) {
	switch v := ref.(type) {
	case float64:
		return db.GetFeature(ctx, int(v))
	case int:
		return db.GetFeature(ctx, v)
	case string:
		if isDigits(v) {
			n, _ := strconv.Atoi(v)
			return db.GetFeature(ctx, n)
		}
		return db.GetFeatureByName(ctx, v)
	default:
		return nil, sql.ErrNoRows
	}
}

func (db *DB) GetFeature(ctx context.Context, code int) (*Feature, error) {
	row := db.sql.QueryRowContext(ctx, "SELECT code, name, description, enabled FROM features WHERE code=?", code)
	f, err := scanFeature(row)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func (db *DB) GetFeatureByName(ctx context.Context, name string) (*Feature, error) {
	row := db.sql.QueryRowContext(ctx, "SELECT code, name, description, enabled FROM features WHERE name=? COLLATE NOCASE", name)
	f, err := scanFeature(row)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func (a *WechatAccount) Public() AccountPublic {
	return AccountPublic{
		ID:            a.ID,
		OpenID:        a.OpenID,
		UIN:           a.UIN,
		Alias:         a.Alias,
		Nickname:      a.Nickname,
		Avatar:        a.Avatar,
		Status:        a.Status,
		LastCheckedAt: a.LastCheckedAt,
		CreatedAt:     a.CreatedAt,
		UpdatedAt:     a.UpdatedAt,
	}
}

const selectAccountSQL = `SELECT id, openid, uin, alias, nickname, avatar, user_info, login_buffer, credentials, status, bound_proxy, allowed_source_ips, last_checked_at, created_at, updated_at FROM wechat_accounts`

const selectUserSQL = `SELECT id, username, password_hash, role, locked_until, failed_attempts, last_login_at, created_at, updated_at FROM admin_users`

type accountScanner interface {
	Scan(dest ...any) error
}

type featureScanner interface {
	Scan(dest ...any) error
}

func (db *DB) scanAccount(row accountScanner) (*WechatAccount, error) {
	return scanAccountRows(row)
}

func scanAccountRows(row accountScanner) (*WechatAccount, error) {
	var (
		a                       WechatAccount
		uin, lastChecked        sql.NullInt64
		alias, nickname, avatar sql.NullString
		userJSON, credJSON      sql.NullString
		status                  sql.NullString
		boundProxy              sql.NullString
		allowedIPs              sql.NullString
	)
	err := row.Scan(
		&a.ID, &a.OpenID, &uin, &alias, &nickname, &avatar, &userJSON,
		&a.LoginBuffer, &credJSON, &status, &boundProxy, &allowedIPs,
		&lastChecked, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if uin.Valid {
		a.UIN = &uin.Int64
	}
	a.Alias = stringPtrFromNull(alias)
	a.Nickname = stringPtrFromNull(nickname)
	a.Avatar = stringPtrFromNull(avatar)
	a.Status = stringPtrFromNull(status)
	a.BoundProxy = boundProxy.String
	a.AllowedSourceIPs = allowedIPs.String
	if lastChecked.Valid {
		a.LastCheckedAt = &lastChecked.Int64
	}
	if userJSON.Valid && userJSON.String != "" {
		_ = json.Unmarshal([]byte(userJSON.String), &a.UserInfo)
	}
	if credJSON.Valid && credJSON.String != "" {
		_ = json.Unmarshal([]byte(credJSON.String), &a.Credentials)
	}
	return &a, nil
}

func scanSession(row accountScanner) (*SessionRow, error) {
	var s SessionRow
	var uin sql.NullInt64
	var blob string
	if err := row.Scan(&s.ID, &s.WechatAccountID, &uin, &s.TCPProxy, &blob, &s.ExpiresAt, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	if uin.Valid {
		s.UIN = &uin.Int64
	}
	if err := json.Unmarshal([]byte(blob), &s.SessionBlob); err != nil {
		return nil, fmt.Errorf("decode session_blob: %w", err)
	}
	return &s, nil
}

func scanFeature(row featureScanner) (Feature, error) {
	var f Feature
	var desc sql.NullString
	var enabled int
	if err := row.Scan(&f.Code, &f.Name, &desc, &enabled); err != nil {
		return Feature{}, err
	}
	f.Description = stringPtrFromNull(desc)
	f.Enabled = enabled != 0
	return f, nil
}

func (db *DB) scanUser(row accountScanner) (*User, error) {
	return scanUserRows(row)
}

func scanUserRows(row accountScanner) (*User, error) {
	var u User
	var lastLogin sql.NullInt64
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.LockedUntil, &u.FailedAttempts, &lastLogin, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}
	if lastLogin.Valid {
		u.LastLoginAt = &lastLogin.Int64
	}
	return &u, nil
}

func scanAuditRows(row accountScanner) (AuditEntry, error) {
	var e AuditEntry
	var targetType, targetID, detail, sourceIP sql.NullString
	if err := row.Scan(&e.ID, &e.TS, &e.Operator, &e.Action, &targetType, &targetID, &e.Result, &detail, &sourceIP); err != nil {
		return AuditEntry{}, err
	}
	e.TargetType = targetType.String
	e.TargetID = targetID.String
	e.Detail = detail.String
	e.SourceIP = sourceIP.String
	return e, nil
}

func marshalNullable(v map[string]any) (sql.NullString, error) {
	if v == nil {
		return sql.NullString{}, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: string(b), Valid: true}, nil
}

func nullableString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func nullableInt(v *int64) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *v, Valid: true}
}

func stringPtrFromNull(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	return &v.String
}

func stringPtr(s string) *string { return &s }

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
