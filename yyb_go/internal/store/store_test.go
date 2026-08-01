package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenMigratesWMPFSessionsTableToSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yyb.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	ctx := context.Background()
	if _, err = raw.ExecContext(ctx, `
CREATE TABLE wechat_accounts (
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
CREATE TABLE wmpf_sessions (
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
CREATE INDEX idx_sess_expires ON wmpf_sessions(expires_at);
INSERT INTO wechat_accounts(id, openid, login_buffer, created_at, updated_at)
VALUES(1, 'openid-1', 'login-buffer', 10, 10);
INSERT INTO wmpf_sessions(id, wechat_account_id, uin, tcp_proxy, session_blob, expires_at, created_at, updated_at)
VALUES(7, 1, 12345, '', '{"ready":true}', ?, 20, 20);
`, time.Now().Add(time.Hour).Unix()); err != nil {
		_ = raw.Close()
		t.Fatalf("seed old schema: %v", err)
	}
	if err = raw.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	oldExists, err := sqliteTableExists(ctx, db.sql, "wmpf_sessions")
	if err != nil {
		t.Fatalf("check old table: %v", err)
	}
	if oldExists {
		t.Fatalf("old wmpf_sessions table still exists")
	}
	newExists, err := sqliteTableExists(ctx, db.sql, "sessions")
	if err != nil {
		t.Fatalf("check new table: %v", err)
	}
	if !newExists {
		t.Fatalf("new sessions table does not exist")
	}

	session, err := db.GetSession(ctx, 1, "")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if session.ID != 7 {
		t.Fatalf("session id = %d, want 7", session.ID)
	}
	if ready, ok := session.SessionBlob["ready"].(bool); !ok || !ready {
		t.Fatalf("session blob = %#v", session.SessionBlob)
	}
}

func TestOpenMigratesAccountSecurityColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yyb.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	ctx := context.Background()
	if _, err = raw.ExecContext(ctx, `
CREATE TABLE wechat_accounts (
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
INSERT INTO wechat_accounts(id, openid, login_buffer, created_at, updated_at)
VALUES(1, 'openid-1', 'login-buffer', 10, 10);`); err != nil {
		_ = raw.Close()
		t.Fatalf("seed old schema: %v", err)
	}
	if err = raw.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	for _, col := range []string{"bound_proxy", "allowed_source_ips"} {
		ok, err := sqliteColumnExists(ctx, db.sql, "wechat_accounts", col)
		if err != nil {
			t.Fatalf("check column %s: %v", col, err)
		}
		if !ok {
			t.Fatalf("column %s not added by migration", col)
		}
	}

	acc, err := db.GetAccount(ctx, 1)
	if err != nil {
		t.Fatalf("GetAccount() error = %v", err)
	}
	if acc.BoundProxy != "" || acc.AllowedSourceIPs != "" {
		t.Fatalf("new columns should default empty, got %q / %q", acc.BoundProxy, acc.AllowedSourceIPs)
	}
}

func TestAccountConfigReadWrite(t *testing.T) {
	db := mustOpenDB(t)
	defer db.Close()
	ctx := context.Background()

	acc, err := db.UpsertAccount(ctx, "openid-cfg", "buf", nil, stringPtr("nick"), nil, nil, nil, stringPtr("alive"))
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}
	if err := db.SetAccountConfig(ctx, acc.ID, "socks5://1.2.3.4:1080", "10.0.0.0/8, 8.8.8.8"); err != nil {
		t.Fatalf("SetAccountConfig() error = %v", err)
	}
	got, err := db.GetAccountConfig(ctx, acc.ID)
	if err != nil {
		t.Fatalf("GetAccountConfig() error = %v", err)
	}
	if got.BoundProxy != "socks5://1.2.3.4:1080" {
		t.Fatalf("bound_proxy = %q", got.BoundProxy)
	}
	if got.AllowedSourceIPs != "10.0.0.0/8, 8.8.8.8" {
		t.Fatalf("allowed_source_ips = %q", got.AllowedSourceIPs)
	}
	if err := db.SetAccountProxy(ctx, acc.ID, "http-connect://5.6.7.8:3128"); err != nil {
		t.Fatalf("SetAccountProxy() error = %v", err)
	}
	got, _ = db.GetAccountConfig(ctx, acc.ID)
	if got.BoundProxy != "http-connect://5.6.7.8:3128" {
		t.Fatalf("bound_proxy after SetAccountProxy = %q", got.BoundProxy)
	}
	if got.AllowedSourceIPs != "10.0.0.0/8, 8.8.8.8" {
		t.Fatalf("allowed_source_ips should be preserved, got %q", got.AllowedSourceIPs)
	}
}

func TestAuditAppendAndQuery(t *testing.T) {
	db := mustOpenDB(t)
	defer db.Close()
	ctx := context.Background()

	now := time.Now().Unix()
	for i, op := range []AuditEntry{
		{TS: now - 20, Operator: "alice", Action: "login_success", Result: "success", SourceIP: "1.1.1.1"},
		{TS: now - 10, Operator: "bob", Action: "account_delete", TargetType: "account", TargetID: "5", Result: "success", SourceIP: "2.2.2.2"},
		{TS: now, Operator: "alice", Action: "wxapp_call", TargetType: "account", TargetID: "7", Result: "fail", Detail: "bad gateway", SourceIP: "1.1.1.1"},
	} {
		if err := db.AppendAudit(ctx, op); err != nil {
			t.Fatalf("AppendAudit #%d error = %v", i, err)
		}
	}

	all, err := db.QueryAudit(ctx, "", "", 0, 0, 10, 0)
	if err != nil {
		t.Fatalf("QueryAudit() error = %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("query all len = %d, want 3", len(all))
	}
	if all[0].TS != now {
		t.Fatalf("query should be ts DESC, first ts = %d", all[0].TS)
	}

	alice, err := db.QueryAudit(ctx, "alice", "", 0, 0, 10, 0)
	if err != nil {
		t.Fatalf("QueryAudit(alice) error = %v", err)
	}
	if len(alice) != 2 {
		t.Fatalf("query alice len = %d, want 2", len(alice))
	}

	deletes, err := db.QueryAudit(ctx, "", "account_delete", 0, 0, 10, 0)
	if err != nil {
		t.Fatalf("QueryAudit(action) error = %v", err)
	}
	if len(deletes) != 1 || deletes[0].TargetID != "5" {
		t.Fatalf("query account_delete = %#v", deletes)
	}

	page, err := db.QueryAudit(ctx, "", "", 0, 0, 2, 1)
	if err != nil {
		t.Fatalf("QueryAudit(page) error = %v", err)
	}
	if len(page) != 2 {
		t.Fatalf("page len = %d, want 2", len(page))
	}
}

func TestUserCRUD(t *testing.T) {
	db := mustOpenDB(t)
	defer db.Close()
	ctx := context.Background()

	u, err := db.CreateUser(ctx, "admin", "hash1", "admin")
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if u.Role != "admin" || u.Username != "admin" {
		t.Fatalf("created user = %#v", u)
	}

	byName, err := db.GetUserByName(ctx, "ADMIN")
	if err != nil {
		t.Fatalf("GetUserByName() error = %v", err)
	}
	if byName.ID != u.ID {
		t.Fatalf("GetUserByName case-insensitive failed: %#v", byName)
	}

	if err := db.SetUserRole(ctx, u.ID, "viewer"); err != nil {
		t.Fatalf("SetUserRole() error = %v", err)
	}
	u, _ = db.GetUser(ctx, u.ID)
	if u.Role != "viewer" {
		t.Fatalf("role after update = %q", u.Role)
	}

	if err := db.SetUserPassword(ctx, u.ID, "hash2"); err != nil {
		t.Fatalf("SetUserPassword() error = %v", err)
	}
	u, _ = db.GetUser(ctx, u.ID)
	if u.PasswordHash != "hash2" {
		t.Fatalf("password hash = %q", u.PasswordHash)
	}

	now := time.Now().Unix()
	if err := db.UpdateUserLoginMeta(ctx, u.ID, now, 3, &now); err != nil {
		t.Fatalf("UpdateUserLoginMeta() error = %v", err)
	}
	u, _ = db.GetUser(ctx, u.ID)
	if u.LockedUntil != now || u.FailedAttempts != 3 || u.LastLoginAt == nil {
		t.Fatalf("login meta = %#v", u)
	}

	if err := db.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
	if _, err := db.GetUser(ctx, u.ID); err != sql.ErrNoRows {
		t.Fatalf("user should be deleted, err = %v", err)
	}
}

func mustOpenDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return db
}
