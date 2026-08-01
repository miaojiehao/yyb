package auth

import (
	"testing"
	"time"
)

func TestPasswordHashAndVerify(t *testing.T) {
	hash, err := HashPassword("s3cret-pass")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if hash == "s3cret-pass" {
		t.Fatalf("hash must not equal plaintext")
	}
	if !VerifyPassword(hash, "s3cret-pass") {
		t.Fatalf("VerifyPassword() should pass for correct password")
	}
	if VerifyPassword(hash, "wrong") {
		t.Fatalf("VerifyPassword() should fail for wrong password")
	}
}

func TestSessionCreateGetDeleteRenew(t *testing.T) {
	m := NewManager(time.Second)

	id, err := m.Create(1, "alice", RoleAdmin, "1.2.3.4")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if id == "" {
		t.Fatalf("session id is empty")
	}

	s, ok := m.Get(id)
	if !ok {
		t.Fatalf("Get() should find fresh session")
	}
	if s.Username != "alice" || s.Role != RoleAdmin || s.UserID != 1 {
		t.Fatalf("session = %#v", s)
	}

	m.Delete(id)
	if _, ok := m.Get(id); ok {
		t.Fatalf("Get() should miss after Delete")
	}

	id2, _ := m.Create(2, "bob", RoleViewer, "5.6.7.8")
	m.Renew(id2)
	if _, ok := m.Get(id2); !ok {
		t.Fatalf("session should survive Renew")
	}
}

func TestSessionExpiry(t *testing.T) {
	m := NewManager(50 * time.Millisecond)
	id, err := m.Create(1, "alice", RoleAdmin, "1.2.3.4")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	time.Sleep(80 * time.Millisecond)
	if _, ok := m.Get(id); ok {
		t.Fatalf("Get() should miss after expiry")
	}
}

func TestSessionIDsAreRandom(t *testing.T) {
	m := NewManager(time.Minute)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := m.Create(int64(i), "u", RoleViewer, "1.1.1.1")
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate session id %q", id)
		}
		seen[id] = true
	}
}

func TestIsPublicPath(t *testing.T) {
	public := []string{"/", "/health", "/auth/login", "/auth/logout", "/scan", "/favicon.ico", "/qr", "/qr/abc/image", "/static/app.js"}
	for _, p := range public {
		if !IsPublicPath(p) {
			t.Fatalf("path %q should be public", p)
		}
	}
	protected := []string{"/accounts", "/accounts/1/config", "/wxapp/getCode", "/docs", "/docs/index.html", "/openapi.json", "/audit/logs"}
	for _, p := range protected {
		if IsPublicPath(p) {
			t.Fatalf("path %q should be protected", p)
		}
	}
}
