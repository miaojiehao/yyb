package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUnauthorizedProtectedRoutes(t *testing.T) {
	_, handler, _ := newTestApp(t)

	home := httptest.NewRecorder()
	handler.ServeHTTP(home, httptest.NewRequest(http.MethodGet, "/", nil))
	if home.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200 (login page must be public, body=%s)", home.Code, home.Body.String())
	}

	for _, path := range []string{"/accounts", "/accounts/avatar", "/docs", "/openapi.json", "/audit/logs", "/auth/me"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s unauthenticated status = %d, want 401 (body=%s)", path, w.Code, w.Body.String())
		}
	}
}

func TestLoginFailureAndMe(t *testing.T) {
	_, handler, _ := newTestApp(t)

	wrong := httptest.NewRecorder()
	body := bytes.NewReader([]byte(`{"username":"admin","password":"wrong-pass"}`))
	req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(wrong, req)
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want 401", wrong.Code)
	}

	missing := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(missing, req)
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing fields status = %d, want 400", missing.Code)
	}

	me := httptest.NewRecorder()
	handler.ServeHTTP(me, authedRequest(http.MethodGet, "/auth/me", nil, loginCookie(t, handler, "admin", testAdminPassword)))
	if me.Code != http.StatusOK {
		t.Fatalf("GET /auth/me status = %d", me.Code)
	}
	if !strings.Contains(me.Body.String(), `"role":"admin"`) {
		t.Fatalf("GET /auth/me body = %s", me.Body.String())
	}
}

func TestLoginLockout(t *testing.T) {
	_, handler, _ := newTestApp(t)
	var last *httptest.ResponseRecorder
	for i := 0; i < 6; i++ {
		last = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader([]byte(`{"username":"admin","password":"bad"}`)))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(last, req)
	}
	if last.Code != 423 {
		t.Fatalf("locked status = %d, want 423 (body=%s)", last.Code, last.Body.String())
	}
}

func TestRoleMatrix(t *testing.T) {
	_, handler, adminCookie := newTestApp(t)

	createUser(t, handler, adminCookie, "viewer1", "viewer-pass", "viewer")
	createUser(t, handler, adminCookie, "op1", "op-pass", "operator")
	viewerCookie := loginCookie(t, handler, "viewer1", "viewer-pass")
	opCookie := loginCookie(t, handler, "op1", "op-pass")

	// viewer: read allowed
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, authedRequest(http.MethodGet, "/accounts", nil, viewerCookie))
	if w.Code != http.StatusOK {
		t.Fatalf("viewer GET /accounts status = %d, want 200", w.Code)
	}

	// viewer: change denied
	for _, p := range []string{"/accounts/refresh", "/wxapp/getCode", "/auth/users"} {
		w = httptest.NewRecorder()
		req := authedRequest(http.MethodPost, p, bytes.NewReader([]byte(`{"ref":"x","app_id":"y"}`)), viewerCookie)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("viewer POST %s status = %d, want 403 (body=%s)", p, w.Code, w.Body.String())
		}
	}

	// operator: user management denied
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, authedRequest(http.MethodGet, "/auth/users", nil, opCookie))
	if w.Code != http.StatusForbidden {
		t.Fatalf("operator GET /auth/users status = %d, want 403", w.Code)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, authedRequest(http.MethodGet, "/audit/logs", nil, opCookie))
	if w.Code != http.StatusForbidden {
		t.Fatalf("operator GET /audit/logs status = %d, want 403", w.Code)
	}

	// operator: account list allowed
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, authedRequest(http.MethodGet, "/accounts", nil, opCookie))
	if w.Code != http.StatusOK {
		t.Fatalf("operator GET /accounts status = %d, want 200", w.Code)
	}
}

func TestAccountIPWhitelist(t *testing.T) {
	app, handler, cookie := newTestApp(t)
	seedAccount(t, app, "openid-ip")
	setAccountConfig(t, app, cookie, "openid-ip", "", "1.2.3.4")

	// blocked source
	w := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/accounts/refresh", bytes.NewReader([]byte(`{"ref":"openid-ip"}`)), cookie)
	req.RemoteAddr = "9.9.9.9:1234"
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "source ip not allowed") {
		t.Fatalf("blocked source status = %d body=%s", w.Code, w.Body.String())
	}

	// allowed source must not be blocked by account whitelist
	w = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/accounts/refresh", bytes.NewReader([]byte(`{"ref":"openid-ip"}`)), cookie)
	req.RemoteAddr = "1.2.3.4:5678"
	handler.ServeHTTP(w, req)
	if w.Code == http.StatusForbidden {
		t.Fatalf("allowed source unexpectedly forbidden: %s", w.Body.String())
	}
}

func TestAccountConfigEndpoint(t *testing.T) {
	app, handler, cookie := newTestApp(t)
	seedAccount(t, app, "openid-cfg")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, authedRequest(http.MethodGet, "/accounts/openid-cfg/config", nil, cookie))
	if w.Code != http.StatusOK {
		t.Fatalf("GET config status = %d", w.Code)
	}
	var cfg map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &cfg)
	data := cfg["data"].(map[string]any)
	if data["bound_proxy"] != "" || data["allowed_source_ips"] != "" {
		t.Fatalf("default config = %#v", data)
	}

	// invalid proxy
	w = httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/accounts/openid-cfg/config", bytes.NewReader([]byte(`{"bound_proxy":"ftp://x:1"}`)), cookie)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid proxy status = %d, want 400", w.Code)
	}

	// valid update
	w = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/accounts/openid-cfg/config", bytes.NewReader([]byte(`{"bound_proxy":"socks5://1.2.3.4:1080","allowed_source_ips":"10.0.0.0/8, 8.8.8.8"}`)), cookie)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("valid update status = %d body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, authedRequest(http.MethodGet, "/accounts/openid-cfg/config", nil, cookie))
	_ = json.Unmarshal(w.Body.Bytes(), &cfg)
	data = cfg["data"].(map[string]any)
	if data["bound_proxy"] != "socks5://1.2.3.4:1080" {
		t.Fatalf("bound_proxy after update = %v", data["bound_proxy"])
	}
}

func TestAuditLogsEndpoint(t *testing.T) {
	_, handler, cookie := newTestApp(t)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, authedRequest(http.MethodGet, "/audit/logs", nil, cookie))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /audit/logs status = %d", w.Code)
	}
	var env struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode audit logs: %v", err)
	}
	if len(env.Data) == 0 {
		t.Fatalf("audit logs should contain login_success record")
	}
	found := false
	for _, e := range env.Data {
		if e["action"] == "login_success" && e["operator"] == "admin" {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit logs missing login_success for admin: %#v", env.Data)
	}
}

func createUser(t *testing.T, handler http.Handler, cookie *http.Cookie, username, password, role string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password, "role": role})
	w := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/auth/users", bytes.NewReader(body), cookie)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create user %s status = %d body=%s", username, w.Code, w.Body.String())
	}
}

func seedAccount(t *testing.T, app *App, openid string) map[string]any {
	t.Helper()
	status := "alive"
	acc, err := app.db.UpsertAccount(context.Background(), openid, "login-buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}
	return map[string]any{"id": acc.ID, "openid": acc.OpenID}
}

func setAccountConfig(t *testing.T, app *App, cookie *http.Cookie, ref, proxy, ips string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"bound_proxy": proxy, "allowed_source_ips": ips})
	w := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/accounts/"+ref+"/config", bytes.NewReader(payload), cookie)
	req.Header.Set("Content-Type", "application/json")
	handler := app.Handler()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("set config for %s status = %d body=%s", ref, w.Code, w.Body.String())
	}
}
