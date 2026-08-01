package ipfilter

import (
	"net"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCompileAndAllowSingleIP(t *testing.T) {
	m, err := Compile("8.8.8.8")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if !m.Allow(net.ParseIP("8.8.8.8")) {
		t.Fatalf("exact IP should be allowed")
	}
	if m.Allow(net.ParseIP("8.8.4.4")) {
		t.Fatalf("different IP should be denied")
	}
}

func TestCompileAndAllowCIDR(t *testing.T) {
	m, err := Compile("10.0.0.0/8")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if !m.Allow(net.ParseIP("10.1.2.3")) {
		t.Fatalf("IP inside CIDR should be allowed")
	}
	if m.Allow(net.ParseIP("11.0.0.1")) {
		t.Fatalf("IP outside CIDR should be denied")
	}
}

func TestCompileMixedList(t *testing.T) {
	m, err := Compile("1.1.1.1, 10.0.0.0/24, 2001:db8::/32")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	cases := []struct {
		ip    string
		allow bool
	}{
		{"1.1.1.1", true},
		{"10.0.0.42", true},
		{"10.0.1.1", false},
		{"2001:db8::1", true},
		{"2001:db9::1", false},
	}
	for _, c := range cases {
		if got := m.Allow(net.ParseIP(c.ip)); got != c.allow {
			t.Fatalf("Allow(%s) = %v, want %v", c.ip, got, c.allow)
		}
	}
}

func TestEmptyListAllowsNothingButNilMatcherAllowsAll(t *testing.T) {
	m, err := Compile("")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if m.Allow(net.ParseIP("1.2.3.4")) {
		t.Fatalf("empty matcher should deny everything")
	}
	if !(*Matcher)(nil).Allow(net.ParseIP("1.2.3.4")) {
		t.Fatalf("nil matcher should allow everything")
	}
}

func TestCompileInvalid(t *testing.T) {
	for _, bad := range []string{"999.1.1.1", "10.0.0.0/999", "not-an-ip", "1.2.3.4/33"} {
		if _, err := Compile(bad); err == nil {
			t.Fatalf("Compile(%q) should fail", bad)
		}
	}
}

func TestSplitList(t *testing.T) {
	if got := splitList(" 1.1.1.1, 2.2.2.2 ,10.0.0.0/8\t3.3.3.3\n"); len(got) != 4 {
		t.Fatalf("splitList len = %d, want 4: %#v", len(got), got)
	}
}

func TestClientIPFromHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "9.9.9.9:1234"
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
	if got := ClientIP(r).String(); got != "1.1.1.1" {
		t.Fatalf("XFF first entry = %s, want 1.1.1.1", got)
	}

	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "9.9.9.9:1234"
	r2.Header.Set("X-Real-IP", "5.5.5.5")
	if got := ClientIP(r2).String(); got != "5.5.5.5" {
		t.Fatalf("X-Real-IP = %s, want 5.5.5.5", got)
	}

	r3 := httptest.NewRequest("GET", "/", nil)
	r3.RemoteAddr = "9.9.9.9:1234"
	if got := ClientIP(r3).String(); got != "9.9.9.9" {
		t.Fatalf("RemoteAddr fallback = %s, want 9.9.9.9", got)
	}
}

func TestGlobalMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m, _ := Compile("1.1.1.1")

	router := gin.New()
	router.Use(GlobalMiddleware(m))
	router.GET("/ping", func(c *gin.Context) { c.Status(200) })
	router.GET("/health", func(c *gin.Context) { c.Status(200) })

	allowed := httptest.NewRequest("GET", "/ping", nil)
	allowed.RemoteAddr = "1.1.1.1:1000"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, allowed)
	if w.Code != 200 {
		t.Fatalf("allowed IP status = %d, want 200", w.Code)
	}

	blocked := httptest.NewRequest("GET", "/ping", nil)
	blocked.RemoteAddr = "2.2.2.2:1000"
	w = httptest.NewRecorder()
	router.ServeHTTP(w, blocked)
	if w.Code != 403 {
		t.Fatalf("blocked IP status = %d, want 403", w.Code)
	}

	health := httptest.NewRequest("GET", "/health", nil)
	health.RemoteAddr = "2.2.2.2:1000"
	w = httptest.NewRecorder()
	router.ServeHTTP(w, health)
	if w.Code != 200 {
		t.Fatalf("health should bypass whitelist, status = %d", w.Code)
	}
}
