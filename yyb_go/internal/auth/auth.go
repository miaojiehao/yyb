package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"

	SessionCookie = "yyb_session"

	MaxLoginAttempts = 5
	LockDuration     = 30 * time.Minute
)

type Session struct {
	ID        string
	UserID    int64
	Username  string
	Role      string
	SourceIP  string
	ExpiresAt time.Time
}

func (s *Session) Expired(now time.Time) bool {
	return now.After(s.ExpiresAt)
}

type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	ttl      time.Duration
}

func NewManager(ttl time.Duration) *Manager {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &Manager{
		sessions: make(map[string]*Session),
		ttl:      ttl,
	}
}

func newSessionID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func hashID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func (m *Manager) Create(userID int64, username, role, sourceIP string) (string, error) {
	id, err := newSessionID()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.sessions[hashID(id)] = &Session{
		ID:        id,
		UserID:    userID,
		Username:  username,
		Role:      role,
		SourceIP:  sourceIP,
		ExpiresAt: time.Now().Add(m.ttl),
	}
	m.mu.Unlock()
	return id, nil
}

func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hashID(id)]
	if !ok {
		return nil, false
	}
	now := time.Now()
	if s.Expired(now) {
		delete(m.sessions, hashID(id))
		return nil, false
	}
	return s, true
}

func (m *Manager) Renew(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := hashID(id)
	s, ok := m.sessions[key]
	if !ok || s.Expired(time.Now()) {
		delete(m.sessions, key)
		return false
	}
	s.ExpiresAt = time.Now().Add(m.ttl)
	return true
}

func (m *Manager) Delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, hashID(id))
}

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func VerifyPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

type ctxKey int

const currentUserKey ctxKey = 0

func WithCurrentUser(c *gin.Context, s *Session) {
	c.Set("auth.session", s)
}

func CurrentUser(c *gin.Context) (*Session, bool) {
	v, ok := c.Get("auth.session")
	if !ok {
		return nil, false
	}
	s, ok := v.(*Session)
	return s, ok
}

func CurrentUserFrom(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(currentUserKey).(*Session)
	return s, ok
}

func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, currentUserKey, s)
}

func IsPublicPath(path string) bool {
	switch path {
	case "/", "/health", "/auth/login", "/auth/logout", "/scan", "/favicon.ico", "/qr":
		return true
	}
	return strings.HasPrefix(path, "/qr/") || strings.HasPrefix(path, "/static/")
}

func AuthMiddleware(m *Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		if IsPublicPath(c.Request.URL.Path) {
			c.Next()
			return
		}
		token, err := c.Cookie(SessionCookie)
		if err != nil || token == "" {
			abortJSON(c, 401, "unauthorized")
			return
		}
		s, ok := m.Get(token)
		if !ok {
			abortJSON(c, 401, "unauthorized")
			return
		}
		m.Renew(token)
		WithCurrentUser(c, s)
		c.Request = c.Request.WithContext(WithSession(c.Request.Context(), s))
		c.Next()
	}
}

func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(c *gin.Context) {
		s, ok := CurrentUser(c)
		if !ok {
			abortJSON(c, 401, "unauthorized")
			return
		}
		if !allowed[s.Role] {
			abortJSON(c, 403, "forbidden")
			return
		}
		c.Next()
	}
}

func abortJSON(c *gin.Context, status int, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"code": status, "msg": msg, "data": nil})
}
