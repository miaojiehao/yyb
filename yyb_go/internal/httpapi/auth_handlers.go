package httpapi

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"yyb_go/internal/audit"
	"yyb_go/internal/auth"
	"yyb_go/internal/ipfilter"
)

func (a *App) ensureAdminUser() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := a.db.GetUserByName(ctx, "admin"); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	pw := a.cfg.AdminPassword
	if pw == "" {
		pw = randomPassword(16)
		log.Printf("generated initial admin password: %s", pw)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	_, err = a.db.CreateUser(ctx, "admin", hash, "admin")
	return err
}

func randomPassword(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	rb := make([]byte, n)
	if _, err := rand.Read(rb); err != nil {
		return strings.Repeat("x", n)
	}
	for i := range b {
		b[i] = letters[int(rb[i])%len(letters)]
	}
	return string(b)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *App) handleLogin(c *gin.Context) {
	if c.Request.Method != http.MethodPost {
		writeError(c.Writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body loginRequest
	if err := decodeOptionalJSON(c.Request, &body); err != nil {
		writeError(c.Writer, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	username := strings.TrimSpace(body.Username)
	if username == "" || body.Password == "" {
		writeError(c.Writer, http.StatusBadRequest, "username and password are required")
		return
	}
	ctx := c.Request.Context()
	ip := clientIPString(c.Request)
	user, err := a.db.GetUserByName(ctx, username)
	if errors.Is(err, sql.ErrNoRows) {
		a.auditAs(ip, username, audit.ActionLoginFail, "user", username, "fail", "user not found")
		writeError(c.Writer, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err != nil {
		writeError(c.Writer, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now().Unix()
	if user.LockedUntil > now {
		remaining := (user.LockedUntil - now) / 60
		a.auditAs(ip, username, audit.ActionLoginFail, "user", username, "fail", "locked")
		writeError(c.Writer, 423, fmt.Sprintf("account locked, retry in %d minutes", remaining))
		return
	}
	if !auth.VerifyPassword(user.PasswordHash, body.Password) {
		attempts := user.FailedAttempts + 1
		lockedUntil := int64(0)
		if attempts >= auth.MaxLoginAttempts {
			lockedUntil = now + int64(auth.LockDuration.Seconds())
			attempts = 0
		}
		_ = a.db.UpdateUserLoginMeta(ctx, user.ID, lockedUntil, attempts, nil)
		a.auditAs(ip, username, audit.ActionLoginFail, "user", username, "fail", "invalid credentials")
		writeError(c.Writer, http.StatusUnauthorized, "invalid credentials")
		return
	}
	_ = a.db.UpdateUserLoginMeta(ctx, user.ID, 0, 0, &now)
	token, err := a.sessions.Create(user.ID, user.Username, user.Role, ip)
	if err != nil {
		writeError(c.Writer, http.StatusInternalServerError, err.Error())
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     auth.SessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(a.cfg.SessionTTL.Seconds()),
		SameSite: http.SameSiteLaxMode,
	})
	a.auditAs(ip, username, audit.ActionLoginSuccess, "user", username, "success", ip)
	writeJSON(c.Writer, http.StatusOK, gin.H{"username": user.Username, "role": user.Role})
}

func (a *App) handleLogout(c *gin.Context) {
	if c.Request.Method != http.MethodPost {
		writeError(c.Writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if token, err := c.Cookie(auth.SessionCookie); err == nil {
		a.sessions.Delete(token)
	}
	if s, ok := auth.CurrentUser(c); ok {
		a.audit(c, audit.ActionLogout, "user", s.Username, "success", "")
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     auth.SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	writeJSON(c.Writer, http.StatusOK, gin.H{"logged_out": true})
}

func (a *App) handleMe(c *gin.Context) {
	if c.Request.Method != http.MethodGet {
		writeError(c.Writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s, ok := auth.CurrentUser(c)
	if !ok {
		writeError(c.Writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(c.Writer, http.StatusOK, gin.H{"username": s.Username, "role": s.Role})
}

func (a *App) handlePassword(c *gin.Context) {
	if c.Request.Method != http.MethodPost {
		writeError(c.Writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s, ok := auth.CurrentUser(c)
	if !ok {
		writeError(c.Writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeOptionalJSON(c.Request, &body); err != nil {
		writeError(c.Writer, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if len(body.NewPassword) < 6 {
		writeError(c.Writer, http.StatusBadRequest, "new password must be at least 6 characters")
		return
	}
	user, err := a.db.GetUser(c.Request.Context(), s.UserID)
	if err != nil {
		writeError(c.Writer, http.StatusInternalServerError, err.Error())
		return
	}
	if !auth.VerifyPassword(user.PasswordHash, body.OldPassword) {
		writeError(c.Writer, http.StatusBadRequest, "old password is incorrect")
		return
	}
	hash, err := auth.HashPassword(body.NewPassword)
	if err != nil {
		writeError(c.Writer, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.db.SetUserPassword(c.Request.Context(), s.UserID, hash); err != nil {
		writeError(c.Writer, http.StatusInternalServerError, err.Error())
		return
	}
	a.audit(c, audit.ActionPasswordChange, "user", s.Username, "success", "")
	writeJSON(c.Writer, http.StatusOK, gin.H{"changed": true})
}

func (a *App) handleUsersRoot(c *gin.Context) {
	if !a.requireRole(c, auth.RoleAdmin) {
		return
	}
	ctx := c.Request.Context()
	switch c.Request.Method {
	case http.MethodGet:
		users, err := a.db.ListUsers(ctx)
		if err != nil {
			writeError(c.Writer, http.StatusInternalServerError, err.Error())
			return
		}
		out := make([]gin.H, 0, len(users))
		for _, u := range users {
			out = append(out, gin.H{"id": u.ID, "username": u.Username, "role": u.Role, "locked_until": u.LockedUntil, "created_at": u.CreatedAt})
		}
		writeJSON(c.Writer, http.StatusOK, out)
	case http.MethodPost:
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := decodeOptionalJSON(c.Request, &body); err != nil {
			writeError(c.Writer, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		body.Username = strings.TrimSpace(body.Username)
		if body.Username == "" || body.Password == "" {
			writeError(c.Writer, http.StatusBadRequest, "username and password are required")
			return
		}
		if body.Role == "" {
			body.Role = auth.RoleViewer
		}
		if !validRole(body.Role) {
			writeError(c.Writer, http.StatusBadRequest, "invalid role")
			return
		}
		if len(body.Password) < 6 {
			writeError(c.Writer, http.StatusBadRequest, "password must be at least 6 characters")
			return
		}
		hash, err := auth.HashPassword(body.Password)
		if err != nil {
			writeError(c.Writer, http.StatusInternalServerError, err.Error())
			return
		}
		u, err := a.db.CreateUser(ctx, body.Username, hash, body.Role)
		if err != nil {
			writeError(c.Writer, http.StatusInternalServerError, err.Error())
			return
		}
		a.audit(c, audit.ActionUserCreate, "user", u.Username, "success", "role="+u.Role)
		writeJSON(c.Writer, http.StatusOK, gin.H{"id": u.ID, "username": u.Username, "role": u.Role})
	default:
		writeError(c.Writer, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleUserByID(c *gin.Context) {
	if c.Request.Method != http.MethodDelete {
		writeError(c.Writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !a.requireRole(c, auth.RoleAdmin) {
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(c.Writer, http.StatusBadRequest, "invalid user id")
		return
	}
	if s, ok := auth.CurrentUser(c); ok && s.UserID == id {
		writeError(c.Writer, http.StatusForbidden, "cannot delete yourself")
		return
	}
	ctx := c.Request.Context()
	user, err := a.db.GetUser(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(c.Writer, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeError(c.Writer, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.db.DeleteUser(ctx, id); err != nil {
		writeError(c.Writer, http.StatusInternalServerError, err.Error())
		return
	}
	a.audit(c, audit.ActionUserDelete, "user", user.Username, "success", "")
	writeJSON(c.Writer, http.StatusOK, gin.H{"deleted": user.Username})
}

func (a *App) handleUserRole(c *gin.Context) {
	if c.Request.Method != http.MethodPost && c.Request.Method != http.MethodPut {
		writeError(c.Writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !a.requireRole(c, auth.RoleAdmin) {
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(c.Writer, http.StatusBadRequest, "invalid user id")
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if err := decodeOptionalJSON(c.Request, &body); err != nil {
		writeError(c.Writer, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if !validRole(body.Role) {
		writeError(c.Writer, http.StatusBadRequest, "invalid role")
		return
	}
	ctx := c.Request.Context()
	user, err := a.db.GetUser(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(c.Writer, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeError(c.Writer, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.db.SetUserRole(ctx, id, body.Role); err != nil {
		writeError(c.Writer, http.StatusInternalServerError, err.Error())
		return
	}
	a.audit(c, audit.ActionUserRoleUpdate, "user", user.Username, "success", "role="+body.Role)
	writeJSON(c.Writer, http.StatusOK, gin.H{"updated": user.Username, "role": body.Role})
}

func (a *App) handleAuditLogs(c *gin.Context) {
	if c.Request.Method != http.MethodGet {
		writeError(c.Writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !a.requireRole(c, auth.RoleAdmin) {
		return
	}
	q := c.Request.URL.Query()
	limit := parseIntQuery(q.Get("limit"), 50)
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset := parseIntQuery(q.Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}
	var from, to int64
	if v := q.Get("from"); v != "" {
		from, _ = strconv.ParseInt(v, 10, 64)
	}
	if v := q.Get("to"); v != "" {
		to, _ = strconv.ParseInt(v, 10, 64)
	}
	entries, err := a.db.QueryAudit(c.Request.Context(), q.Get("operator"), q.Get("action"), from, to, limit, offset)
	if err != nil {
		writeError(c.Writer, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(c.Writer, http.StatusOK, entries)
}

func validRole(role string) bool {
	switch role {
	case auth.RoleAdmin, auth.RoleOperator, auth.RoleViewer:
		return true
	}
	return false
}

func (a *App) requireRole(c *gin.Context, roles ...string) bool {
	return a.requireRoleReq(c.Writer, c.Request, roles...)
}

func (a *App) requireRoleReq(w http.ResponseWriter, r *http.Request, roles ...string) bool {
	s, ok := auth.CurrentUserFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	for _, role := range roles {
		if s.Role == role {
			return true
		}
	}
	writeError(w, http.StatusForbidden, "forbidden")
	return false
}

func (a *App) audit(c *gin.Context, action, targetType, targetID, result, detail string) {
	a.auditReq(c.Writer, c.Request, action, targetType, targetID, result, detail)
}

func (a *App) auditReq(w http.ResponseWriter, r *http.Request, action, targetType, targetID, result, detail string) {
	operator := "anonymous"
	if s, ok := auth.CurrentUserFrom(r.Context()); ok {
		operator = s.Username
	}
	_ = a.db.AppendAudit(r.Context(), audit.Entry(operator, action, targetType, targetID, result, detail, clientIPString(r)))
}

func (a *App) auditAs(sourceIP, operator, action, targetType, targetID, result, detail string) {
	_ = a.db.AppendAudit(context.Background(), audit.Entry(operator, action, targetType, targetID, result, detail, sourceIP))
}

func clientIPString(r *http.Request) string {
	ip := ipfilter.ClientIP(r)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func parseIntQuery(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
