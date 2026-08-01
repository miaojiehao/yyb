package httpapi

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"yyb_go/internal/audit"
	"yyb_go/internal/auth"
	"yyb_go/internal/ipfilter"
	"yyb_go/internal/protocol"
	"yyb_go/internal/store"
)

func (a *App) handleAccountConfig(c *gin.Context) {
	ref := c.Param("ref")
	acc, ok := a.resolveAccountRef(c.Writer, c.Request, ref)
	if !ok {
		return
	}
	switch c.Request.Method {
	case http.MethodGet:
		writeJSON(c.Writer, http.StatusOK, gin.H{
			"id":                 acc.ID,
			"openid":             acc.OpenID,
			"bound_proxy":        acc.BoundProxy,
			"allowed_source_ips": acc.AllowedSourceIPs,
		})
	case http.MethodPost:
		if !a.requireRole(c, auth.RoleAdmin, auth.RoleOperator) {
			return
		}
		var body struct {
			BoundProxy       string `json:"bound_proxy"`
			AllowedSourceIPs string `json:"allowed_source_ips"`
		}
		if err := decodeOptionalJSON(c.Request, &body); err != nil {
			writeError(c.Writer, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		body.BoundProxy = strings.TrimSpace(body.BoundProxy)
		body.AllowedSourceIPs = strings.TrimSpace(body.AllowedSourceIPs)
		if body.BoundProxy != "" {
			if _, err := protocol.ParseTCPProxy(body.BoundProxy); err != nil {
				writeError(c.Writer, http.StatusBadRequest, "invalid proxy: "+err.Error())
				return
			}
		}
		if body.AllowedSourceIPs != "" {
			if _, err := ipfilter.Compile(body.AllowedSourceIPs); err != nil {
				writeError(c.Writer, http.StatusBadRequest, "invalid ip list: "+err.Error())
				return
			}
		}
		if body.BoundProxy != acc.BoundProxy && acc.BoundProxy != "" {
			_ = a.db.InvalidateSession(c.Request.Context(), acc.ID, acc.BoundProxy)
		}
		if err := a.db.SetAccountConfig(c.Request.Context(), acc.ID, body.BoundProxy, body.AllowedSourceIPs); err != nil {
			writeError(c.Writer, http.StatusInternalServerError, err.Error())
			return
		}
		a.audit(c, audit.ActionAccountConfigUpdate, "account", ref, "success", "bound_proxy="+body.BoundProxy+"; allowed_source_ips="+body.AllowedSourceIPs)
		writeJSON(c.Writer, http.StatusOK, gin.H{"updated": acc.ID, "openid": acc.OpenID})
	default:
		writeError(c.Writer, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func effectiveAccountProxy(acc *store.WechatAccount, globalProxy string) string {
	if acc != nil && acc.BoundProxy != "" {
		return acc.BoundProxy
	}
	return globalProxy
}

func (a *App) checkAccountIP(c *gin.Context, acc *store.WechatAccount) bool {
	return a.checkAccountIPReq(c.Writer, c.Request, acc)
}

func (a *App) checkAccountIPReq(w http.ResponseWriter, r *http.Request, acc *store.WechatAccount) bool {
	if acc == nil || acc.AllowedSourceIPs == "" {
		return true
	}
	m, err := ipfilter.Compile(acc.AllowedSourceIPs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid allowed_source_ips config")
		return false
	}
	ip := ipfilter.ClientIP(r)
	if !m.Allow(ip) {
		writeError(w, http.StatusForbidden, "source ip not allowed for account")
		return false
	}
	return true
}
