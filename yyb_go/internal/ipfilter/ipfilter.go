package ipfilter

import (
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type Matcher struct {
	nets []*net.IPNet
	ips  []net.IP
}

func Compile(list string) (*Matcher, error) {
	m := &Matcher{}
	for _, part := range splitList(list) {
		if strings.Contains(part, "/") {
			_, ipnet, err := net.ParseCIDR(part)
			if err != nil {
				return nil, err
			}
			m.nets = append(m.nets, ipnet)
			continue
		}
		ip := net.ParseIP(part)
		if ip == nil {
			return nil, &net.ParseError{Type: "IP address", Text: part}
		}
		m.ips = append(m.ips, ip)
	}
	return m, nil
}

func (m *Matcher) Allow(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if m == nil {
		return true
	}
	for _, allowed := range m.ips {
		if allowed.Equal(ip) {
			return true
		}
	}
	for _, ipnet := range m.nets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func splitList(list string) []string {
	if list == "" {
		return nil
	}
	parts := strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func ClientIP(r *http.Request) net.IP {
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP"} {
		v := r.Header.Get(h)
		if v == "" {
			continue
		}
		first := strings.TrimSpace(strings.Split(v, ",")[0])
		if ip := net.ParseIP(first); ip != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

func GlobalMiddleware(matcher *Matcher) gin.HandlerFunc {
	return func(c *gin.Context) {
		if matcher == nil {
			c.Next()
			return
		}
		if c.Request.URL.Path == "/health" {
			c.Next()
			return
		}
		ip := ClientIP(c.Request)
		if !matcher.Allow(ip) {
			c.AbortWithStatusJSON(403, gin.H{"code": 403, "msg": "ip not allowed", "data": nil})
			return
		}
		c.Next()
	}
}
