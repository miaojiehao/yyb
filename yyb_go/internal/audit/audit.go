package audit

import (
	"time"

	"yyb_go/internal/store"
)

const (
	ActionLoginSuccess        = "login_success"
	ActionLoginFail           = "login_fail"
	ActionLogout              = "logout"
	ActionAccountCreate       = "account_create"
	ActionAccountDelete       = "account_delete"
	ActionAccountRefresh      = "account_refresh"
	ActionAccountResync       = "account_resync"
	ActionAccountConfigUpdate = "account_config_update"
	ActionWXAppCall           = "wxapp_call"
	ActionUserCreate          = "user_create"
	ActionUserDelete          = "user_delete"
	ActionUserRoleUpdate      = "user_role_update"
	ActionPasswordChange      = "password_change"
)

func Entry(operator, action, targetType, targetID, result, detail, sourceIP string) store.AuditEntry {
	return store.AuditEntry{
		TS:         time.Now().Unix(),
		Operator:   operator,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Result:     result,
		Detail:     detail,
		SourceIP:   sourceIP,
	}
}
