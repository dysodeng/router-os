package middleware

import (
	"net/http"
	"strings"
)

// AuthConfig 认证配置
type AuthConfig struct {
	Username string
	Password string
}

// AuthMiddleware 认证中间件
type AuthMiddleware struct {
	config AuthConfig
}

// NewAuthMiddleware 创建认证中间件
func NewAuthMiddleware(config AuthConfig) *AuthMiddleware {
	return &AuthMiddleware{
		config: config,
	}
}

// RequireAuth 认证中间件
func (am *AuthMiddleware) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 简单的token验证
		token := strings.TrimPrefix(auth, "Bearer ")
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 这里可以添加更复杂的token验证逻辑
		// 目前只是简单检查token是否存在

		next(w, r)
	}
}

// ValidateCredentials 验证用户凭据
func (am *AuthMiddleware) ValidateCredentials(username, password string) bool {
	return username == am.config.Username && password == am.config.Password
}
