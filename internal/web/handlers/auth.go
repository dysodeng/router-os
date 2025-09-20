package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"router-os/internal/web/middleware"
	"router-os/internal/web/templates"
)

// AuthHandler 认证处理器
type AuthHandler struct {
	authMiddleware *middleware.AuthMiddleware
	renderer       *templates.Renderer
}

// NewAuthHandler 创建认证处理器
func NewAuthHandler(authMiddleware *middleware.AuthMiddleware, renderer *templates.Renderer) *AuthHandler {
	return &AuthHandler{
		authMiddleware: authMiddleware,
		renderer:       renderer,
	}
}

// ShowLogin 显示登录页面
func (h *AuthHandler) ShowLogin(w http.ResponseWriter, r *http.Request) {
	data := templates.TemplateData{
		Title: "登录",
	}

	if err := h.renderer.Render(w, "login", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// HandleLogin 处理登录请求
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if h.authMiddleware.ValidateCredentials(loginReq.Username, loginReq.Password) {
		token := fmt.Sprintf("token_%d", time.Now().Unix())

		response := map[string]string{
			"token": token,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}

// HandleLogout 处理退出登录
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
