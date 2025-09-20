package handlers

import (
	"encoding/json"
	"net/http"

	"router-os/internal/web/templates"
)

// VPNHandler VPN处理器
type VPNHandler struct {
	renderer *templates.Renderer
	router   *RouterInstance
}

// NewVPNHandler 创建VPN处理器
func NewVPNHandler(renderer *templates.Renderer, router *RouterInstance) *VPNHandler {
	return &VPNHandler{
		renderer: renderer,
		router:   router,
	}
}

// ShowVPN 显示VPN页面
func (h *VPNHandler) ShowVPN(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "VPN管理",
	}

	if err := h.renderer.Render(w, "vpn", data); err != nil {
		http.Error(w, "渲染模板失败", http.StatusInternalServerError)
		return
	}
}

// HandleVPNConfig 处理VPN配置
func (h *VPNHandler) HandleVPNConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 这里应该从VPN服务器获取配置
	config := map[string]interface{}{
		"enabled":  false,
		"port":     1194,
		"protocol": "udp",
	}

	json.NewEncoder(w).Encode(config)
}

// HandleVPNClients 处理VPN客户端
func (h *VPNHandler) HandleVPNClients(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// 获取VPN客户端列表
		clients := []interface{}{}
		json.NewEncoder(w).Encode(clients)
	case "POST":
		// 添加VPN客户端
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	case "DELETE":
		// 删除VPN客户端
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	default:
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
	}
}
