package handlers

import (
	"encoding/json"
	"net/http"

	"router-os/internal/web/templates"
)

// QoSHandler QoS处理器
type QoSHandler struct {
	renderer *templates.Renderer
	router   *RouterInstance
}

// NewQoSHandler 创建QoS处理器
func NewQoSHandler(renderer *templates.Renderer, router *RouterInstance) *QoSHandler {
	return &QoSHandler{
		renderer: renderer,
		router:   router,
	}
}

// ShowQoS 显示QoS页面
func (h *QoSHandler) ShowQoS(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "QoS管理",
	}

	if err := h.renderer.Render(w, "qos", data); err != nil {
		http.Error(w, "渲染模板失败", http.StatusInternalServerError)
		return
	}
}

// HandleQoSConfig 处理QoS配置
func (h *QoSHandler) HandleQoSConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 这里应该从QoS引擎获取配置
	config := map[string]interface{}{
		"enabled": true,
		"rules":   []interface{}{},
	}

	_ = json.NewEncoder(w).Encode(config)
}

// HandleQoSRules 处理QoS规则
func (h *QoSHandler) HandleQoSRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// 获取QoS规则列表
		var rules []interface{}
		_ = json.NewEncoder(w).Encode(rules)
	case "POST":
		// 添加QoS规则
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	case "DELETE":
		// 删除QoS规则
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	default:
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
	}
}
