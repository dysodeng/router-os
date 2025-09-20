package handlers

import (
	"encoding/json"
	"net/http"

	"router-os/internal/web/templates"
)

// FirewallHandler 防火墙处理器
type FirewallHandler struct {
	renderer *templates.Renderer
	router   *RouterInstance
}

// NewFirewallHandler 创建防火墙处理器
func NewFirewallHandler(renderer *templates.Renderer, router *RouterInstance) *FirewallHandler {
	return &FirewallHandler{
		renderer: renderer,
		router:   router,
	}
}

// ShowFirewall 显示防火墙页面
func (h *FirewallHandler) ShowFirewall(w http.ResponseWriter, r *http.Request) {
	data := templates.TemplateData{
		Title: "防火墙",
	}

	if err := h.renderer.Render(w, "firewall", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// HandleRulesList 处理防火墙规则列表API
func (h *FirewallHandler) HandleRulesList(w http.ResponseWriter, r *http.Request) {
	chain := r.URL.Query().Get("chain")
	if chain == "" {
		chain = "input" // 默认获取input链
	}

	rules, err := h.router.Firewall.GetRules(chain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rules)
}

// HandleRuleAdd 处理添加防火墙规则API
func (h *FirewallHandler) HandleRuleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var ruleReq struct {
		Action     string `json:"action"`
		Protocol   string `json:"protocol"`
		SourceIP   string `json:"source_ip"`
		DestIP     string `json:"dest_ip"`
		SourcePort int    `json:"source_port"`
		DestPort   int    `json:"dest_port"`
	}

	if err := json.NewDecoder(r.Body).Decode(&ruleReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 这里应该调用防火墙的添加规则方法
	// 由于防火墙模块的具体实现可能不同，这里只是示例
	w.WriteHeader(http.StatusOK)
}

// HandleRuleDelete 处理删除防火墙规则API
func (h *FirewallHandler) HandleRuleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var deleteReq struct {
		RuleID int `json:"rule_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&deleteReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 这里应该调用防火墙的删除规则方法
	w.WriteHeader(http.StatusOK)
}
