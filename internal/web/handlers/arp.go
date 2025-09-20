package handlers

import (
	"encoding/json"
	"net/http"

	"router-os/internal/web/templates"
)

// ARPHandler ARP表处理器
type ARPHandler struct {
	renderer *templates.Renderer
	router   *RouterInstance
}

// NewARPHandler 创建ARP表处理器
func NewARPHandler(renderer *templates.Renderer, router *RouterInstance) *ARPHandler {
	return &ARPHandler{
		renderer: renderer,
		router:   router,
	}
}

// ShowARP 显示ARP表页面
func (h *ARPHandler) ShowARP(w http.ResponseWriter, r *http.Request) {
	data := templates.TemplateData{
		Title: "ARP表",
	}

	if err := h.renderer.Render(w, "arp", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// HandleARPList 处理ARP表列表API
func (h *ARPHandler) HandleARPList(w http.ResponseWriter, r *http.Request) {
	entries := h.router.ARPTable.GetAllEntries()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

// HandleARPClear 处理清空ARP表API
func (h *ARPHandler) HandleARPClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.router.ARPTable.FlushTable()
	w.WriteHeader(http.StatusOK)
}
