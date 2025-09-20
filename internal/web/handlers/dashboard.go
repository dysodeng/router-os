package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"router-os/internal/web/templates"
)

// DashboardHandler 仪表板处理器
type DashboardHandler struct {
	renderer *templates.Renderer
	router   *RouterInstance
}

// NewDashboardHandler 创建仪表板处理器
func NewDashboardHandler(renderer *templates.Renderer, router *RouterInstance) *DashboardHandler {
	return &DashboardHandler{
		renderer: renderer,
		router:   router,
	}
}

// ShowDashboard 显示仪表板页面
func (h *DashboardHandler) ShowDashboard(w http.ResponseWriter, r *http.Request) {
	data := templates.TemplateData{
		Title: "仪表板",
	}

	if err := h.renderer.Render(w, "dashboard", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// HandleStatus 处理状态查询API
func (h *DashboardHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	interfaces := h.router.InterfaceManager.GetAllInterfaces()
	routes := h.router.RoutingTable.GetAllRoutes()
	arpEntries := h.router.ARPTable.GetAllEntries()
	leases := h.router.DHCP.GetLeases()

	status := map[string]interface{}{
		"interfaces":  len(interfaces),
		"routes":      len(routes),
		"arp_entries": len(arpEntries),
		"dhcp_leases": len(leases),
		"uptime":      time.Since(time.Now()).Seconds(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
