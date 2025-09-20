package handlers

import (
	"encoding/json"
	"net"
	"net/http"

	"router-os/internal/routing"
	"router-os/internal/web/templates"
)

// RoutesHandler 路由表处理器
type RoutesHandler struct {
	renderer *templates.Renderer
	router   *RouterInstance
}

// NewRoutesHandler 创建路由表处理器
func NewRoutesHandler(renderer *templates.Renderer, router *RouterInstance) *RoutesHandler {
	return &RoutesHandler{
		renderer: renderer,
		router:   router,
	}
}

// ShowRoutes 显示路由表页面
func (h *RoutesHandler) ShowRoutes(w http.ResponseWriter, r *http.Request) {
	data := templates.TemplateData{
		Title: "路由表",
	}

	if err := h.renderer.Render(w, "routes", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// HandleRoutesList 处理路由列表API
func (h *RoutesHandler) HandleRoutesList(w http.ResponseWriter, r *http.Request) {
	routes := h.router.RoutingTable.GetAllRoutes()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(routes)
}

// HandleRouteAdd 处理添加路由API
func (h *RoutesHandler) HandleRouteAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var routeReq struct {
		Destination string `json:"destination"`
		Gateway     string `json:"gateway"`
		Interface   string `json:"interface"`
		Metric      int    `json:"metric"`
	}

	if err := json.NewDecoder(r.Body).Decode(&routeReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 解析目标网络
	_, destNet, err := net.ParseCIDR(routeReq.Destination)
	if err != nil {
		http.Error(w, "Invalid destination network", http.StatusBadRequest)
		return
	}

	// 解析网关
	gateway := net.ParseIP(routeReq.Gateway)
	if gateway == nil {
		http.Error(w, "Invalid gateway IP", http.StatusBadRequest)
		return
	}

	// 创建路由
	route := routing.Route{
		Destination: destNet,
		Gateway:     gateway,
		Interface:   routeReq.Interface,
		Metric:      routeReq.Metric,
		Type:        routing.RouteTypeStatic,
	}

	if err := h.router.RoutingTable.AddRoute(route); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HandleRouteDelete 处理删除路由API
func (h *RoutesHandler) HandleRouteDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var deleteReq struct {
		Destination string `json:"destination"`
	}

	if err := json.NewDecoder(r.Body).Decode(&deleteReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 解析目标网络
	_, destNet, err := net.ParseCIDR(deleteReq.Destination)
	if err != nil {
		http.Error(w, "Invalid destination network", http.StatusBadRequest)
		return
	}

	if err := h.router.RoutingTable.RemoveRoute(destNet, nil, ""); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
