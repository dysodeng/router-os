package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"router-os/internal/module/routing"
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

	// 统计不同类型的路由数量
	stats := map[string]int{
		"total":     0,
		"static":    0,
		"dynamic":   0,
		"connected": 0,
		"default":   0,
	}

	// 转换路由数据格式以匹配前端期望
	var routeData []map[string]interface{}
	for _, route := range routes {
		// 计算路由状态
		status := "活跃"
		if route.TTL > 0 {
			elapsed := time.Since(route.Age)
			if elapsed > route.TTL {
				status = "过期"
			} else {
				remaining := route.TTL - elapsed
				if remaining < time.Minute*5 {
					status = "即将过期"
				}
			}
		}

		// 格式化时间显示
		ageStr := route.Age.In(time.Local).Format("2006-01-02 15:04:05 CST")
		ttlStr := "永久"
		if route.TTL > 0 {
			ttlStr = route.TTL.String()
		}

		// 格式化源地址显示
		srcStr := ""
		if route.Src != nil {
			srcStr = route.Src.String()
		}

		// 处理网关字段
		var gatewayStr string
		if route.Gateway != nil {
			gatewayStr = route.Gateway.String()
		} else {
			gatewayStr = "N/A"
		}

		routeItem := map[string]interface{}{
			"destination": route.Destination.String(),
			"gateway":     gatewayStr,
			"iface":       route.Interface,
			"metric":      route.Metric,
			"proto":       route.Proto,
			"scope":       route.Scope,
			"src":         srcStr,
			"flags":       route.Flags,
			"type":        route.Type.String(),
			"age":         ageStr,
			"ttl":         ttlStr,
			"status":      status,
		}
		routeData = append(routeData, routeItem)

		// 统计路由类型
		stats["total"]++
		switch route.Type {
		case routing.RouteTypeStatic:
			stats["static"]++
		case routing.RouteTypeDynamic:
			stats["dynamic"]++
		case routing.RouteTypeConnected:
			stats["connected"]++
		case routing.RouteTypeDefault:
			stats["default"]++
		}
	}

	response := map[string]interface{}{
		"routes": routeData,
		"stats":  stats,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
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
		Interface   string `json:"iface"`
		Metric      int    `json:"metric"`
		Proto       string `json:"proto"`
		Scope       string `json:"scope"`
		Src         string `json:"src"`
		Flags       string `json:"flags"`
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

	// 解析源地址（可选）
	var src net.IP
	if routeReq.Src != "" {
		src = net.ParseIP(routeReq.Src)
		if src == nil {
			http.Error(w, "Invalid source IP", http.StatusBadRequest)
			return
		}
	}

	// 创建路由
	route := routing.Route{
		Destination: destNet,
		Gateway:     gateway,
		Interface:   routeReq.Interface,
		Metric:      routeReq.Metric,
		Proto:       routeReq.Proto,
		Scope:       routeReq.Scope,
		Src:         src,
		Flags:       routeReq.Flags,
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
