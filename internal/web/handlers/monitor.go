package handlers

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"
)

// MonitorHandler 系统监控处理器
type MonitorHandler struct {
	router *RouterInstance
}

// NewMonitorHandler 创建系统监控处理器
func NewMonitorHandler(router *RouterInstance) *MonitorHandler {
	return &MonitorHandler{
		router: router,
	}
}

// ShowMonitor 显示系统监控页面
func (h *MonitorHandler) ShowMonitor(w http.ResponseWriter, r *http.Request) {
	// 这里应该使用模板渲染器，暂时返回简单响应
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<h1>系统监控</h1><p>监控页面正在开发中...</p>"))
}

// HandleSystemStats 处理系统统计信息API
func (h *MonitorHandler) HandleSystemStats(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	stats := map[string]interface{}{
		"memory": map[string]interface{}{
			"alloc":       m.Alloc,
			"total_alloc": m.TotalAlloc,
			"sys":         m.Sys,
			"num_gc":      m.NumGC,
		},
		"goroutines": runtime.NumGoroutine(),
		"timestamp":  time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// HandleNetworkStats 处理网络统计信息API
func (h *MonitorHandler) HandleNetworkStats(w http.ResponseWriter, r *http.Request) {
	// 获取网络接口统计信息
	interfaces := h.router.InterfaceManager.GetAllInterfaces()

	stats := make(map[string]interface{})
	for _, iface := range interfaces {
		stats[iface.Name] = map[string]interface{}{
			"rx_bytes":   iface.RxBytes,
			"tx_bytes":   iface.TxBytes,
			"rx_packets": iface.RxPackets,
			"tx_packets": iface.TxPackets,
			"status":     iface.Status,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// HandleFirewallStats 处理防火墙统计信息API
func (h *MonitorHandler) HandleFirewallStats(w http.ResponseWriter, r *http.Request) {
	stats := h.router.Firewall.GetStats()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// HandleRoutingStats 处理路由统计信息API
func (h *MonitorHandler) HandleRoutingStats(w http.ResponseWriter, r *http.Request) {
	routes := h.router.RoutingTable.GetAllRoutes()

	stats := map[string]interface{}{
		"total_routes": len(routes),
		"routes":       routes,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}
