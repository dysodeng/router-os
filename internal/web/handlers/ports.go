package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"router-os/internal/module/interfaces"
	"router-os/internal/web/templates"
)

// PortsHandler 端口管理处理器
type PortsHandler struct {
	renderer *templates.Renderer
	router   *RouterInstance
}

// NewPortsHandler 创建端口管理处理器
func NewPortsHandler(renderer *templates.Renderer, router *RouterInstance) *PortsHandler {
	return &PortsHandler{
		renderer: renderer,
		router:   router,
	}
}

// ShowPorts 显示端口管理页面
func (h *PortsHandler) ShowPorts(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "端口管理",
	}

	if err := h.renderer.Render(w, "ports", data); err != nil {
		http.Error(w, "渲染模板失败", http.StatusInternalServerError)
		return
	}
}

// PortInfo 端口信息结构
type PortInfo struct {
	Name      string                     `json:"name"`
	Role      interfaces.PortRole        `json:"role"`
	Status    interfaces.InterfaceStatus `json:"status"`
	IPAddress string                     `json:"ip_address"`
	Netmask   string                     `json:"netmask"`
	Gateway   string                     `json:"gateway"`
	MTU       int                        `json:"mtu"`
	Speed     int64                      `json:"speed"`
	Duplex    string                     `json:"duplex"`
	TxPackets uint64                     `json:"tx_packets"`
	RxPackets uint64                     `json:"rx_packets"`
	TxBytes   uint64                     `json:"tx_bytes"`
	RxBytes   uint64                     `json:"rx_bytes"`
	TxErrors  uint64                     `json:"tx_errors"`
	RxErrors  uint64                     `json:"rx_errors"`
	TxDropped uint64                     `json:"tx_dropped"`
	RxDropped uint64                     `json:"rx_dropped"`
}

// HandlePortsList 处理端口列表请求
func (h *PortsHandler) HandlePortsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "GET" {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	// 获取所有接口
	interfacesMap := h.router.InterfaceManager.GetAllInterfaces()

	var ports []PortInfo
	for _, iface := range interfacesMap {
		// 获取接口角色
		role, _ := h.router.InterfaceManager.GetInterfaceRole(iface.Name)

		port := PortInfo{
			Name:      iface.Name,
			Role:      role,
			Status:    iface.Status,
			IPAddress: iface.IPAddress.String(),
			Netmask:   net.IP(iface.Netmask).String(),
			Gateway:   iface.Gateway.String(),
			MTU:       iface.MTU,
			Speed:     0,  // 暂时设为0，Interface结构体中没有Speed字段
			Duplex:    "", // 暂时设为空，Interface结构体中没有Duplex字段
			TxPackets: iface.TxPackets,
			RxPackets: iface.RxPackets,
			TxBytes:   iface.TxBytes,
			RxBytes:   iface.RxBytes,
			TxErrors:  iface.Errors, // 使用Errors字段
			RxErrors:  0,            // Interface结构体中没有单独的RxErrors
			TxDropped: 0,            // Interface结构体中没有TxDropped字段
			RxDropped: 0,            // Interface结构体中没有RxDropped字段
		}
		ports = append(ports, port)
	}

	if err := json.NewEncoder(w).Encode(ports); err != nil {
		http.Error(w, "编码响应失败", http.StatusInternalServerError)
		return
	}
}

// PortRoleRequest 端口角色设置请求
type PortRoleRequest struct {
	InterfaceName string `json:"interface_name"`
	Role          string `json:"role"`
}

// HandlePortRoleUpdate 处理端口角色更新
func (h *PortsHandler) HandlePortRoleUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req PortRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "解析请求失败", http.StatusBadRequest)
		return
	}

	// 验证角色值
	var role interfaces.PortRole
	switch strings.ToUpper(req.Role) {
	case "WAN":
		role = interfaces.PortRoleWAN
	case "LAN":
		role = interfaces.PortRoleLAN
	case "UNASSIGNED":
		role = interfaces.PortRoleUnassigned
	default:
		http.Error(w, "无效的端口角色", http.StatusBadRequest)
		return
	}

	// 使用端口管理器分配角色，这会自动处理转发规则
	if err := h.router.PortManager.AssignPortRole(req.InterfaceName, role); err != nil {
		http.Error(w, "设置端口角色失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "端口角色设置成功",
		"data": map[string]interface{}{
			"interface_name": req.InterfaceName,
			"role":           role.String(),
		},
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "编码响应失败", http.StatusInternalServerError)
		return
	}
}

// HandlePortTopology 处理网络拓扑信息
func (h *PortsHandler) HandlePortTopology(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "GET" {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	// 获取不同角色的接口
	wanInterfaces := h.router.InterfaceManager.GetWANInterfaces()
	lanInterfaces := h.router.InterfaceManager.GetLANInterfaces()
	unassignedInterfaces := h.router.InterfaceManager.GetUnassignedInterfaces()

	topology := map[string]interface{}{
		"wan_interfaces":        wanInterfaces,
		"lan_interfaces":        lanInterfaces,
		"unassigned_interfaces": unassignedInterfaces,
		"total_interfaces":      len(h.router.InterfaceManager.GetAllInterfaces()),
	}

	if err := json.NewEncoder(w).Encode(topology); err != nil {
		http.Error(w, "编码响应失败", http.StatusInternalServerError)
		return
	}
}

// BatchPortRoleRequest 批量端口角色设置请求
type BatchPortRoleRequest struct {
	Updates []PortRoleRequest `json:"updates"`
}

// HandleBatchPortRoleUpdate 处理批量端口角色更新
func (h *PortsHandler) HandleBatchPortRoleUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req BatchPortRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "解析请求失败", http.StatusBadRequest)
		return
	}

	var results []map[string]interface{}
	var errors []string

	for _, update := range req.Updates {
		// 验证角色值
		var role interfaces.PortRole
		switch strings.ToUpper(update.Role) {
		case "WAN":
			role = interfaces.PortRoleWAN
		case "LAN":
			role = interfaces.PortRoleLAN
		case "UNASSIGNED":
			role = interfaces.PortRoleUnassigned
		default:
			errors = append(errors, "接口 "+update.InterfaceName+" 的角色无效: "+update.Role)
			continue
		}

		// 使用端口管理器分配角色，这会自动处理转发规则
		if err := h.router.PortManager.AssignPortRole(update.InterfaceName, role); err != nil {
			errors = append(errors, "设置接口 "+update.InterfaceName+" 角色失败: "+err.Error())
			continue
		}

		results = append(results, map[string]interface{}{
			"interface_name": update.InterfaceName,
			"role":           role.String(),
			"status":         "success",
		})
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "批量更新完成",
		"results": results,
	}

	if len(errors) > 0 {
		response["errors"] = errors
		response["status"] = "partial_success"
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "编码响应失败", http.StatusInternalServerError)
		return
	}
}
