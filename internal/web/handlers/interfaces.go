package handlers

import (
	"encoding/json"
	"net/http"

	"router-os/internal/web/templates"
)

// InterfacesHandler 网络接口处理器
type InterfacesHandler struct {
	renderer *templates.Renderer
	router   *RouterInstance
}

// NewInterfacesHandler 创建网络接口处理器
func NewInterfacesHandler(renderer *templates.Renderer, router *RouterInstance) *InterfacesHandler {
	return &InterfacesHandler{
		renderer: renderer,
		router:   router,
	}
}

// ShowInterfaces 显示网络接口页面
func (h *InterfacesHandler) ShowInterfaces(w http.ResponseWriter, r *http.Request) {
	data := templates.TemplateData{
		Title: "网络接口",
	}

	if err := h.renderer.Render(w, "interfaces", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// HandleInterfacesList 处理接口列表API
func (h *InterfacesHandler) HandleInterfacesList(w http.ResponseWriter, r *http.Request) {
	interfacesMap := h.router.InterfaceManager.GetAllInterfaces()

	// 转换为前端期望的格式
	var interfaces []map[string]interface{}
	for _, iface := range interfacesMap {
		var status string
		switch iface.Status {
		case 0: // InterfaceStatusDown
			status = "down"
		case 1: // InterfaceStatusUp
			status = "up"
		case 2: // InterfaceStatusTesting
			status = "testing"
		default:
			status = "unknown"
		}

		var ipStr string
		if iface.IPAddress != nil {
			ipStr = iface.IPAddress.String()
		}

		var macStr string
		if iface.MACAddress != nil {
			macStr = iface.MACAddress.String()
		}

		interfaceData := map[string]interface{}{
			"name":   iface.Name,
			"ip":     ipStr,
			"status": status,
			"mac":    macStr,
			"mtu":    iface.MTU,
		}
		interfaces = append(interfaces, interfaceData)
	}

	response := map[string]interface{}{
		"interfaces": interfaces,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// HandleInterfaceUpdate 处理接口更新API
func (h *InterfacesHandler) HandleInterfaceUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var updateReq struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 更新接口状态
	if updateReq.Status == "up" {
		if err := h.router.InterfaceManager.SetInterfaceStatus(updateReq.Name, 1); err != nil { // InterfaceStatusUp = 1
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := h.router.InterfaceManager.SetInterfaceStatus(updateReq.Name, 0); err != nil { // InterfaceStatusDown = 0
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}
