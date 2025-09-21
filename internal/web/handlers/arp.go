package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

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

	// 转换数据格式以匹配前端期望
	var arpEntries []map[string]interface{}
	for _, entry := range entries {
		// 转换状态码为字符串
		var statusStr string
		switch entry.State {
		case 0: // StateIncomplete
			statusStr = "incomplete"
		case 1: // StateReachable
			statusStr = "reachable"
		case 2: // StateStale
			statusStr = "stale"
		case 3: // StateFailed
			statusStr = "failed"
		case 4: // StatePending
			statusStr = "pending"
		default:
			statusStr = "unknown"
		}

		arpEntry := map[string]interface{}{
			"ip":           entry.IPAddress.String(),
			"mac":          entry.MACAddress.String(),
			"interface":    entry.Interface,
			"status":       statusStr,
			"ttl":          entry.TTL.Seconds(),
			"timestamp":    entry.Timestamp.Format("2006-01-02 15:04:05"),
			"lastAccessed": entry.LastAccessed.Format("2006-01-02 15:04:05"),
		}
		arpEntries = append(arpEntries, arpEntry)
	}

	// 包装在entries字段中
	response := map[string]interface{}{
		"entries": arpEntries,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
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

// HandleARPAdd 处理添加静态ARP条目API
func (h *ARPHandler) HandleARPAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP        string `json:"ip"`
		MAC       string `json:"mac"`
		Interface string `json:"interface"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 验证IP地址
	ip := net.ParseIP(req.IP)
	if ip == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	// 验证MAC地址
	mac, err := net.ParseMAC(req.MAC)
	if err != nil {
		http.Error(w, "Invalid MAC address", http.StatusBadRequest)
		return
	}

	// 添加静态ARP条目
	if err := h.router.ARPTable.AddStaticEntry(ip, mac, req.Interface); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HandleARPDelete 处理删除ARP条目API
func (h *ARPHandler) HandleARPDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 从URL路径中提取IP地址
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid URL path", http.StatusBadRequest)
		return
	}

	ipStr := parts[len(parts)-1]
	ip := net.ParseIP(ipStr)
	if ip == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	// 删除ARP条目
	if !h.router.ARPTable.DeleteEntry(ip) {
		http.Error(w, "Entry not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HandleARPResolve 处理解析IP地址API
func (h *ARPHandler) HandleARPResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 验证IP地址
	ip := net.ParseIP(req.IP)
	if ip == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	// 同步接口信息
	err := h.router.ARPTable.SyncInterfacesFromManager(h.router.InterfaceManager)
	if err != nil {
		http.Error(w, "Failed to sync interfaces", http.StatusInternalServerError)
		return
	}

	// 智能选择最佳接口
	bestInterface, err := h.router.ARPTable.SelectBestInterface(ip)
	if err != nil {
		// 如果智能选择失败，尝试使用默认接口
		bestInterface = "en0"
	}

	// 发送ARP请求（异步）
	if err := h.router.ARPTable.SendARPRequest(ip, bestInterface); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HandleARPStats 处理获取ARP统计信息API
func (h *ARPHandler) HandleARPStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.router.ARPTable.GetStats()
	entries := h.router.ARPTable.GetAllEntries()

	// 统计各种状态的条目数量
	var reachableCount, staleCount, incompleteCount, permanentCount int
	for _, entry := range entries {
		switch entry.State {
		case 1: // StateReachable
			reachableCount++
		case 2: // StateStale
			staleCount++
		case 0: // StateIncomplete
			incompleteCount++
		case 4: // StatePending (treated as permanent for display)
			permanentCount++
		}
	}

	response := map[string]interface{}{
		"total_entries":      stats.TotalEntries,
		"reachable_entries":  reachableCount,
		"stale_entries":      staleCount,
		"incomplete_entries": incompleteCount,
		"permanent_entries":  permanentCount,
		"max_entries":        1000, // 从配置中获取
		"entries_added":      stats.EntriesAdded,
		"entries_removed":    stats.EntriesRemoved,
		"lookup_hits":        stats.LookupHits,
		"lookup_misses":      stats.LookupMisses,
		"requests_sent":      stats.RequestsSent,
		"replies_received":   stats.RepliesReceived,
		"expired_entries":    stats.ExpiredEntries,
		"conflicts_detected": stats.ConflictsDetected,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
