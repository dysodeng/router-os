package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"router-os/internal/dhcp"
	"router-os/internal/web/templates"
)

// DHCPHandler DHCP处理器
type DHCPHandler struct {
	renderer *templates.Renderer
	router   *RouterInstance
}

// NewDHCPHandler 创建DHCP处理器
func NewDHCPHandler(renderer *templates.Renderer, router *RouterInstance) *DHCPHandler {
	return &DHCPHandler{
		renderer: renderer,
		router:   router,
	}
}

// convertIPsToStrings converts a slice of net.IP to a slice of strings
func convertIPsToStrings(ips []net.IP) []string {
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result
}

// ShowDHCP 显示DHCP页面
func (h *DHCPHandler) ShowDHCP(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "DHCP服务器",
	}

	if err := h.renderer.Render(w, "dhcp", data); err != nil {
		http.Error(w, "渲染模板失败", http.StatusInternalServerError)
		return
	}
}

// HandleDHCPConfig handles DHCP configuration requests
func (h *DHCPHandler) HandleDHCPConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// Get real DHCP configuration from the server
		dhcpConfig := h.router.DHCP.GetConfig()

		// Convert to response format
		config := map[string]interface{}{
			"enabled":            dhcpConfig.Enabled,
			"server_ip":          dhcpConfig.ServerIP.String(),
			"range_start":        dhcpConfig.PoolStart.String(),
			"range_end":          dhcpConfig.PoolEnd.String(),
			"netmask":            net.IP(dhcpConfig.SubnetMask).String(),
			"gateway":            dhcpConfig.Gateway.String(),
			"dns_servers":        convertIPsToStrings(dhcpConfig.DNSServers),
			"domain_name":        dhcpConfig.DomainName,
			"lease_time":         dhcpConfig.LeaseTime.String(),
			"interface":          dhcpConfig.Interface,
			"listen_address":     dhcpConfig.ListenAddress,
			"default_lease_time": dhcpConfig.DefaultLeaseTime.String(),
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(config)

	case "POST":
		// Update DHCP configuration
		var configData map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&configData); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Parse and validate configuration
		config := &dhcp.Config{}

		if enabled, ok := configData["enabled"].(bool); ok {
			config.Enabled = enabled
		}

		if serverIP, ok := configData["server_ip"].(string); ok {
			config.ServerIP = net.ParseIP(serverIP)
		}

		if poolStart, ok := configData["range_start"].(string); ok {
			config.PoolStart = net.ParseIP(poolStart)
		}

		if poolEnd, ok := configData["range_end"].(string); ok {
			config.PoolEnd = net.ParseIP(poolEnd)
		}

		if subnetMask, ok := configData["netmask"].(string); ok {
			config.SubnetMask = net.IPMask(net.ParseIP(subnetMask).To4())
		}

		if gateway, ok := configData["gateway"].(string); ok {
			config.Gateway = net.ParseIP(gateway)
		}

		if dnsServers, ok := configData["dns_servers"].([]interface{}); ok {
			for _, dns := range dnsServers {
				if dnsStr, ok := dns.(string); ok {
					config.DNSServers = append(config.DNSServers, net.ParseIP(dnsStr))
				}
			}
		}

		if domainName, ok := configData["domain_name"].(string); ok {
			config.DomainName = domainName
		}

		if leaseTime, ok := configData["lease_time"].(string); ok {
			if duration, err := time.ParseDuration(leaseTime); err == nil {
				config.LeaseTime = duration
				config.DefaultLeaseTime = duration
			}
		}

		// Update the DHCP server configuration
		h.router.DHCP.SetConfig(config)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}
}

// HandleDHCPLeases 处理DHCP租约
func (h *DHCPHandler) HandleDHCPLeases(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// 获取DHCP租约列表
	var leases []interface{}
	if h.router.DHCP != nil {
		// 这里应该从DHCP服务器获取实际的租约信息
		dhcpLeases := h.router.DHCP.GetLeases()
		for _, lease := range dhcpLeases {
			remaining := lease.Duration - time.Since(lease.StartTime)
			if remaining < 0 {
				remaining = 0
			}

			// 计算结束时间
			endTime := lease.StartTime.Add(lease.Duration)

			// 判断租约状态
			status := "active"
			if remaining <= 0 {
				status = "expired"
			}

			leases = append(leases, map[string]interface{}{
				"ip":         lease.IP.String(),
				"mac":        lease.MAC.String(),
				"hostname":   lease.Hostname,
				"lease_time": lease.Duration.String(),
				"remaining":  remaining.String(),
				"status":     status,
				"start_time": lease.StartTime.In(time.Local).Format("2006-01-02 15:04:05 CST"),
				"end_time":   endTime.In(time.Local).Format("2006-01-02 15:04:05 CST"),
			})
		}
	}

	// 包装在leases字段中
	response := map[string]interface{}{
		"leases": leases,
	}

	_ = json.NewEncoder(w).Encode(response)
}
