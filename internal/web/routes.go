package web

import (
	"fmt"
	"net/http"

	"router-os/internal/web/handlers"
	"router-os/internal/web/middleware"
	"router-os/internal/web/templates"
)

// setupRoutes 设置路由
func (ws *Server) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// 创建中间件
	authMiddleware := middleware.NewAuthMiddleware(middleware.AuthConfig{
		Username: ws.config.Username,
		Password: ws.config.Password,
	})
	corsMiddleware := middleware.CORSMiddleware
	loggingMiddleware := middleware.LoggingMiddleware

	// 创建模板渲染器
	renderer := templates.NewRenderer("./templates")
	if err := renderer.LoadTemplates(); err != nil {
		panic(fmt.Sprintf("加载模板失败: %v", err))
	}

	// 转换路由器实例类型
	routerInstance := &handlers.RouterInstance{
		InterfaceManager: ws.router.InterfaceManager,
		RoutingTable:     ws.router.RoutingTable,
		ARPTable:         ws.router.ARPTable,
		Forwarder:        ws.router.Forwarder,
		NetConfig:        ws.router.NetConfig,
		Firewall:         ws.router.Firewall,
		QoS:              ws.router.QoS,
		DHCP:             ws.router.DHCP,
		VPN:              ws.router.VPN,
		PortManager:      ws.router.PortManager,
		NATManager:       ws.router.NATManager,
	}

	// 创建处理器
	authHandler := handlers.NewAuthHandler(authMiddleware, renderer)
	dashboardHandler := handlers.NewDashboardHandler(renderer, routerInstance)
	interfacesHandler := handlers.NewInterfacesHandler(renderer, routerInstance)
	routesHandler := handlers.NewRoutesHandler(renderer, routerInstance)
	arpHandler := handlers.NewARPHandler(renderer, routerInstance)
	firewallHandler := handlers.NewFirewallHandler(renderer, routerInstance)
	monitorHandler := handlers.NewMonitorHandler(routerInstance)
	qosHandler := handlers.NewQoSHandler(renderer, routerInstance)
	vpnHandler := handlers.NewVPNHandler(renderer, routerInstance)
	dhcpHandler := handlers.NewDHCPHandler(renderer, routerInstance)
	portsHandler := handlers.NewPortsHandler(renderer, routerInstance)

	// 静态文件和首页
	mux.HandleFunc("/", dashboardHandler.ShowDashboard)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./templates/static/"))))

	// 认证相关路由
	mux.HandleFunc("/login", authHandler.ShowLogin)
	mux.HandleFunc("/api/login", corsMiddleware(loggingMiddleware(authHandler.HandleLogin)))
	mux.HandleFunc("/api/logout", corsMiddleware(loggingMiddleware(authHandler.HandleLogout)))

	// 仪表板路由
	mux.HandleFunc("/dashboard", dashboardHandler.ShowDashboard)
	mux.HandleFunc("/api/status", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(dashboardHandler.HandleStatus))))

	// 网络接口路由
	mux.HandleFunc("/interfaces", interfacesHandler.ShowInterfaces)
	mux.HandleFunc("/api/interfaces", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(interfacesHandler.HandleInterfacesList))))
	mux.HandleFunc("/api/interfaces/update", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(interfacesHandler.HandleInterfaceUpdate))))

	// 路由表路由
	mux.HandleFunc("/routes", routesHandler.ShowRoutes)
	mux.HandleFunc("/api/routes", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(routesHandler.HandleRoutesList))))
	mux.HandleFunc("/api/routes/add", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(routesHandler.HandleRouteAdd))))
	mux.HandleFunc("/api/routes/delete", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(routesHandler.HandleRouteDelete))))

	// ARP表路由
	mux.HandleFunc("/arp", arpHandler.ShowARP)
	mux.HandleFunc("/api/arp", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(arpHandler.HandleARPList))))
	mux.HandleFunc("/api/arp/clear", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(arpHandler.HandleARPClear))))
	mux.HandleFunc("/api/arp/add", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(arpHandler.HandleARPAdd))))
	mux.HandleFunc("/api/arp/delete/", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(arpHandler.HandleARPDelete))))
	mux.HandleFunc("/api/arp/resolve", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(arpHandler.HandleARPResolve))))
	mux.HandleFunc("/api/arp/stats", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(arpHandler.HandleARPStats))))

	// 防火墙路由
	mux.HandleFunc("/firewall", firewallHandler.ShowFirewall)
	mux.HandleFunc("/api/firewall/rules", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(firewallHandler.HandleRulesList))))
	mux.HandleFunc("/api/firewall/rules/add", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(firewallHandler.HandleRuleAdd))))
	mux.HandleFunc("/api/firewall/rules/delete", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(firewallHandler.HandleRuleDelete))))

	// 系统监控路由
	mux.HandleFunc("/monitor", monitorHandler.ShowMonitor)
	mux.HandleFunc("/api/monitor/system", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(monitorHandler.HandleSystemStats))))
	mux.HandleFunc("/api/monitor/network", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(monitorHandler.HandleNetworkStats))))
	mux.HandleFunc("/api/monitor/firewall", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(monitorHandler.HandleFirewallStats))))
	mux.HandleFunc("/api/monitor/routing", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(monitorHandler.HandleRoutingStats))))

	// QoS路由
	mux.HandleFunc("/qos", qosHandler.ShowQoS)
	mux.HandleFunc("/api/qos/config", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(qosHandler.HandleQoSConfig))))
	mux.HandleFunc("/api/qos/rules", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(qosHandler.HandleQoSRules))))

	// VPN路由
	mux.HandleFunc("/vpn", vpnHandler.ShowVPN)
	mux.HandleFunc("/api/vpn/config", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(vpnHandler.HandleVPNConfig))))
	mux.HandleFunc("/api/vpn/clients", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(vpnHandler.HandleVPNClients))))

	// DHCP路由
	mux.HandleFunc("/dhcp", dhcpHandler.ShowDHCP)
	mux.HandleFunc("/api/dhcp/config", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(dhcpHandler.HandleDHCPConfig))))
	mux.HandleFunc("/api/dhcp/leases", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(dhcpHandler.HandleDHCPLeases))))

	// 端口管理路由
	mux.HandleFunc("/ports", portsHandler.ShowPorts)
	mux.HandleFunc("/api/ports", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(portsHandler.HandlePortsList))))
	mux.HandleFunc("/api/ports/role", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(portsHandler.HandlePortRoleUpdate))))
	mux.HandleFunc("/api/ports/topology", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(portsHandler.HandlePortTopology))))
	mux.HandleFunc("/api/ports/batch", corsMiddleware(loggingMiddleware(authMiddleware.RequireAuth(portsHandler.HandleBatchPortRoleUpdate))))

	return mux
}
