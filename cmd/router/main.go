package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"router-os/internal/arp"
	"router-os/internal/config"
	"router-os/internal/dhcp"
	"router-os/internal/firewall"
	"router-os/internal/forwarding"
	"router-os/internal/interfaces"
	"router-os/internal/netconfig"
	"router-os/internal/qos"
	"router-os/internal/routing"
	"router-os/internal/vpn"
	"router-os/internal/web"
)

func main() {
	// 命令行参数
	var (
		configFile = flag.String("config", "config.json", "配置文件路径")
		help       = flag.Bool("help", false, "显示帮助信息")
	)
	flag.Parse()

	if *help {
		fmt.Println("Router OS - 高性能路由器操作系统")
		fmt.Println()
		fmt.Println("用法:")
		flag.PrintDefaults()
		return
	}

	log.Println("启动 Router OS...")

	// 加载配置文件
	log.Printf("加载配置文件: %s", *configFile)
	appConfig, err := config.LoadAppConfig(*configFile)
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}
	log.Printf("配置加载成功 - DHCP启用: %v, VPN启用: %v", appConfig.DHCP.Enabled, appConfig.VPN.Enabled)

	// 初始化各个模块
	log.Println("初始化网络接口管理器...")
	interfaceManager := interfaces.NewManager()
	if err := interfaceManager.Start(); err != nil {
		log.Fatalf("启动接口管理器失败: %v", err)
	}

	log.Println("初始化路由表...")
	routingTable := routing.NewTable()

	log.Println("初始化ARP表...")
	arpTable := arp.NewARPTable(1000, 300, 60*time.Second)
	if err := arpTable.Start(); err != nil {
		log.Fatalf("启动ARP表失败: %v", err)
	}

	log.Println("初始化数据包转发引擎...")
	forwardingEngine := forwarding.NewForwardingEngine(routingTable, interfaceManager, arpTable)
	if err := forwardingEngine.Start(); err != nil {
		log.Fatalf("启动转发引擎失败: %v", err)
	}

	log.Println("初始化网络配置器...")
	netConfig := netconfig.NewNetworkConfigurator()

	log.Println("初始化防火墙...")
	firewallEngine := firewall.NewFirewall()
	if err := firewallEngine.Start(); err != nil {
		log.Fatalf("启动防火墙失败: %v", err)
	}

	log.Println("初始化QoS引擎...")
	qosEngine := qos.NewQoSEngine()
	if err := qosEngine.Start(); err != nil {
		log.Fatalf("启动QoS引擎失败: %v", err)
	}

	log.Println("初始化DHCP服务器...")
	dhcpServer := dhcp.NewDHCPServer()

	// 根据配置决定是否启动DHCP服务器
	if appConfig.DHCP.Enabled {
		log.Println("DHCP服务已启用，正在配置...")

		// 配置DHCP服务器
		dhcpConfig := dhcpServer.GetConfig()
		dhcpConfig.Enabled = true
		dhcpConfig.Interface = appConfig.DHCP.Interface
		dhcpConfig.ListenAddress = "0.0.0.0"
		dhcpConfig.DefaultLeaseTime = appConfig.DHCP.GetLeaseTimeDuration()
		dhcpServer.SetConfig(dhcpConfig)

		// 添加地址池
		_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%s", appConfig.DHCP.StartIP[:len(appConfig.DHCP.StartIP)-3], "24"))
		if err != nil {
			// 如果解析失败，使用默认网络
			_, network, _ = net.ParseCIDR("192.168.1.0/24")
		}

		pool := &dhcp.AddressPool{
			ID:          "default",
			Name:        "Default Pool",
			Network:     network,
			StartIP:     net.ParseIP(appConfig.DHCP.StartIP),
			EndIP:       net.ParseIP(appConfig.DHCP.EndIP),
			Gateway:     net.ParseIP(appConfig.DHCP.Gateway),
			DNSServers:  make([]net.IP, len(appConfig.DHCP.DNSServers)),
			DomainName:  "local",
			LeaseTime:   appConfig.DHCP.GetLeaseTimeDuration(),
			Enabled:     true,
			Options:     make(map[byte][]byte),
			ExcludedIPs: []net.IP{},
			CreatedAt:   time.Now(),
		}

		// 转换DNS服务器
		for i, dns := range appConfig.DHCP.DNSServers {
			pool.DNSServers[i] = net.ParseIP(dns)
		}

		if err := dhcpServer.AddPool(pool); err != nil {
			log.Printf("添加DHCP地址池失败: %v", err)
		}

		if err := dhcpServer.Start(); err != nil {
			log.Fatalf("启动DHCP服务器失败: %v", err)
		}
		log.Println("DHCP服务器启动成功")
	} else {
		log.Println("DHCP服务已禁用，跳过启动")
	}

	log.Println("初始化VPN服务器...")
	vpnServer := vpn.NewVPNServer()

	// 根据配置决定是否启动VPN服务器
	if appConfig.VPN.Enabled {
		log.Println("VPN服务已启用，正在启动...")
		if err := vpnServer.Start(); err != nil {
			log.Fatalf("启动VPN服务器失败: %v", err)
		}
		log.Println("VPN服务器启动成功")
	} else {
		log.Println("VPN服务已禁用，跳过启动")
	}

	// 创建路由器实例
	router := &web.RouterInstance{
		InterfaceManager: interfaceManager,
		RoutingTable:     routingTable,
		ARPTable:         arpTable,
		Forwarder:        forwardingEngine,
		NetConfig:        netConfig,
		Firewall:         firewallEngine,
		QoS:              qosEngine,
		DHCP:             dhcpServer,
		VPN:              vpnServer,
	}

	// 根据配置决定是否启动Web管理界面
	var webServer *web.WebServer
	if appConfig.Web.Enabled {
		log.Println("Web管理界面已启用，正在启动...")
		webConfig := web.WebConfig{
			Port:     appConfig.Web.Port,
			Host:     appConfig.Web.Host,
			Username: appConfig.Web.Username,
			Password: appConfig.Web.Password,
		}
		webServer = web.NewWebServer(webConfig, router)
		if err := webServer.Start(); err != nil {
			log.Fatalf("启动Web服务器失败: %v", err)
		}
		log.Printf("Web管理界面启动成功: http://%s:%d", appConfig.Web.Host, appConfig.Web.Port)
		log.Printf("用户名: %s, 密码: %s", appConfig.Web.Username, appConfig.Web.Password)
	} else {
		log.Println("Web管理界面已禁用，跳过启动")
	}

	log.Printf("Router OS 启动完成!")

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("正在关闭 Router OS...")

	// 优雅关闭所有服务
	if webServer != nil {
		if err := webServer.Stop(); err != nil {
			log.Printf("关闭Web服务器失败: %v", err)
		}
	}

	vpnServer.Stop()
	dhcpServer.Stop()
	qosEngine.Stop()
	firewallEngine.Stop()
	forwardingEngine.Stop()
	arpTable.Stop()
	interfaceManager.Stop()

	log.Println("Router OS 已关闭")
}
