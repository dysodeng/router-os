package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"router-os/internal/arp"
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
		webPort = flag.Int("port", 8080, "Web管理界面端口")
		webHost = flag.String("host", "0.0.0.0", "Web管理界面监听地址")
		help    = flag.Bool("help", false, "显示帮助信息")
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
	if err := dhcpServer.Start(); err != nil {
		log.Fatalf("启动DHCP服务器失败: %v", err)
	}

	log.Println("初始化VPN服务器...")
	vpnServer := vpn.NewVPNServer()
	if err := vpnServer.Start(); err != nil {
		log.Fatalf("启动VPN服务器失败: %v", err)
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

	log.Println("启动Web管理界面...")
	webConfig := web.WebConfig{
		Port:     *webPort,
		Host:     *webHost,
		Username: "admin",
		Password: "admin123",
	}
	webServer := web.NewWebServer(webConfig, router)
	if err := webServer.Start(); err != nil {
		log.Fatalf("启动Web服务器失败: %v", err)
	}

	log.Printf("Router OS 启动完成!")
	log.Printf("Web管理界面: http://%s:%d", *webHost, *webPort)
	log.Printf("默认用户名: admin, 密码: admin123")

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("正在关闭 Router OS...")

	// 优雅关闭所有服务
	if err := webServer.Stop(); err != nil {
		log.Printf("关闭Web服务器失败: %v", err)
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