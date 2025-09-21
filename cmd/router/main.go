package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"router-os/internal/arp"
	"router-os/internal/config"
	"router-os/internal/database"
	"router-os/internal/dhcp"
	"router-os/internal/firewall"
	"router-os/internal/forwarding"
	"router-os/internal/interfaces"
	"router-os/internal/nat"
	"router-os/internal/netconfig"
	"router-os/internal/port"
	"router-os/internal/qos"
	"router-os/internal/routing"
	"router-os/internal/vpn"
	"router-os/internal/web"
)

func main() {
	// 设置时区为中国时区
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		log.Printf("加载中国时区失败，使用本地时区: %v", err)
	} else {
		time.Local = loc
		log.Println("已设置时区为中国时区 (Asia/Shanghai)")
	}

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

	// 初始化数据库连接
	log.Println("初始化数据库连接...")
	dbConfig, err := appConfig.Database.ToDBConfig()
	if err != nil {
		log.Fatalf("转换数据库配置失败: %v", err)
	}

	// 创建数据库连接
	db, err := database.CreateDatabase(dbConfig)
	if err != nil {
		log.Fatalf("创建数据库连接失败: %v", err)
	}

	// 连接数据库
	ctx := context.Background()
	if err = db.Connect(ctx); err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}
	log.Printf("数据库连接成功 - 类型: %s", dbConfig.Type)

	// 确保程序退出时关闭数据库连接
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("关闭数据库连接失败: %v", err)
		} else {
			log.Println("数据库连接已关闭")
		}
	}()

	// 初始化各个模块
	log.Println("初始化网络接口管理器...")
	interfaceManager := interfaces.NewManager()
	if err = interfaceManager.Start(); err != nil {
		log.Fatalf("启动接口管理器失败: %v", err)
	}

	log.Println("初始化路由表...")
	routingTable := routing.NewOptimizedTableWithDefaults()

	log.Println("初始化ARP表...")
	arpTable := arp.NewARPTable(1000, 300*time.Second, 60*time.Second)
	if err = arpTable.Start(); err != nil {
		log.Fatalf("启动ARP表失败: %v", err)
	}

	log.Println("初始化数据包转发引擎...")
	forwardingEngine := forwarding.NewForwardingEngine(routingTable, interfaceManager, arpTable)
	if err = forwardingEngine.Start(); err != nil {
		log.Fatalf("启动转发引擎失败: %v", err)
	}

	log.Println("初始化网络配置器...")
	netConfig := netconfig.NewNetworkConfigurator()

	// 获取系统路由表并同步到路由表中
	log.Println("获取系统路由表...")
	systemRoutes, err := netConfig.GetRouteTable()
	if err != nil {
		log.Printf("获取系统路由表失败: %v", err)
	} else {
		log.Printf("成功获取到 %d 条系统路由", len(systemRoutes))

		// 将系统路由添加到路由表中
		for _, routeEntry := range systemRoutes {
			// 目标网络已经是*net.IPNet类型，直接使用
			destNet := routeEntry.Destination
			if destNet == nil {
				log.Printf("跳过无效的路由条目：目标网络为空")
				continue
			}

			// 网关IP已经是net.IP类型，直接使用
			gateway := routeEntry.Gateway

			// 根据路由类型字符串确定路由类型
			var routeType routing.RouteType
			switch routeEntry.Type {
			case "static":
				routeType = routing.RouteTypeStatic
			case "dynamic":
				routeType = routing.RouteTypeDynamic
			case "connected":
				routeType = routing.RouteTypeConnected
			case "default":
				routeType = routing.RouteTypeDefault
			default:
				routeType = routing.RouteTypeStatic // 默认为静态路由
			}

			// 使用netconfig.RouteEntry中的字段，如果为空则使用默认值
			proto := routeEntry.Proto
			if proto == "" {
				proto = "kernel"
			}

			scope := routeEntry.Scope
			if scope == "" {
				scope = "global"
			}

			flags := routeEntry.Flags
			if flags == "" {
				// 根据路由类型设置默认flags
				if routeType == routing.RouteTypeDefault {
					flags = "default"
				}
			}

			// 创建路由条目
			route := routing.Route{
				Destination: destNet,
				Gateway:     gateway,
				Interface:   routeEntry.Interface,
				Metric:      routeEntry.Metric,
				Proto:       proto,
				Scope:       scope,
				Src:         routeEntry.Src,
				Flags:       flags,
				Type:        routeType,
				Age:         time.Now(),
			}

			// 添加到路由表
			if err = routingTable.AddRoute(route); err != nil {
				log.Printf("添加系统路由失败 %s: %v", destNet.String(), err)
			} else {
				gatewayStr := "直连"
				if gateway != nil {
					gatewayStr = gateway.String()
				}
				log.Printf("成功添加系统路由: %s via %s dev %s",
					destNet.String(), gatewayStr, routeEntry.Interface)
			}
		}
	}

	log.Println("初始化防火墙...")
	firewallEngine := firewall.NewFirewall()
	if err = firewallEngine.Start(); err != nil {
		log.Fatalf("启动防火墙失败: %v", err)
	}

	log.Println("初始化QoS引擎...")
	qosEngine := qos.NewQoSEngine()
	if err = qosEngine.Start(); err != nil {
		log.Fatalf("启动QoS引擎失败: %v", err)
	}

	log.Println("初始化NAT管理器...")
	natBackend := nat.NewIptablesManager()
	natManager := nat.NewManager(natBackend, interfaceManager)
	if err = natManager.Start(); err != nil {
		log.Fatalf("启动NAT管理器失败: %v", err)
	}

	log.Println("初始化端口管理器...")
	portManager := port.NewManager(interfaceManager, natManager)
	if err = portManager.Start(); err != nil {
		log.Fatalf("启动端口管理器失败: %v", err)
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
		// 正确解析子网掩码和网络地址
		var network *net.IPNet
		var mask net.IPMask

		// 解析子网掩码
		maskIP := net.ParseIP(appConfig.DHCP.SubnetMask)
		if maskIP != nil && maskIP.To4() != nil {
			// 将IP地址格式的子网掩码转换为IPMask
			mask = net.IPv4Mask(maskIP[12], maskIP[13], maskIP[14], maskIP[15])
		} else {
			// 如果解析失败，使用默认的/24掩码
			mask = net.CIDRMask(24, 32)
			log.Printf("警告: 子网掩码解析失败，使用默认/24掩码")
		}

		// 使用网关IP计算网络地址
		gatewayIP := net.ParseIP(appConfig.DHCP.Gateway)
		if gatewayIP != nil {
			// 计算网络地址：网关IP与掩码进行AND操作
			networkIP := gatewayIP.Mask(mask)
			network = &net.IPNet{
				IP:   networkIP,
				Mask: mask,
			}
			log.Printf("DHCP网络配置: %s/%d, 网关: %s", network.IP.String(), maskBits(mask), gatewayIP.String())
		} else {
			// 备用方案：使用起始IP计算网络地址
			startIP := net.ParseIP(appConfig.DHCP.StartIP)
			if startIP != nil {
				networkIP := startIP.Mask(mask)
				network = &net.IPNet{
					IP:   networkIP,
					Mask: mask,
				}
				log.Printf("DHCP网络配置(备用): %s/%d", network.IP.String(), maskBits(mask))
			} else {
				// 最后的备用方案
				_, network, _ = net.ParseCIDR("192.168.2.0/24")
				log.Printf("DHCP网络配置(默认): %s", network.String())
			}
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

		if err = dhcpServer.AddPool(pool); err != nil {
			log.Printf("添加DHCP地址池失败: %v", err)
		}

		if err = dhcpServer.Start("0.0.0.0:67"); err != nil {
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
		if err = vpnServer.Start(); err != nil {
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
		PortManager:      portManager,
		NATManager:       natManager,
	}

	// 根据配置决定是否启动Web管理界面
	var webServer *web.Server
	if appConfig.Web.Enabled {
		log.Println("Web管理界面已启用，正在启动...")
		webConfig := web.Config{
			Port:     appConfig.Web.Port,
			Host:     appConfig.Web.Host,
			Username: appConfig.Web.Username,
			Password: appConfig.Web.Password,
		}
		webServer = web.NewWebServer(webConfig, router)

		go func() {
			if err = webServer.Start(); err != nil {
				log.Printf("Web服务器启动失败: %v", err)
			}
		}()

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

	// 创建带超时的context，最多等待5秒
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 使用WaitGroup来并发关闭服务
	var wg sync.WaitGroup

	// 定义关闭函数
	shutdownService := func(name string, stopFunc func()) {
		defer wg.Done()
		log.Printf("正在关闭 %s...", name)
		stopFunc()
		log.Printf("%s 已关闭", name)
	}

	shutdownServiceWithError := func(name string, stopFunc func() error) {
		defer wg.Done()
		log.Printf("正在关闭 %s...", name)
		if err := stopFunc(); err != nil {
			log.Printf("关闭 %s 失败: %v", name, err)
		} else {
			log.Printf("%s 已关闭", name)
		}
	}

	// 并发关闭所有服务
	if webServer != nil {
		wg.Add(1)
		go shutdownServiceWithError("Web服务器", webServer.Stop)
	}

	wg.Add(6)
	go shutdownService("VPN服务器", vpnServer.Stop)
	go shutdownService("DHCP服务器", dhcpServer.Stop)
	go shutdownService("QoS引擎", qosEngine.Stop)
	go shutdownService("防火墙引擎", firewallEngine.Stop)
	go shutdownService("转发引擎", forwardingEngine.Stop)
	go shutdownService("ARP表", arpTable.Stop)

	// 接口管理器最后关闭
	wg.Add(1)
	go shutdownService("接口管理器", interfaceManager.Stop)

	// 等待所有服务关闭或超时
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("Router OS 已正常关闭")
	case <-ctx.Done():
		log.Println("关闭超时，强制退出")
	}
}

// maskBits 计算子网掩码的位数
func maskBits(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}
