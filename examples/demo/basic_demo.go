package demo

import (
	"fmt"
	"net"
	"strings"

	"router-os/internal/module/protocols"
	"router-os/internal/module/router"
	"router-os/internal/module/routing"
)

func RunBasicDemo() {
	fmt.Println("Router OS 基本功能测试")
	fmt.Println()

	// 创建路由器
	r, err := router.NewRouter()
	if err != nil {
		fmt.Printf("创建路由器失败: %v\n", err)
		return
	}

	// 启动路由器
	if err := r.Start(); err != nil {
		fmt.Printf("启动路由器失败: %v\n", err)
		return
	}
	defer r.Stop()

	// 创建静态路由管理器
	staticManager := protocols.NewStaticRouteManager(r.GetRoutingTable())

	// 测试添加静态路由
	fmt.Println("\n=== 测试静态路由 ===")

	// 添加一些测试路由
	routes := []struct {
		dest, gateway, iface string
		metric               int
	}{
		{"192.168.1.0/24", "10.0.0.1", "eth0", 1},
		{"192.168.2.0/24", "10.0.0.2", "eth1", 2},
		{"0.0.0.0/0", "10.0.0.1", "eth0", 10}, // 默认路由
	}

	for _, route := range routes {
		if err := staticManager.AddStaticRoute(route.dest, route.gateway, route.iface, route.metric); err != nil {
			fmt.Printf("添加路由失败 %s: %v\n", route.dest, err)
		} else {
			fmt.Printf("成功添加路由: %s -> %s via %s (metric: %d)\n",
				route.dest, route.gateway, route.iface, route.metric)
		}
	}

	// 显示路由表
	fmt.Println("\n=== 当前路由表 ===")
	displayRoutingTable(r.GetRoutingTable())

	// 测试路由查找
	fmt.Println("\n=== 测试路由查找 ===")
	testIPs := []string{
		"192.168.1.100",
		"192.168.2.50",
		"8.8.8.8",
		"10.0.0.1",
	}

	for _, ipStr := range testIPs {
		ip := net.ParseIP(ipStr)
		if route, err := r.GetRoutingTable().LookupRoute(ip); err != nil {
			fmt.Printf("查找 %s 的路由失败: %v\n", ipStr, err)
		} else {
			fmt.Printf("到达 %s 的路由: %s via %s (metric: %d)\n",
				ipStr, route.Destination.String(), route.Gateway.String(), route.Metric)
		}
	}

	// 测试数据包处理
	fmt.Println("\n=== 测试数据包处理 ===")
	testPacketProcessing(r)

	// 测试接口管理
	fmt.Println("\n=== 测试接口管理 ===")
	testInterfaceManagement(r)

	fmt.Println("\n测试完成")
}

func displayRoutingTable(table routing.TableInterface) {
	routes := table.GetAllRoutes()
	if len(routes) == 0 {
		fmt.Println("路由表为空")
		return
	}

	fmt.Printf("%-18s %-15s %-10s %-6s %-8s\n", "目标网络", "网关", "接口", "度量", "类型")
	fmt.Println(strings.Repeat("-", 70))

	for _, route := range routes {
		var routeType string
		switch route.Type {
		case routing.RouteTypeStatic:
			routeType = "静态"
		case routing.RouteTypeDynamic:
			routeType = "动态"
		case routing.RouteTypeConnected:
			routeType = "连接"
		case routing.RouteTypeDefault:
			routeType = "默认"
		}

		fmt.Printf("%-18s %-15s %-10s %-6d %-8s\n",
			route.Destination.String(),
			route.Gateway.String(),
			route.Interface,
			route.Metric,
			routeType)
	}
}

func testPacketProcessing(r *router.Router) {
	// 创建测试数据包
	testPackets := []struct {
		src, dst string
		data     string
	}{
		{"10.0.0.100", "192.168.1.100", "Hello World"},
		{"10.0.0.200", "192.168.2.50", "Test Packet"},
		{"192.168.1.10", "8.8.8.8", "DNS Query"},
	}

	for _, pkt := range testPackets {
		dstIP := net.ParseIP(pkt.dst)

		fmt.Printf("处理数据包: %s -> %s (%s)\n", pkt.src, pkt.dst, pkt.data)

		// 这里只是模拟处理，实际的数据包处理需要更复杂的逻辑
		if route, err := r.GetRoutingTable().LookupRoute(dstIP); err != nil {
			fmt.Printf("  无法找到路由: %v\n", err)
		} else {
			fmt.Printf("  将通过接口 %s 转发到 %s\n", route.Interface, route.Gateway.String())
		}
	}
}

func testInterfaceManagement(r *router.Router) {
	interfaces := r.GetInterfaceManager().GetAllInterfaces()

	fmt.Printf("发现 %d 个网络接口:\n", len(interfaces))
	for name, iface := range interfaces {
		var status string
		switch iface.Status {
		case 0: // InterfaceStatusDown
			status = "关闭"
		case 1: // InterfaceStatusUp
			status = "启用"
		case 2: // InterfaceStatusTesting
			status = "测试"
		}

		ipAddr := "未配置"
		if iface.IPAddress != nil {
			ipAddr = iface.IPAddress.String()
		}

		fmt.Printf("  %s: %s (状态: %s, MTU: %d)\n", name, ipAddr, status, iface.MTU)
	}
}
