package demo

import (
	"fmt"
	"net"
	"time"

	"router-os/internal/module/routing"
)

// RoutingAlgorithmsDemo 路由算法演示
// 这个演示程序展示了路由器操作系统中的核心路由算法和概念
// 通过具体的例子帮助理解路由表操作、最长前缀匹配等概念
type RoutingAlgorithmsDemo struct {
	table *routing.Table
}

// NewRoutingAlgorithmsDemo 创建路由算法演示实例
func NewRoutingAlgorithmsDemo() *RoutingAlgorithmsDemo {
	return &RoutingAlgorithmsDemo{
		table: routing.NewTable(),
	}
}

// RunDemo 运行完整的路由算法演示
func (demo *RoutingAlgorithmsDemo) RunDemo() {
	fmt.Println("=== 路由算法和概念演示 ===")
	fmt.Println("这个演示将帮助您理解路由器的核心工作原理")
	fmt.Println()

	// 1. 基础路由表操作演示
	demo.demonstrateBasicRouting()

	// 2. 最长前缀匹配演示
	demo.demonstrateLongestPrefixMatch()

	// 3. 路由优先级和度量值演示
	demo.demonstrateRoutePriority()

	// 4. 动态路由更新演示
	demo.demonstrateDynamicRouting()

	// 5. 路由收敛演示
	demo.demonstrateRouteConvergence()
}

// demonstrateBasicRouting 演示基础路由表操作
func (demo *RoutingAlgorithmsDemo) demonstrateBasicRouting() {
	fmt.Println("=== 1. 基础路由表操作演示 ===")
	fmt.Println("路由表是路由器的核心数据结构，存储了网络可达性信息")
	fmt.Println()

	// 创建一些示例路由
	routes := []routing.Route{
		{
			Destination: parseNetwork("192.168.1.0/24"),
			Gateway:     net.ParseIP("10.0.0.1"),
			Interface:   "eth0",
			Metric:      1,
			Type:        routing.RouteTypeStatic,
			Age:         time.Now(),
		},
		{
			Destination: parseNetwork("192.168.2.0/24"),
			Gateway:     net.ParseIP("10.0.0.2"),
			Interface:   "eth1",
			Metric:      2,
			Type:        routing.RouteTypeDynamic,
			Age:         time.Now(),
		},
		{
			Destination: parseNetwork("10.0.0.0/8"),
			Gateway:     net.ParseIP("172.16.0.1"),
			Interface:   "eth2",
			Metric:      5,
			Type:        routing.RouteTypeDynamic,
			Age:         time.Now(),
		},
	}

	fmt.Println("添加路由到路由表：")
	for i, route := range routes {
		err := demo.table.AddRoute(route)
		if err != nil {
			fmt.Printf("添加路由 %d 失败: %v\n", i+1, err)
		} else {
			fmt.Printf("✓ 添加路由 %d: %s -> %s (via %s, metric: %d)\n",
				i+1, route.Destination.String(), route.Interface,
				route.Gateway.String(), route.Metric)
		}
	}
	fmt.Println()

	// 显示路由表内容
	fmt.Println("当前路由表内容：")
	demo.printRoutingTable()
	fmt.Println()
}

// demonstrateLongestPrefixMatch 演示最长前缀匹配算法
func (demo *RoutingAlgorithmsDemo) demonstrateLongestPrefixMatch() {
	fmt.Println("=== 2. 最长前缀匹配算法演示 ===")
	fmt.Println("最长前缀匹配是路由查找的核心算法")
	fmt.Println("当有多个路由匹配同一个目标地址时，选择前缀最长（最具体）的路由")
	fmt.Println()

	// 添加重叠的路由条目来演示最长前缀匹配
	overlappingRoutes := []routing.Route{
		{
			Destination: parseNetwork("192.168.0.0/16"), // 较大的网络
			Gateway:     net.ParseIP("10.0.0.10"),
			Interface:   "eth0",
			Metric:      3,
			Type:        routing.RouteTypeStatic,
			Age:         time.Now(),
		},
		{
			Destination: parseNetwork("192.168.1.0/24"), // 更具体的网络
			Gateway:     net.ParseIP("10.0.0.11"),
			Interface:   "eth1",
			Metric:      1,
			Type:        routing.RouteTypeDynamic,
			Age:         time.Now(),
		},
		{
			Destination: parseNetwork("192.168.1.128/25"), // 最具体的网络
			Gateway:     net.ParseIP("10.0.0.12"),
			Interface:   "eth2",
			Metric:      2,
			Type:        routing.RouteTypeDynamic,
			Age:         time.Now(),
		},
	}

	fmt.Println("添加重叠的路由条目：")
	for _, route := range overlappingRoutes {
		_ = demo.table.AddRoute(route)
		fmt.Printf("✓ %s -> %s\n", route.Destination.String(), route.Gateway.String())
	}
	fmt.Println()

	// 测试不同目标地址的路由查找
	testIPs := []string{
		"192.168.1.100", // 匹配 /24 路由
		"192.168.1.200", // 匹配 /25 路由
		"192.168.2.100", // 匹配 /16 路由
		"192.168.1.50",  // 匹配 /24 路由
	}

	fmt.Println("最长前缀匹配测试：")
	for _, ipStr := range testIPs {
		ip := net.ParseIP(ipStr)
		route, err := demo.table.LookupRoute(ip)
		if err != nil {
			fmt.Printf("❌ %s: 未找到路由\n", ipStr)
		} else {
			fmt.Printf("✓ %s -> 匹配路由 %s (via %s)\n",
				ipStr, route.Destination.String(), route.Gateway.String())
		}
	}
	fmt.Println()

	fmt.Println("解释：")
	fmt.Println("- 192.168.1.100 匹配 192.168.1.0/24 (24位前缀)")
	fmt.Println("- 192.168.1.200 匹配 192.168.1.128/25 (25位前缀，更具体)")
	fmt.Println("- 192.168.2.100 只能匹配 192.168.0.0/16 (16位前缀)")
	fmt.Println("- 算法总是选择前缀最长的匹配路由")
	fmt.Println()
}

// demonstrateRoutePriority 演示路由优先级和度量值
func (demo *RoutingAlgorithmsDemo) demonstrateRoutePriority() {
	fmt.Println("=== 3. 路由优先级和度量值演示 ===")
	fmt.Println("当有多个相同前缀长度的路由时，使用度量值选择最优路由")
	fmt.Println("度量值越小，路由越优")
	fmt.Println()

	// 添加到同一目标的多个路由（不同度量值）
	sameDestRoutes := []routing.Route{
		{
			Destination: parseNetwork("10.1.1.0/24"),
			Gateway:     net.ParseIP("192.168.1.1"),
			Interface:   "eth0",
			Metric:      5, // 较高的度量值
			Type:        routing.RouteTypeDynamic,
			Age:         time.Now(),
		},
		{
			Destination: parseNetwork("10.1.1.0/24"),
			Gateway:     net.ParseIP("192.168.1.2"),
			Interface:   "eth1",
			Metric:      2, // 较低的度量值（更优）
			Type:        routing.RouteTypeDynamic,
			Age:         time.Now(),
		},
		{
			Destination: parseNetwork("10.1.1.0/24"),
			Gateway:     net.ParseIP("192.168.1.3"),
			Interface:   "eth2",
			Metric:      8, // 最高的度量值
			Type:        routing.RouteTypeStatic,
			Age:         time.Now(),
		},
	}

	fmt.Println("添加到同一目标的多个路由：")
	for i, route := range sameDestRoutes {
		_ = demo.table.AddRoute(route)
		fmt.Printf("✓ 路由 %d: %s via %s (metric: %d, type: %v)\n",
			i+1, route.Destination.String(), route.Gateway.String(),
			route.Metric, route.Type)
	}
	fmt.Println()

	// 查找最优路由
	testIP := net.ParseIP("10.1.1.100")
	route, err := demo.table.LookupRoute(testIP)
	if err != nil {
		fmt.Printf("❌ 查找 %s 失败: %v\n", testIP.String(), err)
	} else {
		fmt.Printf("✓ 最优路由选择: %s -> %s (metric: %d)\n",
			testIP.String(), route.Gateway.String(), route.Metric)
	}
	fmt.Println()

	fmt.Println("解释：")
	fmt.Println("- 路由表会自动选择度量值最小的路由")
	fmt.Println("- 度量值代表到达目标的\"成本\"（跳数、带宽、延迟等）")
	fmt.Println("- 不同协议可能使用不同的度量值计算方法")
	fmt.Println()
}

// demonstrateDynamicRouting 演示动态路由更新
func (demo *RoutingAlgorithmsDemo) demonstrateDynamicRouting() {
	fmt.Println("=== 4. 动态路由更新演示 ===")
	fmt.Println("动态路由协议会根据网络变化自动更新路由表")
	fmt.Println()

	// 模拟网络拓扑变化
	fmt.Println("初始网络状态：")
	initialRoute := routing.Route{
		Destination: parseNetwork("172.16.0.0/16"),
		Gateway:     net.ParseIP("10.0.1.1"),
		Interface:   "eth0",
		Metric:      3,
		Type:        routing.RouteTypeDynamic,
		Age:         time.Now(),
	}
	_ = demo.table.AddRoute(initialRoute)
	fmt.Printf("✓ 添加初始路由: %s via %s (metric: %d)\n",
		initialRoute.Destination.String(), initialRoute.Gateway.String(), initialRoute.Metric)
	fmt.Println()

	// 模拟收到更好的路由更新
	fmt.Println("收到路由更新（发现更好的路径）：")
	betterRoute := routing.Route{
		Destination: parseNetwork("172.16.0.0/16"),
		Gateway:     net.ParseIP("10.0.1.2"),
		Interface:   "eth1",
		Metric:      1, // 更好的度量值
		Type:        routing.RouteTypeDynamic,
		Age:         time.Now(),
	}
	_ = demo.table.AddRoute(betterRoute)
	fmt.Printf("✓ 更新路由: %s via %s (metric: %d)\n",
		betterRoute.Destination.String(), betterRoute.Gateway.String(), betterRoute.Metric)
	fmt.Println()

	// 验证路由更新
	testIP := net.ParseIP("172.16.1.1")
	route, _ := demo.table.LookupRoute(testIP)
	fmt.Printf("✓ 当前最优路由: %s -> %s (metric: %d)\n",
		testIP.String(), route.Gateway.String(), route.Metric)
	fmt.Println()

	// 模拟路由失效
	fmt.Println("模拟链路故障（路由失效）：")
	fmt.Println("- 在真实环境中，路由协议会检测到邻居超时")
	fmt.Println("- 失效的路由会被标记为不可达（metric = 16）")
	fmt.Println("- 路由器会寻找替代路径")
	fmt.Println()
}

// demonstrateRouteConvergence 演示路由收敛过程
func (demo *RoutingAlgorithmsDemo) demonstrateRouteConvergence() {
	fmt.Println("=== 5. 路由收敛演示 ===")
	fmt.Println("路由收敛是指网络拓扑变化后，所有路由器达到一致路由视图的过程")
	fmt.Println()

	fmt.Println("模拟三个路由器的网络：")
	fmt.Println("Router A (10.0.1.1) <-> Router B (10.0.2.1) <-> Router C (10.0.3.1)")
	fmt.Println()

	// 模拟Router A的视角
	fmt.Println("Router A 的初始路由表：")
	routerARoutes := []routing.Route{
		{
			Destination: parseNetwork("10.0.2.0/24"),
			Gateway:     net.ParseIP("10.0.2.1"), // 直连到Router B
			Interface:   "eth0",
			Metric:      1,
			Type:        routing.RouteTypeDynamic,
			Age:         time.Now(),
		},
		{
			Destination: parseNetwork("10.0.3.0/24"),
			Gateway:     net.ParseIP("10.0.2.1"), // 通过Router B到达Router C
			Interface:   "eth0",
			Metric:      2, // 2跳到达
			Type:        routing.RouteTypeDynamic,
			Age:         time.Now(),
		},
	}

	for _, route := range routerARoutes {
		_ = demo.table.AddRoute(route)
		fmt.Printf("✓ %s via %s (metric: %d)\n",
			route.Destination.String(), route.Gateway.String(), route.Metric)
	}
	fmt.Println()

	fmt.Println("网络收敛过程说明：")
	fmt.Println("1. 初始状态：所有路由器交换路由信息")
	fmt.Println("2. 稳定状态：每个路由器都知道到达所有网络的最优路径")
	fmt.Println("3. 拓扑变化：某个链路故障或新路由器加入")
	fmt.Println("4. 重新收敛：路由器重新计算和交换路由信息")
	fmt.Println("5. 新稳定状态：达到新的一致路由视图")
	fmt.Println()

	fmt.Println("RIP协议收敛特点：")
	fmt.Println("- 收敛时间：通常需要几分钟")
	fmt.Println("- 收敛机制：定期更新 + 触发更新")
	fmt.Println("- 防环机制：水平分割、毒性逆转")
	fmt.Println("- 度量值限制：最大15跳，16表示无穷大")
	fmt.Println()
}

// printRoutingTable 打印路由表内容
func (demo *RoutingAlgorithmsDemo) printRoutingTable() {
	fmt.Println("目标网络          下一跳        接口    度量值  协议")
	fmt.Println("--------------------------------------------------------")

	// 注意：这里简化了路由表的显示
	// 在实际实现中，需要访问路由表的内部结构
	fmt.Println("(路由表内容显示需要路由表提供遍历接口)")
}

// parseNetwork 解析网络地址
func parseNetwork(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("解析网络地址失败: %v", err))
	}
	return network
}

// RunAlgorithmsDemo 运行路由算法演示
// 这个函数可以被其他程序调用来展示路由算法
func RunAlgorithmsDemo() {
	demo := NewRoutingAlgorithmsDemo()
	demo.RunDemo()

	fmt.Println("=== 演示结束 ===")
	fmt.Println("通过这个演示，您应该了解了：")
	fmt.Println("1. 路由表的基本操作")
	fmt.Println("2. 最长前缀匹配算法")
	fmt.Println("3. 路由优先级和度量值")
	fmt.Println("4. 动态路由更新机制")
	fmt.Println("5. 路由收敛过程")
	fmt.Println()
	fmt.Println("建议接下来：")
	fmt.Println("- 阅读 docs/ROUTING_BASICS.md 了解更多理论知识")
	fmt.Println("- 查看 internal/routing/table.go 了解实现细节")
	fmt.Println("- 运行 examples/basic_demo.go 体验完整功能")
}
