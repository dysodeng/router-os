package demo

import (
	"fmt"
	"log"
	"net"
	"time"

	"router-os/internal/routing"
)

// RunAdvancedRoutingDemo 运行高级路由功能演示
func RunAdvancedRoutingDemo() {
	fmt.Println("=== 高级路由功能演示 ===")

	// 演示负载均衡
	demonstrateLoadBalancing()

	// 演示故障转移
	demonstrateFailover()

	// 演示健康监控
	demonstrateHealthMonitoring()

	fmt.Println("\n=== 演示完成 ===")
}

// demonstrateLoadBalancing 演示负载均衡功能
func demonstrateLoadBalancing() {
	fmt.Println("\n--- 负载均衡演示 ---")

	// 创建目标网络
	_, destNet, _ := net.ParseCIDR("192.168.1.0/24")

	// 创建负载均衡器
	lb := routing.NewLoadBalancer(destNet, routing.RoundRobin)

	// 添加路由
	routes := []struct {
		gateway net.IP
		iface   string
		weight  int
	}{
		{net.ParseIP("10.0.1.1"), "eth0", 3},
		{net.ParseIP("10.0.1.2"), "eth1", 2},
		{net.ParseIP("10.0.1.3"), "eth2", 1},
	}

	for _, r := range routes {
		route := routing.Route{
			Destination: destNet,
			Gateway:     r.gateway,
			Interface:   r.iface,
			Metric:      1,
		}

		err := lb.AddRoute(route, r.weight)
		if err != nil {
			log.Printf("添加路由失败: %v", err)
			continue
		}

		fmt.Printf("添加路由: %s via %s (权重: %d)\n",
			destNet.String(), r.gateway.String(), r.weight)
	}

	// 测试不同的负载均衡算法
	algorithms := []routing.LoadBalancingAlgorithm{
		routing.RoundRobin,
		routing.WeightedRoundRobin,
		routing.LeastConnections,
	}

	for _, alg := range algorithms {
		fmt.Printf("\n使用 %s 算法:\n", getAlgorithmName(alg))
		lb.SetAlgorithm(alg)

		// 模拟多次路由选择
		for i := 0; i < 6; i++ {
			clientIP := net.ParseIP(fmt.Sprintf("192.168.100.%d", i+1))
			selectedRoute, err := lb.SelectRoute(clientIP)
			if err != nil {
				log.Printf("路由选择失败: %v", err)
				continue
			}

			fmt.Printf("  客户端 %s -> 网关 %s\n",
				clientIP.String(), selectedRoute.Gateway.String())
		}
	}

	// 显示统计信息
	stats := lb.GetStats()
	fmt.Printf("\n负载均衡统计:\n")
	fmt.Printf("  总请求数: %d\n", stats.TotalRequests)
	fmt.Printf("  健康路由数: %d\n", lb.GetHealthyRouteCount())
}

// demonstrateFailover 演示故障转移功能
func demonstrateFailover() {
	fmt.Println("\n--- 故障转移演示 ---")

	// 创建目标网络
	_, destNet, _ := net.ParseCIDR("10.0.0.0/16")

	// 创建故障转移管理器
	fm := routing.NewFailoverManager(destNet, routing.ActivePassive)

	// 配置健康检查
	healthConfig := routing.HealthCheckConfig{
		Type:             routing.PingCheck,
		Interval:         5 * time.Second,
		Timeout:          2 * time.Second,
		Retries:          3,
		FailureThreshold: 2,
		SuccessThreshold: 2,
		Target:           "",
		Port:             0,
	}

	// 添加主路由和备份路由
	routes := []struct {
		gateway  net.IP
		iface    string
		priority int
	}{
		{net.ParseIP("172.16.1.1"), "eth0", 1}, // 主路由
		{net.ParseIP("172.16.2.1"), "eth1", 2}, // 备份路由1
		{net.ParseIP("172.16.3.1"), "eth2", 3}, // 备份路由2
	}

	for _, r := range routes {
		route := routing.Route{
			Destination: destNet,
			Gateway:     r.gateway,
			Interface:   r.iface,
			Metric:      1,
		}

		healthConfig.Target = r.gateway.String()
		err := fm.AddRoute(route, r.priority, healthConfig)
		if err != nil {
			log.Printf("添加故障转移路由失败: %v", err)
			continue
		}

		fmt.Printf("添加故障转移路由: %s via %s (优先级: %d)\n",
			destNet.String(), r.gateway.String(), r.priority)
	}

	// 监听故障转移事件
	go func() {
		eventChan := fm.GetEventChannel()
		for event := range eventChan {
			fmt.Printf("故障转移事件: %s - %s\n",
				getEventTypeName(event.Type), event.Message)
		}
	}()

	// 模拟路由选择
	fmt.Println("\n模拟路由选择:")
	for i := 0; i < 3; i++ {
		clientIP := net.ParseIP(fmt.Sprintf("192.168.1.%d", i+1))
		selectedRoute, err := fm.SelectRoute(clientIP)
		if err != nil {
			log.Printf("故障转移路由选择失败: %v", err)
			continue
		}

		fmt.Printf("  客户端 %s -> 网关 %s (优先级: %d)\n",
			clientIP.String(), selectedRoute.Gateway.String(), selectedRoute.Priority)
	}

	// 显示故障转移统计
	stats := fm.GetStats()
	fmt.Printf("\n故障转移统计:\n")
	fmt.Printf("  总故障转移次数: %d\n", stats.TotalFailovers)
	fmt.Printf("  活跃路由数: %d\n", stats.ActiveRouteCount)
	fmt.Printf("  健康路由数: %d\n", stats.HealthyRouteCount)

	// 清理
	fm.Stop()
}

// demonstrateHealthMonitoring 演示健康监控功能
func demonstrateHealthMonitoring() {
	fmt.Println("\n--- 健康监控演示 ---")

	// 创建健康监控配置
	config := routing.DefaultHealthMonitorConfig
	config.Interval = 10 * time.Second
	config.Enabled = true

	// 创建健康监控器
	hm := routing.NewHealthMonitor(config)

	// 添加健康状态变化回调
	hm.AddHealthChangeCallback(func(routeID string, oldHealth, newHealth bool, metrics routing.HealthMetrics) {
		status := "不健康"
		if newHealth {
			status = "健康"
		}
		fmt.Printf("路由 %s 状态变化: %s (延迟: %.2fms, 丢包率: %.2f%%)\n",
			routeID, status, metrics.Latency, metrics.PacketLoss)
	})

	// 添加监控路由
	routes := []struct {
		dest    string
		gateway string
		iface   string
	}{
		{"192.168.1.0/24", "10.0.1.1", "eth0"},
		{"192.168.2.0/24", "10.0.2.1", "eth1"},
		{"0.0.0.0/0", "10.0.3.1", "eth2"},
	}

	for _, r := range routes {
		_, destNet, _ := net.ParseCIDR(r.dest)
		route := &routing.Route{
			Destination: destNet,
			Gateway:     net.ParseIP(r.gateway),
			Interface:   r.iface,
			Metric:      1,
		}

		err := hm.AddRoute(route)
		if err != nil {
			log.Printf("添加监控路由失败: %v", err)
			continue
		}

		fmt.Printf("添加监控路由: %s via %s\n", r.dest, r.gateway)
	}

	// 等待一段时间让监控运行
	fmt.Println("\n等待健康检查运行...")
	time.Sleep(3 * time.Second)

	// 显示健康指标
	fmt.Println("\n当前健康指标:")
	allMetrics := hm.GetAllMetrics()
	for routeID, metrics := range allMetrics {
		status := "不健康"
		if metrics.IsHealthy {
			status = "健康"
		}

		fmt.Printf("  路由 %s: %s\n", routeID, status)
		fmt.Printf("    延迟: %.2fms\n", metrics.Latency)
		fmt.Printf("    丢包率: %.2f%%\n", metrics.PacketLoss)
		fmt.Printf("    带宽利用率: %.2f%%\n", metrics.BandwidthUtilization)
		fmt.Printf("    吞吐量: %.2fMbps\n", metrics.Throughput)
		fmt.Printf("    最后更新: %s\n", metrics.LastUpdate.Format("15:04:05"))
	}

	// 显示监控统计
	stats := hm.GetStats()
	fmt.Printf("\n健康监控统计:\n")
	fmt.Printf("  总路由数: %d\n", stats["total_routes"])
	fmt.Printf("  健康路由数: %d\n", stats["healthy_routes"])
	fmt.Printf("  不健康路由数: %d\n", stats["unhealthy_routes"])
	fmt.Printf("  总检查次数: %d\n", stats["total_checks"])
	fmt.Printf("  失败率: %.2f%%\n", stats["failure_rate"])

	// 清理
	hm.Stop()
}

// 辅助函数
func getAlgorithmName(alg routing.LoadBalancingAlgorithm) string {
	switch alg {
	case routing.RoundRobin:
		return "轮询"
	case routing.WeightedRoundRobin:
		return "加权轮询"
	case routing.LeastConnections:
		return "最少连接"
	default:
		return "未知"
	}
}

func getEventTypeName(eventType routing.FailoverEventType) string {
	switch eventType {
	case routing.RouteHealthy:
		return "路由健康"
	case routing.RouteUnhealthy:
		return "路由不健康"
	case routing.RouteActivated:
		return "路由激活"
	case routing.RouteDeactivated:
		return "路由停用"
	case routing.FailoverTriggered:
		return "故障转移触发"
	case routing.FailoverCompleted:
		return "故障转移完成"
	default:
		return "未知事件"
	}
}
