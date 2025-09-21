package demo

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"router-os/internal/module/routing"
)

func RunPerformanceDemo() {
	fmt.Println("🚀 Router OS 路由表性能优化演示")
	fmt.Println(strings.Repeat("=", 50))

	// 演示不同规模下的性能对比
	routeCounts := []int{100, 500, 1000, 5000}

	for _, count := range routeCounts {
		fmt.Printf("\n📊 测试路由数量: %d\n", count)
		fmt.Println(strings.Repeat("-", 30))

		// 性能对比测试
		performanceComparison(count)

		// 缓存效果演示
		if count >= 1000 {
			fmt.Println("\n💾 缓存效果演示:")
			cacheEffectivenessDemo(count)
		}
	}

	// 并发性能测试
	fmt.Println("\n🔄 并发性能测试:")
	concurrencyDemo()

	// 内存使用对比
	fmt.Println("\n💾 内存使用对比:")
	memoryUsageDemo()

	// 实际应用场景模拟
	fmt.Println("\n🌐 实际应用场景模拟:")
	realWorldScenarioDemo()
}

// performanceComparison 性能对比测试
func performanceComparison(routeCount int) {
	// 创建原始路由表
	originalTable := routing.NewTable()
	setupOriginalRoutes(originalTable, routeCount)

	// 创建优化路由表
	optimizedTable := routing.NewOptimizedTableWithDefaults()
	setupOptimizedRoutes(optimizedTable, routeCount)

	// 生成测试IP
	testIPs := generateRandomIPs(1000)

	// 测试原始实现
	fmt.Print("  原始实现: ")
	originalTime := measureLookupTime(func() {
		for _, ip := range testIPs {
			_, _ = originalTable.LookupRoute(ip)
		}
	})

	// 测试优化实现
	fmt.Print("  优化实现: ")
	optimizedTime := measureLookupTime(func() {
		for _, ip := range testIPs {
			_, _ = optimizedTable.LookupRoute(ip)
		}
	})

	// 计算性能提升
	improvement := float64(originalTime) / float64(optimizedTime)

	fmt.Printf("  📈 性能提升: %.2fx (原始: %v, 优化: %v)\n",
		improvement, originalTime, optimizedTime)

	// 显示优化表的统计信息
	stats := optimizedTable.GetStats()
	fmt.Printf("  📊 查找统计: 总计=%d, 缓存命中=%d, Trie命中=%d, 失败=%d\n",
		stats.Lookups, stats.CacheHits, stats.TrieHits, stats.Misses)
}

// cacheEffectivenessDemo 缓存效果演示
func cacheEffectivenessDemo(routeCount int) {
	table := routing.NewOptimizedTableWithDefaults()
	setupOptimizedRoutes(table, routeCount)

	// 生成热点IP（模拟真实访问模式）
	hotIPs := generateRandomIPs(20)   // 20个热点IP
	coldIPs := generateRandomIPs(980) // 980个普通IP

	fmt.Println("  第一轮查找（冷缓存）:")
	coldCacheTime := measureLookupTime(func() {
		for i := 0; i < 1000; i++ {
			var ip net.IP
			if i%5 < 4 { // 80%访问热点IP
				ip = hotIPs[i%len(hotIPs)]
			} else { // 20%访问普通IP
				ip = coldIPs[i%len(coldIPs)]
			}
			_, _ = table.LookupRoute(ip)
		}
	})

	fmt.Println("  第二轮查找（热缓存）:")
	hotCacheTime := measureLookupTime(func() {
		for i := 0; i < 1000; i++ {
			var ip net.IP
			if i%5 < 4 { // 80%访问热点IP
				ip = hotIPs[i%len(hotIPs)]
			} else { // 20%访问普通IP
				ip = coldIPs[i%len(coldIPs)]
			}
			_, _ = table.LookupRoute(ip)
		}
	})

	cacheImprovement := float64(coldCacheTime) / float64(hotCacheTime)
	fmt.Printf("  🔥 缓存效果: %.2fx 提升 (冷: %v, 热: %v)\n",
		cacheImprovement, coldCacheTime, hotCacheTime)

	// 显示缓存统计
	cacheStats := table.GetCacheStats()
	if cacheStats != nil && cacheStats["enabled"].(bool) {
		hits := cacheStats["hits"].(int64)
		misses := cacheStats["misses"].(int64)
		if hits+misses > 0 {
			hitRate := float64(hits) / float64(hits+misses) * 100
			fmt.Printf("  📊 缓存命中率: %.1f%% (命中=%d, 未命中=%d)\n",
				hitRate, hits, misses)
		}
	}
}

// concurrencyDemo 并发性能演示
func concurrencyDemo() {
	table := routing.NewOptimizedTableWithDefaults()
	setupOptimizedRoutes(table, 2000)

	testIPs := generateRandomIPs(100)
	goroutineCount := 10
	lookupsPerGoroutine := 1000

	fmt.Printf("  启动 %d 个协程，每个执行 %d 次查找\n", goroutineCount, lookupsPerGoroutine)

	start := time.Now()
	done := make(chan bool, goroutineCount)

	for i := 0; i < goroutineCount; i++ {
		go func(id int) {
			for j := 0; j < lookupsPerGoroutine; j++ {
				ip := testIPs[j%len(testIPs)]
				_, _ = table.LookupRoute(ip)
			}
			done <- true
		}(i)
	}

	// 等待所有协程完成
	for i := 0; i < goroutineCount; i++ {
		<-done
	}

	totalTime := time.Since(start)
	totalLookups := goroutineCount * lookupsPerGoroutine
	avgTime := totalTime / time.Duration(totalLookups)

	fmt.Printf("  ⚡ 并发性能: %d 次查找耗时 %v (平均 %v/次)\n",
		totalLookups, totalTime, avgTime)

	stats := table.GetStats()
	fmt.Printf("  📊 并发统计: 总查找=%d, 缓存命中率=%.1f%%\n",
		stats.Lookups, float64(stats.CacheHits)/float64(stats.Lookups)*100)
}

// memoryUsageDemo 内存使用演示
func memoryUsageDemo() {
	routeCounts := []int{1000, 5000, 10000}

	for _, count := range routeCounts {
		fmt.Printf("  路由数量: %d\n", count)

		// 原始实现
		originalTable := routing.NewTable()
		setupOriginalRoutes(originalTable, count)
		fmt.Printf("    原始实现: %d 条路由\n", originalTable.Size())

		// 优化实现
		optimizedTable := routing.NewOptimizedTableWithDefaults()
		setupOptimizedRoutes(optimizedTable, count)
		fmt.Printf("    优化实现: %d 条路由\n", optimizedTable.Size())

		// 显示优化表的详细信息
		report := optimizedTable.GetPerformanceReport()
		if cacheInfo, ok := report["cacheInfo"].(map[string]interface{}); ok {
			fmt.Printf("    缓存大小: %v/%v\n", cacheInfo["size"], cacheInfo["maxSize"])
		}
	}
}

// realWorldScenarioDemo 真实场景模拟
func realWorldScenarioDemo() {
	fmt.Println("  模拟企业网络环境（10000条路由，混合访问模式）")

	table := routing.NewOptimizedTableWithDefaults()

	// 添加不同类型的路由
	addEnterpriseRoutes(table)

	// 模拟真实访问模式
	simulateRealTraffic(table)

	// 显示性能报告
	report := table.GetPerformanceReport()
	fmt.Printf("  📊 性能报告:\n")
	fmt.Printf("    总路由数: %v\n", report["totalRoutes"])
	fmt.Printf("    总查找数: %v\n", report["totalLookups"])
	fmt.Printf("    缓存命中率: %.1f%%\n", report["cacheHitRate"].(float64)*100)
	fmt.Printf("    整体命中率: %.1f%%\n", report["overallHitRate"].(float64)*100)
	fmt.Printf("    平均查找时间: %.2f ms\n", report["avgLookupTimeMs"].(float64))
}

// 辅助函数

func measureLookupTime(fn func()) time.Duration {
	start := time.Now()
	fn()
	return time.Since(start)
}

func setupOriginalRoutes(table *routing.Table, count int) {
	for i := 0; i < count; i++ {
		network := fmt.Sprintf("10.%d.%d.0/24", (i/256)%256, i%256)
		_, destNet, _ := net.ParseCIDR(network)

		route := routing.Route{
			Destination: destNet,
			Gateway:     net.ParseIP(fmt.Sprintf("192.168.%d.1", i%256)),
			Interface:   fmt.Sprintf("eth%d", i%4),
			Metric:      rand.Intn(100) + 1,
			Type:        routing.RouteTypeStatic,
			Age:         time.Now(),
		}

		_ = table.AddRoute(route)
	}
}

func setupOptimizedRoutes(table *routing.OptimizedTable, count int) {
	for i := 0; i < count; i++ {
		network := fmt.Sprintf("10.%d.%d.0/24", (i/256)%256, i%256)
		_, destNet, _ := net.ParseCIDR(network)

		route := routing.Route{
			Destination: destNet,
			Gateway:     net.ParseIP(fmt.Sprintf("192.168.%d.1", i%256)),
			Interface:   fmt.Sprintf("eth%d", i%4),
			Metric:      rand.Intn(100) + 1,
			Type:        routing.RouteTypeStatic,
			Age:         time.Now(),
		}

		_ = table.AddRoute(route)
	}
}

func generateRandomIPs(count int) []net.IP {
	ips := make([]net.IP, count)
	for i := 0; i < count; i++ {
		ips[i] = net.IPv4(
			byte(10),
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
			byte(rand.Intn(254)+1),
		)
	}
	return ips
}

func addEnterpriseRoutes(table *routing.OptimizedTable) {
	// 添加内网路由
	for i := 0; i < 1000; i++ {
		network := fmt.Sprintf("192.168.%d.0/24", i%256)
		_, destNet, _ := net.ParseCIDR(network)

		route := routing.Route{
			Destination: destNet,
			Gateway:     net.ParseIP("192.168.1.1"),
			Interface:   "eth0",
			Metric:      1,
			Type:        routing.RouteTypeStatic,
			Age:         time.Now(),
		}
		_ = table.AddRoute(route)
	}

	// 添加外网路由
	for i := 0; i < 5000; i++ {
		network := fmt.Sprintf("10.%d.%d.0/24", (i/256)%256, i%256)
		_, destNet, _ := net.ParseCIDR(network)

		route := routing.Route{
			Destination: destNet,
			Gateway:     net.ParseIP("10.0.0.1"),
			Interface:   "eth1",
			Metric:      10,
			Type:        routing.RouteTypeDynamic,
			Age:         time.Now(),
			TTL:         30 * time.Minute,
		}
		_ = table.AddRoute(route)
	}

	// 添加默认路由
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
	defaultRoute := routing.Route{
		Destination: defaultNet,
		Gateway:     net.ParseIP("203.0.113.1"),
		Interface:   "eth2",
		Metric:      100,
		Type:        routing.RouteTypeDefault,
		Age:         time.Now(),
	}
	_ = table.AddRoute(defaultRoute)
}

func simulateRealTraffic(table *routing.OptimizedTable) {
	// 生成不同类型的目标IP
	internalIPs := make([]net.IP, 100)
	for i := 0; i < 100; i++ {
		internalIPs[i] = net.IPv4(192, 168, byte(i%256), byte(rand.Intn(254)+1))
	}

	externalIPs := make([]net.IP, 500)
	for i := 0; i < 500; i++ {
		externalIPs[i] = net.IPv4(10, byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(254)+1))
	}

	internetIPs := make([]net.IP, 100)
	for i := 0; i < 100; i++ {
		internetIPs[i] = net.IPv4(byte(rand.Intn(223)+1), byte(rand.Intn(256)),
			byte(rand.Intn(256)), byte(rand.Intn(254)+1))
	}

	// 模拟访问模式：70%内网，25%外网，5%互联网
	for i := 0; i < 10000; i++ {
		var ip net.IP
		r := rand.Intn(100)
		if r < 70 {
			ip = internalIPs[rand.Intn(len(internalIPs))]
		} else if r < 95 {
			ip = externalIPs[rand.Intn(len(externalIPs))]
		} else {
			ip = internetIPs[rand.Intn(len(internetIPs))]
		}

		_, _ = table.LookupRoute(ip)
	}
}
