package demo

import (
	"fmt"
	"net"
	"strings"
	"time"

	"router-os/internal/protocols"
	"router-os/internal/router"
	"router-os/internal/routing"
)

func RunOptimizedRouterDemo() {
	fmt.Println("🚀 Router OS 优化路由器演示")
	fmt.Println(strings.Repeat("=", 50))

	// 演示不同配置的优化路由器
	demonstrateOptimizedConfigurations()

	// 演示性能对比
	demonstratePerformanceComparison()

	// 演示缓存效果
	demonstrateCacheEffectiveness()

	// 演示监控和统计
	demonstrateMonitoringAndStats()

	fmt.Println("\n✅ 优化路由器演示完成")
}

// demonstrateOptimizedConfigurations 演示不同配置的优化路由器
func demonstrateOptimizedConfigurations() {
	fmt.Println("\n📋 演示不同配置的优化路由器")
	fmt.Println(strings.Repeat("-", 40))

	// 1. 默认配置
	fmt.Println("\n1️⃣ 默认配置路由器:")
	defaultRouter, err := router.NewRouter()
	if err != nil {
		fmt.Printf("创建默认路由器失败: %v\n", err)
		return
	}
	defer defaultRouter.Stop()

	if err := defaultRouter.Start(); err != nil {
		fmt.Printf("启动默认路由器失败: %v\n", err)
		return
	}

	fmt.Printf("   ✓ 路由表类型: %T\n", defaultRouter.GetRoutingTable())

	// 2. 优化配置
	fmt.Println("\n2️⃣ 优化配置路由器:")
	optimizedConfig := router.RouterConfig{
		RoutingTableType: routing.RouteTableTypeOptimized,
		OptimizedTableConfig: &router.OptimizedTableConfig{
			EnableCache:     true,
			CacheSize:       10000,
			CacheTTL:        10 * time.Minute,
			EnableStats:     true,
			AutoCleanup:     true,
			CleanupInterval: 30 * time.Second,
		},
	}

	optimizedRouter, err := router.NewRouterWithConfig(&optimizedConfig)
	if err != nil {
		fmt.Printf("创建优化路由器失败: %v\n", err)
		return
	}
	defer optimizedRouter.Stop()

	if err := optimizedRouter.Start(); err != nil {
		fmt.Printf("启动优化路由器失败: %v\n", err)
		return
	}

	fmt.Printf("   ✓ 路由表类型: %T\n", optimizedRouter.GetRoutingTable())
	fmt.Printf("   ✓ 缓存大小: %d\n", optimizedConfig.OptimizedTableConfig.CacheSize)
	fmt.Printf("   ✓ 缓存TTL: %v\n", optimizedConfig.OptimizedTableConfig.CacheTTL)

	// 3. 高性能配置
	fmt.Println("\n3️⃣ 高性能配置路由器:")
	highPerfConfig := router.RouterConfig{
		RoutingTableType: routing.RouteTableTypeOptimized,
		OptimizedTableConfig: &router.OptimizedTableConfig{
			EnableCache:     true,
			CacheSize:       50000,
			CacheTTL:        30 * time.Minute,
			EnableStats:     true,
			AutoCleanup:     true,
			CleanupInterval: 10 * time.Second,
		},
	}

	highPerfRouter, err := router.NewRouterWithConfig(&highPerfConfig)
	if err != nil {
		fmt.Printf("创建高性能路由器失败: %v\n", err)
		return
	}
	defer highPerfRouter.Stop()

	if err := highPerfRouter.Start(); err != nil {
		fmt.Printf("启动高性能路由器失败: %v\n", err)
		return
	}

	fmt.Printf("   ✓ 路由表类型: %T\n", highPerfRouter.GetRoutingTable())
	fmt.Printf("   ✓ 缓存大小: %d\n", highPerfConfig.OptimizedTableConfig.CacheSize)
	fmt.Printf("   ✓ 缓存TTL: %v\n", highPerfConfig.OptimizedTableConfig.CacheTTL)
}

// demonstratePerformanceComparison 演示性能对比
func demonstratePerformanceComparison() {
	fmt.Println("\n⚡ 性能对比演示")
	fmt.Println(strings.Repeat("-", 40))

	// 创建基础路由器
	basicConfig := router.RouterConfig{
		RoutingTableType: routing.RouteTableTypeBasic,
	}
	basicRouter, err := router.NewRouterWithConfig(&basicConfig)
	if err != nil {
		fmt.Printf("创建基础路由器失败: %v\n", err)
		return
	}
	defer basicRouter.Stop()

	// 创建优化路由器
	optimizedConfig := router.RouterConfig{
		RoutingTableType: routing.RouteTableTypeOptimized,
		OptimizedTableConfig: &router.OptimizedTableConfig{
			EnableCache: true,
			CacheSize:   5000,
			EnableStats: true,
		},
	}
	optimizedRouter, err := router.NewRouterWithConfig(&optimizedConfig)
	if err != nil {
		fmt.Printf("创建优化路由器失败: %v\n", err)
		return
	}
	defer optimizedRouter.Stop()

	// 启动路由器
	basicRouter.Start()
	optimizedRouter.Start()

	// 添加测试路由
	addTestRoutes(basicRouter, 1000)
	addTestRoutes(optimizedRouter, 1000)

	// 性能测试
	testIPs := generateTestIPs(1000)

	// 测试基础路由器
	basicTime := measureLookupPerformance(basicRouter, testIPs)
	fmt.Printf("   📊 基础路由器: %v (平均每次查找)\n", basicTime)

	// 测试优化路由器
	optimizedTime := measureLookupPerformance(optimizedRouter, testIPs)
	fmt.Printf("   📊 优化路由器: %v (平均每次查找)\n", optimizedTime)

	// 计算性能提升
	if optimizedTime > 0 {
		improvement := float64(basicTime) / float64(optimizedTime)
		fmt.Printf("   🚀 性能提升: %.2fx\n", improvement)
	}
}

// demonstrateCacheEffectiveness 演示缓存效果
func demonstrateCacheEffectiveness() {
	fmt.Println("\n💾 缓存效果演示")
	fmt.Println(strings.Repeat("-", 40))

	// 创建优化路由器
	config := router.RouterConfig{
		RoutingTableType: routing.RouteTableTypeOptimized,
		OptimizedTableConfig: &router.OptimizedTableConfig{
			EnableCache: true,
			CacheSize:   1000,
			EnableStats: true,
		},
	}

	r, err := router.NewRouterWithConfig(&config)
	if err != nil {
		fmt.Printf("创建路由器失败: %v\n", err)
		return
	}
	defer r.Stop()

	if err := r.Start(); err != nil {
		fmt.Printf("启动路由器失败: %v\n", err)
		return
	}

	// 添加路由
	addTestRoutes(r, 500)

	// 获取优化路由表
	optimizedTable, ok := r.GetRoutingTable().(*routing.OptimizedTable)
	if !ok {
		fmt.Println("   ❌ 无法获取优化路由表")
		return
	}

	// 生成热点IP和普通IP
	hotIPs := generateTestIPs(50)   // 50个热点IP
	coldIPs := generateTestIPs(450) // 450个普通IP

	fmt.Println("   第一轮查找（冷缓存）:")
	coldTime := measureLookupTime(func() {
		for i := 0; i < 500; i++ {
			var ip net.IP
			if i%10 < 8 { // 80%访问热点IP
				ip = hotIPs[i%len(hotIPs)]
			} else {
				ip = coldIPs[i%len(coldIPs)]
			}
			optimizedTable.LookupRoute(ip)
		}
	})

	fmt.Println("   第二轮查找（热缓存）:")
	hotTime := measureLookupTime(func() {
		for i := 0; i < 500; i++ {
			var ip net.IP
			if i%10 < 8 { // 80%访问热点IP
				ip = hotIPs[i%len(hotIPs)]
			} else {
				ip = coldIPs[i%len(coldIPs)]
			}
			optimizedTable.LookupRoute(ip)
		}
	})

	// 显示结果
	improvement := float64(coldTime) / float64(hotTime)
	fmt.Printf("   🔥 缓存效果: %.2fx 提升 (冷: %v, 热: %v)\n", improvement, coldTime, hotTime)

	// 显示缓存统计
	cacheStats := optimizedTable.GetCacheStats()
	if cacheStats != nil && cacheStats["enabled"].(bool) {
		hits := cacheStats["hits"].(int64)
		misses := cacheStats["misses"].(int64)
		if hits+misses > 0 {
			hitRate := float64(hits) / float64(hits+misses) * 100
			fmt.Printf("   📊 缓存命中率: %.1f%% (命中=%d, 未命中=%d)\n", hitRate, hits, misses)
		}
	}
}

// demonstrateMonitoringAndStats 演示监控和统计
func demonstrateMonitoringAndStats() {
	fmt.Println("\n📈 监控和统计演示")
	fmt.Println(strings.Repeat("-", 40))

	// 创建优化路由器
	config := router.RouterConfig{
		RoutingTableType: routing.RouteTableTypeOptimized,
		OptimizedTableConfig: &router.OptimizedTableConfig{
			EnableCache: true,
			CacheSize:   2000,
			EnableStats: true,
		},
	}

	r, err := router.NewRouterWithConfig(&config)
	if err != nil {
		fmt.Printf("创建路由器失败: %v\n", err)
		return
	}
	defer r.Stop()

	if err := r.Start(); err != nil {
		fmt.Printf("启动路由器失败: %v\n", err)
		return
	}

	// 添加路由
	addTestRoutes(r, 1000)

	// 获取优化路由表
	optimizedTable, ok := r.GetRoutingTable().(*routing.OptimizedTable)
	if !ok {
		fmt.Println("   ❌ 无法获取优化路由表")
		return
	}

	// 执行一些查找操作
	testIPs := generateTestIPs(500)
	for _, ip := range testIPs {
		optimizedTable.LookupRoute(ip)
	}

	// 显示统计信息
	stats := optimizedTable.GetStats()
	fmt.Printf("   📊 总查找次数: %d\n", stats.Lookups)
	fmt.Printf("   📊 缓存命中次数: %d\n", stats.CacheHits)
	fmt.Printf("   📊 Trie命中次数: %d\n", stats.TrieHits)
	fmt.Printf("   📊 查找失败次数: %d\n", stats.Misses)
	fmt.Printf("   📊 平均查找时间: %.2f μs\n", float64(stats.AvgLookupTime)/1000.0)

	// 显示性能报告
	report := optimizedTable.GetPerformanceReport()
	if totalLookups, ok := report["totalLookups"].(int64); ok && totalLookups > 0 {
		if cacheHitRate, ok := report["cacheHitRate"].(float64); ok {
			fmt.Printf("   📊 缓存命中率: %.1f%%\n", cacheHitRate*100)
		}
		if overallHitRate, ok := report["overallHitRate"].(float64); ok {
			fmt.Printf("   📊 总体命中率: %.1f%%\n", overallHitRate*100)
		}
	}

	// 显示缓存信息
	cacheStats := optimizedTable.GetCacheStats()
	if cacheStats != nil && cacheStats["enabled"].(bool) {
		fmt.Printf("   💾 缓存状态: 启用\n")
		fmt.Printf("   💾 缓存大小: %v/%v\n", cacheStats["size"], cacheStats["capacity"])
		if hitRate, ok := cacheStats["hitRate"].(float64); ok {
			fmt.Printf("   💾 缓存命中率: %.1f%%\n", hitRate*100)
		}
	}
}

// 辅助函数

func addTestRoutes(r *router.Router, count int) {
	staticManager := protocols.NewStaticRouteManager(r.GetRoutingTable())

	for i := 0; i < count; i++ {
		dest := fmt.Sprintf("10.%d.%d.0/24", (i/256)%256, i%256)
		gateway := fmt.Sprintf("192.168.%d.1", i%256)
		iface := fmt.Sprintf("eth%d", i%4)
		metric := (i % 100) + 1

		staticManager.AddStaticRoute(dest, gateway, iface, metric)
	}
}

func generateTestIPs(count int) []net.IP {
	ips := make([]net.IP, count)
	for i := 0; i < count; i++ {
		ip := net.IPv4(
			byte(10),
			byte((i/256)%256),
			byte(i%256),
			byte((i*7)%256),
		)
		ips[i] = ip
	}
	return ips
}

func measureLookupPerformance(r *router.Router, testIPs []net.IP) time.Duration {
	start := time.Now()
	for _, ip := range testIPs {
		r.GetRoutingTable().LookupRoute(ip)
	}
	return time.Since(start)
}
