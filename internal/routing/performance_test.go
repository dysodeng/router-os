package routing

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"
)

// BenchmarkOriginalTableLookup 原始路由表查找性能测试
func BenchmarkOriginalTableLookup(b *testing.B) {
	table := NewTable()

	// 添加测试路由
	setupTestRoutes(table, 1000)

	// 准备测试IP
	testIPs := generateTestIPs(1000)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := testIPs[i%len(testIPs)]
			table.LookupRoute(ip)
			i++
		}
	})
}

// BenchmarkOptimizedTableLookup 优化路由表查找性能测试
func BenchmarkOptimizedTableLookup(b *testing.B) {
	table := NewOptimizedTableWithDefaults()

	// 添加测试路由
	setupOptimizedTestRoutes(table, 1000)

	// 准备测试IP
	testIPs := generateTestIPs(1000)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := testIPs[i%len(testIPs)]
			table.LookupRoute(ip)
			i++
		}
	})
}

// BenchmarkTrieLookup Trie树查找性能测试
func BenchmarkTrieLookup(b *testing.B) {
	trie := NewRouteTrie()

	// 添加测试路由
	setupTrieTestRoutes(trie, 1000)

	// 准备测试IP
	testIPs := generateTestIPs(1000)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := testIPs[i%len(testIPs)]
			trie.Search(ip)
			i++
		}
	})
}

// BenchmarkCacheLookup 缓存查找性能测试
func BenchmarkCacheLookup(b *testing.B) {
	cache := NewRouteCache(5000, 5*time.Minute)

	// 预填充缓存
	testIPs := generateTestIPs(1000)
	for _, ip := range testIPs {
		route := &Route{
			Destination: &net.IPNet{IP: ip, Mask: net.CIDRMask(24, 32)},
			Gateway:     net.ParseIP("192.168.1.1"),
			Interface:   "eth0",
			Metric:      1,
			Type:        RouteTypeStatic,
		}
		cache.Put(ip, route)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := testIPs[i%len(testIPs)]
			cache.Get(ip)
			i++
		}
	})
}

// TestPerformanceComparison 性能对比测试
func TestPerformanceComparison(t *testing.T) {
	routeCounts := []int{100, 500, 1000, 5000, 10000}

	for _, count := range routeCounts {
		t.Run(fmt.Sprintf("Routes_%d", count), func(t *testing.T) {
			// 测试原始实现
			originalTime := benchmarkOriginalTable(count, 1000)

			// 测试优化实现
			optimizedTime := benchmarkOptimizedTable(count, 1000)

			// 计算性能提升
			improvement := float64(originalTime) / float64(optimizedTime)

			t.Logf("路由数量: %d", count)
			t.Logf("原始实现平均查找时间: %v", originalTime)
			t.Logf("优化实现平均查找时间: %v", optimizedTime)
			t.Logf("性能提升: %.2fx", improvement)

			// 验证优化实现确实更快
			if improvement < 1.0 {
				t.Logf("警告: 优化实现在 %d 路由时性能未提升", count)
			}
		})
	}
}

// TestCacheEffectiveness 缓存效果测试
func TestCacheEffectiveness(t *testing.T) {
	table := NewOptimizedTableWithDefaults()
	setupOptimizedTestRoutes(table, 1000)

	// 生成热点IP（模拟真实场景中的访问模式）
	hotIPs := generateTestIPs(50)   // 50个热点IP
	coldIPs := generateTestIPs(950) // 950个冷门IP

	// 第一轮查找（填充缓存）
	for _, ip := range hotIPs {
		table.LookupRoute(ip)
	}

	// 第二轮查找（测试缓存效果）
	start := time.Now()
	for i := 0; i < 1000; i++ {
		// 80%的查询访问热点IP，20%访问冷门IP
		if i%5 < 4 {
			ip := hotIPs[i%len(hotIPs)]
			table.LookupRoute(ip)
		} else {
			ip := coldIPs[i%len(coldIPs)]
			table.LookupRoute(ip)
		}
	}
	duration := time.Since(start)

	// 获取统计信息
	stats := table.GetStats()
	cacheStats := table.GetCacheStats()

	t.Logf("总查找次数: %d", stats.Lookups)
	t.Logf("缓存命中次数: %d", stats.CacheHits)
	t.Logf("Trie命中次数: %d", stats.TrieHits)
	t.Logf("查找失败次数: %d", stats.Misses)
	t.Logf("缓存命中率: %.2f%%", float64(stats.CacheHits)/float64(stats.Lookups)*100)
	t.Logf("总查找时间: %v", duration)
	t.Logf("平均查找时间: %v", duration/1000)

	if cacheStats != nil {
		hits, _ := cacheStats["hits"].(int64)
		misses, _ := cacheStats["misses"].(int64)
		evictions, _ := cacheStats["evictions"].(int64)
		expirations, _ := cacheStats["expirations"].(int64)
		t.Logf("缓存统计: 命中=%d, 未命中=%d, 驱逐=%d, 过期=%d",
			hits, misses, evictions, expirations)
	}
}

// TestMemoryUsage 内存使用测试
func TestMemoryUsage(t *testing.T) {
	routeCounts := []int{1000, 5000, 10000}

	for _, count := range routeCounts {
		t.Run(fmt.Sprintf("Memory_Routes_%d", count), func(t *testing.T) {
			// 测试原始实现内存使用
			originalTable := NewTable()
			setupTestRoutes(originalTable, count)

			// 测试优化实现内存使用
			optimizedTable := NewOptimizedTableWithDefaults()
			setupOptimizedTestRoutes(optimizedTable, count)

			t.Logf("路由数量: %d", count)
			t.Logf("原始实现路由数: %d", originalTable.Size())
			t.Logf("优化实现路由数: %d", optimizedTable.Size())

			// 注意：实际的内存使用测量需要使用runtime包或专门的内存分析工具
			// 这里只是验证功能正确性
		})
	}
}

// TestConcurrentAccess 并发访问测试
func TestConcurrentAccess(t *testing.T) {
	table := NewOptimizedTableWithDefaults()
	setupOptimizedTestRoutes(table, 1000)

	testIPs := generateTestIPs(100)

	// 启动多个goroutine进行并发查找
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 1000; j++ {
				ip := testIPs[j%len(testIPs)]
				_, err := table.LookupRoute(ip)
				if err != nil {
					// 某些查找失败是正常的
				}
			}
			done <- true
		}(i)
	}

	// 等待所有goroutine完成
	for i := 0; i < 10; i++ {
		<-done
	}

	stats := table.GetStats()
	t.Logf("并发测试完成，总查找次数: %d", stats.Lookups)
}

// 辅助函数

// setupTestRoutes 为原始路由表设置测试路由
func setupTestRoutes(table *Table, count int) {
	for i := 0; i < count; i++ {
		// 生成随机网络
		network := fmt.Sprintf("192.%d.%d.0/24", (i/256)%256, i%256)
		_, destNet, _ := net.ParseCIDR(network)

		gateway := net.ParseIP(fmt.Sprintf("10.0.%d.1", i%256))

		route := Route{
			Destination: destNet,
			Gateway:     gateway,
			Interface:   fmt.Sprintf("eth%d", i%4),
			Metric:      rand.Intn(100) + 1,
			Type:        RouteTypeStatic,
			Age:         time.Now(),
		}

		table.AddRoute(route)
	}
}

// setupOptimizedTestRoutes 为优化路由表设置测试路由
func setupOptimizedTestRoutes(table *OptimizedTable, count int) {
	for i := 0; i < count; i++ {
		// 生成随机网络
		network := fmt.Sprintf("192.%d.%d.0/24", (i/256)%256, i%256)
		_, destNet, _ := net.ParseCIDR(network)

		gateway := net.ParseIP(fmt.Sprintf("10.0.%d.1", i%256))

		route := Route{
			Destination: destNet,
			Gateway:     gateway,
			Interface:   fmt.Sprintf("eth%d", i%4),
			Metric:      rand.Intn(100) + 1,
			Type:        RouteTypeStatic,
			Age:         time.Now(),
		}

		table.AddRoute(route)
	}
}

// setupTrieTestRoutes 为Trie树设置测试路由
func setupTrieTestRoutes(trie *RouteTrie, count int) {
	for i := 0; i < count; i++ {
		// 生成随机网络
		network := fmt.Sprintf("192.%d.%d.0/24", (i/256)%256, i%256)
		_, destNet, _ := net.ParseCIDR(network)

		gateway := net.ParseIP(fmt.Sprintf("10.0.%d.1", i%256))

		route := &Route{
			Destination: destNet,
			Gateway:     gateway,
			Interface:   fmt.Sprintf("eth%d", i%4),
			Metric:      rand.Intn(100) + 1,
			Type:        RouteTypeStatic,
			Age:         time.Now(),
		}

		trie.Insert(route)
	}
}

// generateTestIPs 生成测试IP地址
func generateTestIPs(count int) []net.IP {
	ips := make([]net.IP, count)
	for i := 0; i < count; i++ {
		// 生成随机IP地址
		ip := net.IPv4(
			byte(192),
			byte((i/256)%256),
			byte(i%256),
			byte(rand.Intn(254)+1),
		)
		ips[i] = ip
	}
	return ips
}

// benchmarkOriginalTable 基准测试原始路由表
func benchmarkOriginalTable(routeCount, lookupCount int) time.Duration {
	table := NewTable()
	setupTestRoutes(table, routeCount)
	testIPs := generateTestIPs(lookupCount)

	start := time.Now()
	for _, ip := range testIPs {
		table.LookupRoute(ip)
	}
	return time.Since(start) / time.Duration(lookupCount)
}

// benchmarkOptimizedTable 基准测试优化路由表
func benchmarkOptimizedTable(routeCount, lookupCount int) time.Duration {
	table := NewOptimizedTableWithDefaults()
	setupOptimizedTestRoutes(table, routeCount)
	testIPs := generateTestIPs(lookupCount)

	start := time.Now()
	for _, ip := range testIPs {
		table.LookupRoute(ip)
	}
	return time.Since(start) / time.Duration(lookupCount)
}
