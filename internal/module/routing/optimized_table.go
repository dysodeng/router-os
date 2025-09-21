package routing

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// OptimizedTable 优化后的路由表
// 集成了Trie树、缓存和多种性能优化技术
type OptimizedTable struct {
	// trie Trie树，用于快速前缀匹配
	// 这是主要的路由存储结构，提供O(log n)的查找性能
	trie *RouteTrie

	// cache 路由缓存，用于加速频繁查询
	// 对于热点IP地址，可以提供O(1)的查找性能
	cache *RouteCache

	// routes 路由列表的副本，用于兼容性和某些操作
	// 保持与原始Table接口的兼容性
	routes []Route

	// mu 主锁，保护整个表的一致性
	mu sync.RWMutex

	// stats 性能统计信息
	stats OptimizedTableStats

	// config 配置参数
	config OptimizedTableConfig
}

// OptimizedTableStats 优化路由表的统计信息
type OptimizedTableStats struct {
	// Lookups 总查找次数
	Lookups int64

	// CacheHits 缓存命中次数
	CacheHits int64

	// TrieHits Trie树命中次数
	TrieHits int64

	// Misses 查找失败次数
	Misses int64

	// AvgLookupTime 平均查找时间（纳秒）
	AvgLookupTime int64

	// LastOptimization 最后一次优化时间
	LastOptimization time.Time
}

// OptimizedTableConfig 优化路由表的配置
type OptimizedTableConfig struct {
	// enableCache 是否启用缓存
	enableCache bool

	// cacheSize 缓存大小
	cacheSize int

	// cacheTTL 缓存TTL
	cacheTTL time.Duration

	// enableStats 是否启用统计
	enableStats bool

	// autoCleanup 是否自动清理过期路由
	autoCleanup bool

	// cleanupInterval 清理间隔
	cleanupInterval time.Duration
}

// DefaultOptimizedTableConfig 默认配置
func DefaultOptimizedTableConfig() OptimizedTableConfig {
	return OptimizedTableConfig{
		enableCache:     true,
		cacheSize:       5000,
		cacheTTL:        5 * time.Minute,
		enableStats:     true,
		autoCleanup:     true,
		cleanupInterval: 1 * time.Minute,
	}
}

// NewOptimizedTableConfig 创建自定义的优化路由表配置
func NewOptimizedTableConfig(enableCache bool, cacheSize int, cacheTTL time.Duration, enableStats bool, autoCleanup bool, cleanupInterval time.Duration) OptimizedTableConfig {
	return OptimizedTableConfig{
		enableCache:     enableCache,
		cacheSize:       cacheSize,
		cacheTTL:        cacheTTL,
		enableStats:     enableStats,
		autoCleanup:     autoCleanup,
		cleanupInterval: cleanupInterval,
	}
}

// NewOptimizedTable 创建优化的路由表
func NewOptimizedTable(config OptimizedTableConfig) *OptimizedTable {
	table := &OptimizedTable{
		trie:   NewRouteTrie(),
		routes: make([]Route, 0),
		config: config,
		stats:  OptimizedTableStats{},
	}

	// 如果启用缓存，创建缓存实例
	if config.enableCache {
		table.cache = NewRouteCache(config.cacheSize, config.cacheTTL)
	}

	// 如果启用自动清理，启动清理协程
	if config.autoCleanup {
		go table.startCleanupRoutine()
	}

	return table
}

// NewOptimizedTableWithDefaults 使用默认配置创建优化路由表
func NewOptimizedTableWithDefaults() *OptimizedTable {
	return NewOptimizedTable(DefaultOptimizedTableConfig())
}

// AddRoute 添加路由
// 优化版本会同时更新Trie树、缓存和路由列表
func (ot *OptimizedTable) AddRoute(route Route) error {
	ot.mu.Lock()
	defer ot.mu.Unlock()

	// 验证路由有效性
	if route.Destination == nil {
		return fmt.Errorf("路由目标网络不能为空")
	}

	// 设置路由创建时间
	if route.Age.IsZero() {
		route.Age = time.Now()
	}

	// 添加到Trie树
	ot.trie.Insert(&route)

	// 添加到路由列表
	ot.routes = append(ot.routes, route)

	// 如果启用缓存，清理相关缓存
	if ot.config.enableCache && ot.cache != nil {
		// 清理可能受影响的缓存条目
		ot.invalidateRelatedCache(&route)
	}

	return nil
}

// RemoveRoute 删除路由
func (ot *OptimizedTable) RemoveRoute(destination *net.IPNet, gateway net.IP, iface string) error {
	ot.mu.Lock()
	defer ot.mu.Unlock()

	// 从Trie树中删除
	if !ot.trie.Delete(destination) {
		return fmt.Errorf("路由不存在")
	}

	// 从路由列表中删除
	for i, route := range ot.routes {
		if route.Destination.String() == destination.String() &&
			route.Gateway.Equal(gateway) &&
			route.Interface == iface {
			// 删除元素
			ot.routes = append(ot.routes[:i], ot.routes[i+1:]...)
			break
		}
	}

	// 如果启用缓存，清理相关缓存
	if ot.config.enableCache && ot.cache != nil {
		ot.cache.InvalidateAll() // 简单起见，清理所有缓存
	}

	return nil
}

// LookupRoute 查找路由（优化版本）
// 这是性能优化的核心方法，集成了缓存和Trie树查找
func (ot *OptimizedTable) LookupRoute(destination net.IP) (*Route, error) {
	startTime := time.Now()
	defer func() {
		if ot.config.enableStats {
			ot.updateLookupStats(time.Since(startTime))
		}
	}()

	ot.mu.RLock()
	defer ot.mu.RUnlock()

	if ot.config.enableStats {
		ot.stats.Lookups++
	}

	// 第一步：尝试从缓存获取
	if ot.config.enableCache && ot.cache != nil {
		if route, found := ot.cache.Get(destination); found {
			if ot.config.enableStats {
				ot.stats.CacheHits++
			}

			// 检查动态路由的TTL
			if route != nil && route.Type == RouteTypeDynamic && route.TTL > 0 {
				if time.Since(route.Age) > route.TTL {
					// 路由已过期，从缓存中删除并继续查找
					ot.cache.Invalidate(destination)
				} else {
					return route, nil
				}
			} else if route != nil {
				return route, nil
			} else {
				// 负缓存命中（之前查找失败的结果）
				if ot.config.enableStats {
					ot.stats.Misses++
				}
				return nil, fmt.Errorf("未找到到达 %s 的路由", destination.String())
			}
		}
	}

	// 第二步：从Trie树查找
	route := ot.trie.Search(destination)

	if route != nil {
		// 检查动态路由的TTL
		if route.Type == RouteTypeDynamic && route.TTL > 0 {
			if time.Since(route.Age) > route.TTL {
				// 路由已过期，需要从Trie树中删除
				ot.trie.Delete(route.Destination)
				route = nil
			}
		}
	}

	// 第三步：更新缓存和统计
	if ot.config.enableCache && ot.cache != nil {
		ot.cache.Put(destination, route)
	}

	if route != nil {
		if ot.config.enableStats {
			ot.stats.TrieHits++
		}
		return route, nil
	}

	// 查找失败
	if ot.config.enableStats {
		ot.stats.Misses++
	}
	return nil, fmt.Errorf("未找到到达 %s 的路由", destination.String())
}

// GetAllRoutes 获取所有路由
func (ot *OptimizedTable) GetAllRoutes() []Route {
	ot.mu.RLock()
	defer ot.mu.RUnlock()

	// 返回路由列表的副本
	result := make([]Route, len(ot.routes))
	copy(result, ot.routes)
	return result
}

// Size 返回路由表大小
func (ot *OptimizedTable) Size() int {
	ot.mu.RLock()
	defer ot.mu.RUnlock()
	return len(ot.routes)
}

// Clear 清空路由表
func (ot *OptimizedTable) Clear() {
	ot.mu.Lock()
	defer ot.mu.Unlock()

	ot.trie.Clear()
	ot.routes = ot.routes[:0]

	if ot.config.enableCache && ot.cache != nil {
		ot.cache.Clear()
	}

	// 重置统计信息
	if ot.config.enableStats {
		ot.stats = OptimizedTableStats{}
	}
}

// GetStats 获取性能统计信息
func (ot *OptimizedTable) GetStats() OptimizedTableStats {
	ot.mu.RLock()
	defer ot.mu.RUnlock()
	return ot.stats
}

// GetCacheStats 获取缓存统计信息 (实现CacheManager接口)
func (ot *OptimizedTable) GetCacheStats() map[string]interface{} {
	ot.mu.RLock()
	defer ot.mu.RUnlock()

	stats := make(map[string]interface{})
	
	if ot.config.enableCache && ot.cache != nil {
		cacheInfo := ot.cache.GetCacheInfo()
		stats["enabled"] = true
		stats["size"] = cacheInfo["size"]
		stats["capacity"] = cacheInfo["capacity"]
		stats["hitRate"] = cacheInfo["hitRate"]
		stats["hits"] = cacheInfo["hits"]
		stats["misses"] = cacheInfo["misses"]
		stats["evictions"] = cacheInfo["evictions"]
	} else {
		stats["enabled"] = false
	}
	
	return stats
}

// GetPerformanceReport 获取性能报告
func (ot *OptimizedTable) GetPerformanceReport() map[string]interface{} {
	ot.mu.RLock()
	defer ot.mu.RUnlock()

	report := make(map[string]interface{})

	// 基本统计
	report["totalRoutes"] = len(ot.routes)
	report["totalLookups"] = ot.stats.Lookups
	report["cacheHits"] = ot.stats.CacheHits
	report["trieHits"] = ot.stats.TrieHits
	report["misses"] = ot.stats.Misses

	// 性能指标
	if ot.stats.Lookups > 0 {
		report["cacheHitRate"] = float64(ot.stats.CacheHits) / float64(ot.stats.Lookups)
		report["overallHitRate"] = float64(ot.stats.CacheHits+ot.stats.TrieHits) / float64(ot.stats.Lookups)
		report["avgLookupTimeNs"] = ot.stats.AvgLookupTime
		report["avgLookupTimeMs"] = float64(ot.stats.AvgLookupTime) / 1000000.0
	}

	// 缓存信息
	if ot.config.enableCache && ot.cache != nil {
		report["cacheInfo"] = ot.cache.GetCacheInfo()
	}

	// 配置信息
	report["config"] = ot.config

	return report
}

// updateLookupStats 更新查找统计信息
func (ot *OptimizedTable) updateLookupStats(duration time.Duration) {
	// 使用移动平均计算平均查找时间
	newTime := duration.Nanoseconds()
	if ot.stats.AvgLookupTime == 0 {
		ot.stats.AvgLookupTime = newTime
	} else {
		// 使用指数移动平均，权重为0.1
		ot.stats.AvgLookupTime = int64(0.9*float64(ot.stats.AvgLookupTime) + 0.1*float64(newTime))
	}
}

// invalidateRelatedCache 使相关缓存失效
func (ot *OptimizedTable) invalidateRelatedCache(route *Route) {
	// 简单实现：清理所有缓存
	// 更复杂的实现可以只清理受影响的IP范围
	ot.cache.InvalidateAll()
}

// startCleanupRoutine 启动清理协程
func (ot *OptimizedTable) startCleanupRoutine() {
	ticker := time.NewTicker(ot.config.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		ot.cleanupExpiredRoutes()

		if ot.config.enableCache && ot.cache != nil {
			ot.cache.CleanExpired()
		}
	}
}

// cleanupExpiredRoutes 清理过期路由
func (ot *OptimizedTable) cleanupExpiredRoutes() {
	ot.mu.Lock()
	defer ot.mu.Unlock()

	now := time.Now()
	validRoutes := make([]Route, 0, len(ot.routes))

	for _, route := range ot.routes {
		// 检查动态路由是否过期
		if route.Type == RouteTypeDynamic && route.TTL > 0 {
			if now.Sub(route.Age) > route.TTL {
				// 路由过期，从Trie树中删除
				ot.trie.Delete(route.Destination)
				continue
			}
		}

		// 路由仍然有效
		validRoutes = append(validRoutes, route)
	}

	ot.routes = validRoutes
}

// ClearCache 清空路由缓存 (实现CacheManager接口)
func (ot *OptimizedTable) ClearCache() {
	ot.mu.Lock()
	defer ot.mu.Unlock()

	if ot.config.enableCache && ot.cache != nil {
		ot.cache.Clear()
	}
}
