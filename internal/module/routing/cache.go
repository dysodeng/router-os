package routing

import (
	"net"
	"sync"
	"time"
)

// CacheEntry 缓存条目
// 存储路由查找的结果，包括路由信息和缓存元数据
type CacheEntry struct {
	// route 缓存的路由信息
	// 如果为nil，表示这个IP没有对应的路由（负缓存）
	route *Route

	// timestamp 缓存创建时间
	// 用于实现缓存过期机制
	timestamp time.Time

	// hitCount 缓存命中次数
	// 用于实现LRU（最近最少使用）替换策略
	hitCount int64

	// lastAccess 最后访问时间
	// 配合hitCount实现更精确的LRU策略
	lastAccess time.Time
}

// RouteCache 路由缓存
// 实现了一个高性能的路由查找缓存，支持TTL和LRU策略
type RouteCache struct {
	// cache 缓存存储，使用IP地址字符串作为键
	// 选择字符串而不是net.IP是因为map需要可比较的键类型
	cache map[string]*CacheEntry

	// mu 读写锁，保护缓存的并发访问
	mu sync.RWMutex

	// maxSize 缓存最大容量
	// 当缓存超过这个大小时，会触发LRU清理
	maxSize int

	// ttl 缓存生存时间
	// 超过这个时间的缓存条目会被认为过期
	ttl time.Duration

	// stats 缓存统计信息
	stats CacheStats
}

// CacheStats 缓存统计信息
// 用于监控缓存性能和调优
type CacheStats struct {
	// Hits 缓存命中次数
	Hits int64

	// Misses 缓存未命中次数
	Misses int64

	// Evictions 缓存驱逐次数（因为容量限制被删除的条目数）
	Evictions int64

	// Expirations 缓存过期次数（因为TTL过期被删除的条目数）
	Expirations int64
}

// NewRouteCache 创建新的路由缓存
// maxSize: 最大缓存条目数，建议设置为1000-10000
// ttl: 缓存生存时间，建议设置为30秒-5分钟
func NewRouteCache(maxSize int, ttl time.Duration) *RouteCache {
	return &RouteCache{
		cache:   make(map[string]*CacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
		stats:   CacheStats{},
	}
}

// Get 从缓存中获取路由
// 返回值：路由指针（可能为nil），是否在缓存中找到
func (rc *RouteCache) Get(ip net.IP) (*Route, bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	key := ip.String()
	if entry, exists := rc.cache[key]; exists {
		// 检查是否过期
		if time.Since(entry.timestamp) > rc.ttl {
			delete(rc.cache, key)
			rc.stats.Expirations++
			rc.stats.Misses++
			return nil, false
		}

		// 更新访问时间和命中次数
		entry.lastAccess = time.Now()
		entry.hitCount++
		rc.stats.Hits++
		return entry.route, true
	}

	rc.stats.Misses++
	return nil, false
}

// Put 将路由放入缓存
func (rc *RouteCache) Put(ip net.IP, route *Route) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// 如果缓存已满，执行LRU清理
	if len(rc.cache) >= rc.maxSize {
		rc.evictLRU()
	}

	key := ip.String()
	rc.cache[key] = &CacheEntry{
		route:      route,
		timestamp:  time.Now(),
		hitCount:   0,
		lastAccess: time.Now(),
	}
}

// evictLRU 执行LRU（最近最少使用）驱逐策略
// 删除最少使用的缓存条目，为新条目腾出空间
func (rc *RouteCache) evictLRU() {
	if len(rc.cache) == 0 {
		return
	}

	var oldestKey string
	var oldestTime = time.Now()

	for key, entry := range rc.cache {
		if entry.lastAccess.Before(oldestTime) {
			oldestTime = entry.lastAccess
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(rc.cache, oldestKey)
		rc.stats.Evictions++
	}
}

// Clear 清空缓存
func (rc *RouteCache) Clear() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.cache = make(map[string]*CacheEntry)
	rc.stats = CacheStats{}
}

// Size 返回当前缓存大小
func (rc *RouteCache) Size() int {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return len(rc.cache)
}

// GetStats 获取缓存统计信息
func (rc *RouteCache) GetStats() CacheStats {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.stats
}

// GetHitRate 获取缓存命中率
// 返回值范围：0.0-1.0，1.0表示100%命中率
func (rc *RouteCache) GetHitRate() float64 {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	total := rc.stats.Hits + rc.stats.Misses
	if total == 0 {
		return 0.0
	}

	return float64(rc.stats.Hits) / float64(total)
}

// CleanExpired 清理过期的缓存条目
// 这个方法应该定期调用，建议每分钟执行一次
func (rc *RouteCache) CleanExpired() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	now := time.Now()
	expiredKeys := make([]string, 0)

	// 找到所有过期的条目
	for key, entry := range rc.cache {
		if now.Sub(entry.timestamp) > rc.ttl {
			expiredKeys = append(expiredKeys, key)
		}
	}

	// 删除过期条目
	for _, key := range expiredKeys {
		delete(rc.cache, key)
		rc.stats.Expirations++
	}

	return len(expiredKeys)
}

// Invalidate 使特定IP的缓存失效
// 当路由表发生变化时，需要使相关的缓存失效
func (rc *RouteCache) Invalidate(ip net.IP) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	key := ip.String()
	delete(rc.cache, key)
}

// InvalidateAll 使所有缓存失效
// 当路由表发生重大变化时使用
func (rc *RouteCache) InvalidateAll() {
	rc.Clear()
}

// GetCacheInfo 获取缓存详细信息（用于调试和监控）
func (rc *RouteCache) GetCacheInfo() map[string]interface{} {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	info := make(map[string]interface{})
	info["size"] = len(rc.cache)
	info["maxSize"] = rc.maxSize
	info["ttl"] = rc.ttl.String()
	info["hitRate"] = rc.GetHitRate()
	info["stats"] = rc.stats

	// 计算平均命中次数
	if len(rc.cache) > 0 {
		totalHits := int64(0)
		for _, entry := range rc.cache {
			totalHits += entry.hitCount
		}
		info["avgHitCount"] = float64(totalHits) / float64(len(rc.cache))
	} else {
		info["avgHitCount"] = 0.0
	}

	return info
}
