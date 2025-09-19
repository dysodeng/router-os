package router

import (
	"router-os/internal/routing"
	"time"
)

// RouterConfig 路由器配置结构
type RouterConfig struct {
	// RoutingTableType 路由表类型
	RoutingTableType routing.RouteTableType `json:"routing_table_type"`

	// OptimizedTableConfig 优化路由表的配置（当使用OptimizedTable时）
	OptimizedTableConfig *OptimizedTableConfig `json:"optimized_table_config,omitempty"`

	// EnablePerformanceMonitoring 是否启用性能监控
	EnablePerformanceMonitoring bool `json:"enable_performance_monitoring"`

	// LogLevel 日志级别
	LogLevel string `json:"log_level"`
}

// OptimizedTableConfig 优化路由表配置
type OptimizedTableConfig struct {
	// EnableCache 是否启用缓存
	EnableCache bool `json:"enable_cache"`

	// CacheSize 缓存大小
	CacheSize int `json:"cache_size"`

	// CacheTTL 缓存TTL
	CacheTTL time.Duration `json:"cache_ttl"`

	// EnableStats 是否启用统计
	EnableStats bool `json:"enable_stats"`

	// AutoCleanup 是否自动清理过期路由
	AutoCleanup bool `json:"auto_cleanup"`

	// CleanupInterval 清理间隔
	CleanupInterval time.Duration `json:"cleanup_interval"`
}

// DefaultRouterConfig 返回默认的路由器配置
func DefaultRouterConfig() *RouterConfig {
	return &RouterConfig{
		RoutingTableType:            routing.RouteTableTypeBasic,
		EnablePerformanceMonitoring: false,
		LogLevel:                    "info",
	}
}

// DefaultOptimizedRouterConfig 返回使用优化路由表的默认配置
func DefaultOptimizedRouterConfig() *RouterConfig {
	return &RouterConfig{
		RoutingTableType: routing.RouteTableTypeOptimized,
		OptimizedTableConfig: &OptimizedTableConfig{
			EnableCache:     true,
			CacheSize:       5000,
			CacheTTL:        30 * time.Minute,
			EnableStats:     true,
			AutoCleanup:     true,
			CleanupInterval: 5 * time.Minute,
		},
		EnablePerformanceMonitoring: true,
		LogLevel:                    "info",
	}
}

// HighPerformanceRouterConfig 返回高性能路由器配置
func HighPerformanceRouterConfig() *RouterConfig {
	return &RouterConfig{
		RoutingTableType: routing.RouteTableTypeOptimized,
		OptimizedTableConfig: &OptimizedTableConfig{
			EnableCache:     true,
			CacheSize:       10000,
			CacheTTL:        60 * time.Minute,
			EnableStats:     true,
			AutoCleanup:     true,
			CleanupInterval: 2 * time.Minute,
		},
		EnablePerformanceMonitoring: true,
		LogLevel:                    "debug",
	}
}

// ToRoutingConfig 将路由器配置转换为路由表配置
func (c *RouterConfig) ToRoutingConfig() routing.OptimizedTableConfig {
	if c.OptimizedTableConfig == nil {
		return routing.DefaultOptimizedTableConfig()
	}

	// 由于OptimizedTableConfig的字段是未导出的，我们需要创建一个新的配置
	// 这里我们先返回默认配置，稍后会添加一个构造函数
	return routing.NewOptimizedTableConfig(
		c.OptimizedTableConfig.EnableCache,
		c.OptimizedTableConfig.CacheSize,
		c.OptimizedTableConfig.CacheTTL,
		c.OptimizedTableConfig.EnableStats,
		c.OptimizedTableConfig.AutoCleanup,
		c.OptimizedTableConfig.CleanupInterval,
	)
}
