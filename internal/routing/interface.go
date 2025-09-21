package routing

import "net"

// TableInterface 通用路由表接口
// 定义了所有路由表实现必须支持的基本操作
// 这样可以让Router在运行时选择使用传统Table还是OptimizedTable
type TableInterface interface {
	// AddRoute 添加路由到路由表
	// 参数：
	//   - route Route: 要添加的路由条目
	// 返回值：
	//   - error: 添加失败时的错误信息
	AddRoute(route Route) error

	// RemoveRoute 从路由表中删除指定路由
	// 参数：
	//   - destination *net.IPNet: 目标网络
	//   - gateway net.IP: 网关地址
	//   - iface string: 接口名称
	// 返回值：
	//   - error: 删除失败时的错误信息
	RemoveRoute(destination *net.IPNet, gateway net.IP, iface string) error

	// LookupRoute 查找到达指定目标的最佳路由
	// 这是路由表最核心的功能，实现最长前缀匹配
	// 参数：
	//   - destination net.IP: 目标IP地址
	// 返回值：
	//   - *Route: 找到的最佳路由，如果没找到则为nil
	//   - error: 查找失败时的错误信息
	LookupRoute(destination net.IP) (*Route, error)

	// GetAllRoutes 获取路由表中的所有路由
	// 返回值：
	//   - []Route: 所有路由的副本切片
	GetAllRoutes() []Route

	// Size 返回路由表中路由的数量
	// 返回值：
	//   - int: 路由数量
	Size() int

	// Clear 清空路由表中的所有路由
	Clear()
}

// PerformanceReporter 性能报告接口
// 可选接口，用于获取路由表的性能统计信息
// 只有支持性能统计的路由表实现才需要实现这个接口
type PerformanceReporter interface {
	// GetPerformanceReport 获取性能报告
	// 返回值：
	//   - map[string]interface{}: 包含各种性能指标的报告
	GetPerformanceReport() map[string]interface{}
}

// CacheManager 缓存管理接口
// 可选接口，用于管理路由缓存
// 只有支持缓存的路由表实现才需要实现这个接口
type CacheManager interface {
	// ClearCache 清空路由缓存
	ClearCache()

	// GetCacheStats 获取缓存统计信息
	// 返回值：
	//   - map[string]interface{}: 缓存统计信息
	GetCacheStats() map[string]interface{}
}

// RouteTableType 路由表类型枚举
type RouteTableType int

const (
	// RouteTableTypeBasic 基础路由表类型
	// 使用简单的线性查找，适合小规模路由表
	RouteTableTypeBasic RouteTableType = iota

	// RouteTableTypeOptimized 优化路由表类型
	// 使用Trie树和缓存，适合大规模路由表和高频查找
	RouteTableTypeOptimized
)

// String 返回路由表类型的字符串表示
func (t RouteTableType) String() string {
	switch t {
	case RouteTableTypeBasic:
		return "Basic"
	case RouteTableTypeOptimized:
		return "Optimized"
	default:
		return "Unknown"
	}
}
