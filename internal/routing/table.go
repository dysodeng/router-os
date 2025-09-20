package routing

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// RouteType 路由类型枚举
// 在网络中，路由可以通过不同的方式学习到，每种方式对应不同的路由类型
type RouteType int

const (
	// RouteTypeStatic 静态路由
	// 特点：由管理员手动配置，不会自动更新
	// 优点：可控性强，不消耗带宽，配置简单
	// 缺点：网络拓扑变化时需要手动更新
	// 适用场景：小型网络、特殊路由需求、备份路由
	RouteTypeStatic RouteType = iota

	// RouteTypeDynamic 动态路由
	// 特点：通过路由协议（如RIP、OSPF、BGP）自动学习
	// 优点：自动适应网络变化，减少管理工作量
	// 缺点：消耗带宽和CPU资源，配置相对复杂
	// 适用场景：大型网络、复杂拓扑、需要自动故障切换的网络
	RouteTypeDynamic

	// RouteTypeConnected 直连路由
	// 特点：路由器直接连接的网络，自动生成
	// 优点：最高优先级，无需配置
	// 缺点：只能到达直连网络
	// 适用场景：所有网络设备都会自动生成直连路由
	RouteTypeConnected

	// RouteTypeDefault 默认路由
	// 特点：当没有更具体的路由时使用的路由（0.0.0.0/0）
	// 优点：简化路由表，提供兜底路径
	// 缺点：可能导致次优路径选择
	// 适用场景：边缘网络、访问互联网的出口路由
	RouteTypeDefault
)

// String 返回路由类型的字符串表示
func (rt RouteType) String() string {
	switch rt {
	case RouteTypeStatic:
		return "静态"
	case RouteTypeDynamic:
		return "动态"
	case RouteTypeConnected:
		return "直连"
	case RouteTypeDefault:
		return "默认"
	default:
		return "未知"
	}
}

// MarshalJSON 实现JSON序列化接口
func (rt RouteType) MarshalJSON() ([]byte, error) {
	return []byte(`"` + rt.String() + `"`), nil
}

// Route 路由条目结构体
// 这是路由表中的基本单元，包含了路由决策所需的所有信息
// 类比：就像地图上的一条路线指示，告诉你如何从当前位置到达目的地
type Route struct {
	// Destination 目标网络（CIDR格式）
	// 例如：192.168.1.0/24 表示192.168.1.0-192.168.1.255这个网段
	// 这是路由匹配的关键字段，决定了这条路由适用于哪些目标地址
	Destination *net.IPNet `json:"destination"`

	// Gateway 下一跳网关地址
	// 这是数据包应该发送到的下一个路由器的IP地址
	// 如果为nil，表示目标网络是直连的，不需要经过网关
	// 类比：就像导航中的"下一个路口向左转"中的那个路口
	Gateway net.IP `json:"gateway"`

	// Interface 出接口名称
	// 指定数据包应该从哪个网络接口发出
	// 例如："eth0", "wlan0", "lo"等
	// 这确保了数据包从正确的物理或虚拟接口发送
	Interface string `json:"interface"`

	// Metric 路由度量值（成本）
	// 用于在多条到达同一目标的路由中选择最优路径
	// 数值越小表示路径越优
	// 不同协议的度量值计算方式不同：
	// - RIP: 跳数（经过的路由器数量）
	// - OSPF: 基于带宽的成本计算
	// - 静态路由: 管理员手动设置
	Metric int `json:"metric"`

	// Type 路由类型
	// 标识这条路由是如何学习到的
	// 不同类型的路由有不同的优先级和处理方式
	Type RouteType `json:"type"`

	// Age 路由创建或最后更新时间
	// 用于跟踪路由的新鲜度，特别是对于动态路由
	// 可以用来实现路由老化机制，清理过期的路由信息
	Age time.Time `json:"age"`

	// TTL 生存时间（Time To Live）
	// 主要用于动态路由，指定路由的有效期
	// 超过TTL时间的路由会被认为是过期的，需要重新学习
	// 静态路由通常不设置TTL或设置为0表示永不过期
	TTL time.Duration `json:"ttl"`
}

// MarshalJSON 自定义JSON序列化方法
// 确保destination和gateway字段以字符串格式返回，而不是复杂的对象结构
func (r Route) MarshalJSON() ([]byte, error) {
	// 创建一个临时结构体用于序列化
	type RouteJSON struct {
		Destination string        `json:"destination"`
		Gateway     string        `json:"gateway"`
		Interface   string        `json:"interface"`
		Metric      int           `json:"metric"`
		Type        RouteType     `json:"type"`
		Age         time.Time     `json:"age"`
		TTL         time.Duration `json:"ttl"`
	}

	// 转换destination为字符串格式
	var destinationStr string
	if r.Destination != nil {
		destinationStr = r.Destination.String()
	}

	// 转换gateway为字符串格式
	var gatewayStr string
	if r.Gateway != nil {
		gatewayStr = r.Gateway.String()
	}

	// 创建临时对象并序列化
	routeJSON := RouteJSON{
		Destination: destinationStr,
		Gateway:     gatewayStr,
		Interface:   r.Interface,
		Metric:      r.Metric,
		Type:        r.Type,
		Age:         r.Age,
		TTL:         r.TTL,
	}

	return json.Marshal(routeJSON)
}

// Table 路由表结构体
// 这是整个路由系统的核心数据结构，管理所有的路由条目
// 类比：就像一本地图册，包含了到达各个目的地的所有路线信息
type Table struct {
	// routes 路由条目切片
	// 存储所有的路由信息，按照最长前缀匹配原则排序
	// 排序规则：前缀长度越长优先级越高，相同长度时度量值越小优先级越高
	routes []Route

	// mu 读写互斥锁
	// 保证路由表的并发安全性，允许多个goroutine同时读取，但写入时互斥
	// 读操作使用RLock()，写操作使用Lock()
	// 这是网络设备中非常重要的，因为路由查找频繁且需要高性能
	mu sync.RWMutex
}

// NewTable 创建新的路由表实例
// 返回一个初始化的空路由表，准备接收路由条目
//
// 返回值：
//   - *Table: 新创建的路由表指针
//
// 使用示例：
//
//	table := NewTable()
//	// 现在可以向table中添加路由了
func NewTable() *Table {
	return &Table{
		// 初始化一个空的路由切片，容量为0但可以动态扩展
		routes: make([]Route, 0),
	}
}

// AddRoute 向路由表中添加或更新路由条目
// 这是路由表管理的核心方法之一，实现了路由的添加和更新逻辑
//
// 工作流程：
// 1. 获取写锁，确保并发安全
// 2. 检查是否存在相同的路由（相同目标网络、网关和接口）
// 3. 如果存在，更新现有路由；如果不存在，添加新路由
// 4. 重新排序路由表，确保最长前缀匹配的正确性
//
// 参数：
//   - route Route: 要添加的路由条目
//
// 返回值：
//   - error: 操作成功返回nil，失败返回错误信息
//
// 路由匹配规则：
//   - 目标网络相同（例如都是192.168.1.0/24）
//   - 网关地址相同（例如都是192.168.1.1）
//   - 出接口相同（例如都是eth0）
//
// 使用示例：
//
//	_, network, _ := net.ParseCIDR("192.168.1.0/24")
//	gateway := net.ParseIP("192.168.1.1")
//	route := Route{
//	    Destination: network,
//	    Gateway:     gateway,
//	    Interface:   "eth0",
//	    Metric:      1,
//	    Type:        RouteTypeStatic,
//	}
//	err := table.AddRoute(route)
func (t *Table) AddRoute(route Route) error {
	// 获取写锁，防止并发修改路由表
	// 使用defer确保函数退出时释放锁，即使发生panic也能正确释放
	t.mu.Lock()
	defer t.mu.Unlock()

	// 遍历现有路由，检查是否已存在相同的路由
	// 这里的"相同"是指目标网络、网关和接口都相同
	for i, existingRoute := range t.routes {
		// 比较目标网络：将IPNet转换为字符串进行比较
		// 比较网关地址：使用IP.Equal()方法进行精确比较
		// 比较接口名称：直接字符串比较
		if existingRoute.Destination.String() == route.Destination.String() &&
			existingRoute.Gateway.Equal(route.Gateway) &&
			existingRoute.Interface == route.Interface {

			// 找到相同路由，执行更新操作
			// 这种情况通常发生在：
			// 1. 路由协议更新了路由信息（如度量值变化）
			// 2. 管理员重新配置了相同的静态路由
			// 3. 接口状态变化导致路由刷新
			t.routes[i] = route
			t.routes[i].Age = time.Now() // 更新路由的时间戳
			return nil
		}
	}

	// 没有找到相同路由，添加新的路由条目
	route.Age = time.Now() // 设置路由创建时间
	t.routes = append(t.routes, route)

	// 重新排序路由表
	// 这是非常重要的步骤，确保路由查找时能够正确应用最长前缀匹配算法
	// 排序规则：
	// 1. 前缀长度长的路由排在前面（更具体的路由优先）
	// 2. 前缀长度相同时，度量值小的路由排在前面（更优的路径优先）
	t.sortRoutes()

	return nil
}

// RemoveRoute 删除路由
func (t *Table) RemoveRoute(destination *net.IPNet, gateway net.IP, iface string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for i, route := range t.routes {
		if route.Destination.String() == destination.String() &&
			route.Gateway.Equal(gateway) &&
			route.Interface == iface {
			// 删除路由
			t.routes = append(t.routes[:i], t.routes[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("路由不存在")
}

// LookupRoute 查找到达指定目标IP的最佳路由
// 这是路由表最核心的功能，实现了最长前缀匹配算法
//
// 最长前缀匹配算法原理：
// 1. 遍历路由表中的所有路由条目
// 2. 检查目标IP是否在路由的目标网络范围内
// 3. 在所有匹配的路由中，选择前缀长度最长的（最具体的）
// 4. 如果前缀长度相同，选择度量值最小的
//
// 为什么要最长前缀匹配？
// - 更具体的路由应该优先于更通用的路由
// - 例如：目标IP 192.168.1.100
//   - 路由1: 192.168.0.0/16 (匹配16位)
//   - 路由2: 192.168.1.0/24 (匹配24位) ← 应该选择这个
//   - 路由3: 0.0.0.0/0 (默认路由，匹配0位)
//
// 参数：
//   - destination net.IP: 目标IP地址
//
// 返回值：
//   - *Route: 找到的最佳路由指针，如果没找到则为nil
//   - error: 查找失败时的错误信息
//
// 路由有效性检查：
//   - 静态路由和直连路由：永远有效
//   - 动态路由：检查TTL，超时的路由会被跳过
//
// 使用示例：
//
//	targetIP := net.ParseIP("192.168.1.100")
//	route, err := table.LookupRoute(targetIP)
//	if err != nil {
//	    // 没有找到路由，可能需要使用默认路由或丢弃数据包
//	    log.Printf("无法路由到 %s: %v", targetIP, err)
//	} else {
//	    // 找到路由，可以进行数据包转发
//	    log.Printf("路由到 %s 通过网关 %s，接口 %s",
//	               targetIP, route.Gateway, route.Interface)
//	}
func (t *Table) LookupRoute(destination net.IP) (*Route, error) {
	// 获取读锁，允许多个goroutine同时进行路由查找
	// 这对性能很重要，因为路由查找是网络设备最频繁的操作
	t.mu.RLock()
	defer t.mu.RUnlock()

	// 遍历路由表进行最长前缀匹配
	// 由于路由表已经按照前缀长度排序，第一个匹配的就是最佳路由
	for _, route := range t.routes {
		// 检查目标IP是否在当前路由的目标网络范围内
		// Contains方法会检查IP是否在IPNet定义的网络范围内
		// 例如：192.168.1.0/24.Contains(192.168.1.100) 返回true
		if route.Destination.Contains(destination) {

			// 对动态路由进行TTL检查
			// 动态路由有生存时间限制，过期的路由不应该被使用
			if route.Type == RouteTypeDynamic && route.TTL > 0 {
				// 计算路由的存活时间
				routeAge := time.Since(route.Age)
				if routeAge > route.TTL {
					// 路由已过期，跳过这条路由继续查找
					// 注意：这里不删除过期路由，删除操作由ClearExpiredRoutes()负责
					continue
				}
			}

			// 找到有效的匹配路由，返回路由的副本
			// 返回副本而不是指针，避免外部修改路由表内容
			return &route, nil
		}
	}

	// 遍历完所有路由都没有找到匹配的，返回错误
	// 这种情况下，数据包通常会被丢弃，或者发送ICMP不可达消息
	return nil, fmt.Errorf("未找到到达 %s 的路由", destination.String())
}

// GetAllRoutes 获取所有路由
func (t *Table) GetAllRoutes() []Route {
	t.mu.RLock()
	defer t.mu.RUnlock()

	routes := make([]Route, len(t.routes))
	copy(routes, t.routes)
	return routes
}

// ClearExpiredRoutes 清理过期路由
func (t *Table) ClearExpiredRoutes() {
	t.mu.Lock()
	defer t.mu.Unlock()

	validRoutes := make([]Route, 0, len(t.routes))

	for _, route := range t.routes {
		// 静态路由和连接路由不会过期
		if route.Type == RouteTypeStatic || route.Type == RouteTypeConnected || route.Type == RouteTypeDefault {
			validRoutes = append(validRoutes, route)
			continue
		}

		// 检查动态路由是否过期
		if route.Type == RouteTypeDynamic && route.TTL > 0 {
			if time.Since(route.Age) <= route.TTL {
				validRoutes = append(validRoutes, route)
			}
		} else {
			validRoutes = append(validRoutes, route)
		}
	}

	t.routes = validRoutes
}

// sortRoutes 按照最长前缀匹配原则对路由表进行排序
// 这是路由表管理的核心算法，确保路由查找的正确性和效率
//
// 排序规则（按优先级）：
// 1. 前缀长度（子网掩码中1的个数）：越长越优先
// 2. 路由度量值：越小越优先
//
// 为什么需要排序？
// - 确保LookupRoute时第一个匹配的路由就是最佳路由
// - 避免每次查找时都要比较所有匹配的路由
// - 提高路由查找的性能
//
// 前缀长度示例：
//   - 192.168.1.0/24  → 前缀长度24位 (更具体)
//   - 192.168.0.0/16  → 前缀长度16位 (较通用)
//   - 0.0.0.0/0       → 前缀长度0位  (默认路由，最通用)
//
// 排序后的路由表示例：
//  1. 192.168.1.100/32 (主机路由，最具体)
//  2. 192.168.1.0/24   (子网路由)
//  3. 192.168.0.0/16   (更大的网络)
//  4. 10.0.0.0/8       (A类网络)
//  5. 0.0.0.0/0        (默认路由，最后选择)
//
// 度量值比较示例（相同前缀长度时）：
//   - 路由A: 192.168.1.0/24, metric=1 (优先)
//   - 路由B: 192.168.1.0/24, metric=5
func (t *Table) sortRoutes() {
	// 使用Go标准库的sort.Slice进行自定义排序
	// 比较函数返回true表示i应该排在j之前
	sort.Slice(t.routes, func(i, j int) bool {
		// 获取两个路由的前缀长度（子网掩码中1的位数）
		// Size()方法返回(ones, bits)，ones是1的个数，bits是总位数
		// 例如：255.255.255.0 (/24) 返回 (24, 32)
		iOnes, _ := t.routes[i].Destination.Mask.Size()
		jOnes, _ := t.routes[j].Destination.Mask.Size()

		// 第一优先级：前缀长度比较
		// 前缀越长（越具体）的路由排在前面
		if iOnes != jOnes {
			return iOnes > jOnes // 降序排列，长前缀在前
		}

		// 第二优先级：度量值比较
		// 当前缀长度相同时，度量值越小（成本越低）的路由排在前面
		// 这确保了在多条等长路由中选择最优路径
		return t.routes[i].Metric < t.routes[j].Metric // 升序排列，小度量值在前
	})
}

// Size 返回路由表大小
func (t *Table) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.routes)
}

// Clear 清空路由表
func (t *Table) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes = t.routes[:0]
}
