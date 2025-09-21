package routing

import (
	"encoding/json"
	"net"
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

	// Proto 路由协议
	// 标识路由是通过哪种协议学习到的
	// 例如："dhcp", "kernel", "static", "ospf", "bgp", "rip"等
	Proto string `json:"proto"`

	// Scope 路由作用域
	// 定义路由的作用范围
	// - "link": 链路本地路由，仅在本地链路有效
	// - "host": 主机路由，指向特定主机
	// - "global": 全局路由，可以跨网络转发
	Scope string `json:"scope"`

	// Src 源地址
	// 指定从该路由发送数据包时使用的源IP地址
	// 当有多个IP地址时，确定使用哪个作为源地址
	Src net.IP `json:"src"`

	// Flags 路由标志
	// 表示路由的特殊属性和状态
	// 例如："U"(up), "G"(gateway), "H"(host), "D"(dynamic)等
	Flags string `json:"flags"`
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
		Proto       string        `json:"proto"`
		Scope       string        `json:"scope"`
		Src         string        `json:"src"`
		Flags       string        `json:"flags"`
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

	// 转换src为字符串格式
	var srcStr string
	if r.Src != nil {
		srcStr = r.Src.String()
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
		Proto:       r.Proto,
		Scope:       r.Scope,
		Src:         srcStr,
		Flags:       r.Flags,
	}

	return json.Marshal(routeJSON)
}
