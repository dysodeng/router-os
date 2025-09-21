// Package protocols 实现各种路由协议
// 本包目前实现了RIP（Routing Information Protocol）协议
// RIP是一种基于距离向量算法的内部网关协议（IGP）
package protocols

import (
	"fmt"
	"net"
	"sync"
	"time"

	"router-os/internal/interfaces"
	"router-os/internal/logging"
	"router-os/internal/routing"
)

// RIP协议相关常量定义
// 这些常量定义了RIP协议的核心参数，遵循RFC 2453标准
const (
	// RIPPort RIP协议使用的UDP端口号
	// 根据RFC 2453，RIP使用UDP端口520进行通信
	// 所有RIP消息都通过这个端口发送和接收
	RIPPort = 520

	// RIPVersion RIP协议版本号
	// 当前实现使用RIPv2，相比RIPv1增加了以下特性：
	// - 支持子网掩码（VLSM）
	// - 支持路由标签
	// - 支持下一跳地址
	// - 支持组播更新（224.0.0.9）
	RIPVersion = 2

	// RIPUpdateTimer 路由更新间隔时间
	// RIP协议每30秒发送一次完整的路由表更新
	// 这是一个定期的广播，确保网络中所有路由器都有最新的路由信息
	// 频繁更新的优点：快速收敛
	// 频繁更新的缺点：消耗带宽和CPU资源
	RIPUpdateTimer = 30 * time.Second

	// RIPTimeout 路由超时时间
	// 如果180秒内没有收到某条路由的更新，该路由被标记为不可达
	// 这个时间是更新间隔的6倍，允许丢失5次更新
	// 超时机制防止无效路由长期存在于路由表中
	RIPTimeout = 180 * time.Second

	// RIPMaxMetric 最大度量值（无穷大）
	// RIP协议中16跳表示无穷大，即不可达
	// 这个限制使得RIP只适用于小型网络（最多15跳）
	// 当路由的跳数达到16时，该路由被认为是不可达的
	// 这也是RIP协议防止路由环路的重要机制
	RIPMaxMetric = 16
)

// RIPEntry RIP路由条目
// 这是RIP数据包中携带的单个路由信息
// 每个RIP数据包可以包含多个路由条目（最多25个）
type RIPEntry struct {
	// Network 目标网络
	// 使用CIDR格式表示，例如192.168.1.0/24
	// 在RIPv2中，这包含了网络地址和子网掩码信息
	Network net.IPNet

	// Metric 到达目标网络的跳数
	// 表示从当前路由器到目标网络需要经过的路由器数量
	// 取值范围：1-15（16表示不可达）
	// 直连网络的度量值为1
	Metric int

	// NextHop 下一跳地址
	// 在RIPv2中，可以指定与发送路由器不同的下一跳地址
	// 这在多接入网络（如以太网）中很有用
	// 如果为0.0.0.0，则使用发送路由器的地址作为下一跳
	NextHop net.IP

	// Tag 路由标签
	// RIPv2新增的字段，用于标记路由的来源或类型
	// 可以用于路由过滤和策略控制
	// 例如：区分内部路由和外部路由
	Tag uint16
}

// RIPPacket RIP数据包结构
// 这是RIP协议在网络中传输的基本单元
// 符合RFC 2453定义的RIPv2数据包格式
type RIPPacket struct {
	// Command 命令类型
	// 1 = Request（请求）：请求路由信息
	// 2 = Response（响应）：发送路由信息
	// 其他值保留给未来使用
	Command byte

	// Version 版本号
	// 当前实现使用版本2（RIPv2）
	// 版本1（RIPv1）不支持子网掩码
	Version byte

	// Entries 路由条目列表
	// 一个RIP数据包最多可以包含25个路由条目
	// 这个限制来自于UDP数据包的最大长度限制
	// 如果路由表很大，需要分多个数据包发送
	Entries []RIPEntry
}

// RIP状态机状态
type RIPState uint8

const (
	RIPStateIdle RIPState = iota
	RIPStateRunning
	RIPStateStopping
)

// RIP邻居状态
type RIPNeighborState uint8

const (
	RIPNeighborDown RIPNeighborState = iota
	RIPNeighborUp
	RIPNeighborTimeout
)

// RIP认证类型
type RIPAuthType uint16

const (
	RIPAuthNone   RIPAuthType = 0
	RIPAuthSimple RIPAuthType = 2
	RIPAuthMD5    RIPAuthType = 3
)

// RIP认证结构
type RIPAuth struct {
	Type     RIPAuthType
	Password string
	KeyID    uint8
	AuthLen  uint8
	SeqNum   uint32
}

// RIP接口配置
type RIPInterfaceConfig struct {
	SendVersion    uint8         // 发送版本
	ReceiveVersion uint8         // 接收版本
	Authentication *RIPAuth      // 认证配置
	SplitHorizon   bool          // 水平分割
	PoisonReverse  bool          // 毒性逆转
	Passive        bool          // 被动接口
	UpdateTimer    time.Duration // 更新定时器
	TimeoutTimer   time.Duration // 超时定时器
	GarbageTimer   time.Duration // 垃圾回收定时器
}

// RIP邻居信息
type RIPNeighbor struct {
	Address    net.IP
	State      RIPNeighborState
	LastUpdate time.Time
	Version    uint8
	Routes     map[string]*RIPEntry
	Interface  string
	mu         sync.RWMutex //nolint:unused // 为邻居状态同步保留
}

// RIP接口
type RIPInterface struct {
	Name         string
	Address      net.IP
	Network      *net.IPNet
	Config       *RIPInterfaceConfig
	Neighbors    map[string]*RIPNeighbor
	LastUpdate   time.Time
	UpdateTimer  *time.Timer
	TimeoutTimer *time.Timer
	GarbageTimer *time.Timer
	mu           sync.RWMutex //nolint:unused // 为接口状态同步保留
}

// RIP路由表项增强
type RIPRouteEntry struct {
	*RIPEntry
	State        uint8
	ChangeFlag   bool
	TimeoutTimer *time.Timer
	GarbageTimer *time.Timer
	Source       string // 路由来源
}

// RIP统计信息
type RIPStatistics struct {
	PacketsSent       uint64
	PacketsReceived   uint64
	RequestsSent      uint64
	RequestsReceived  uint64
	ResponsesSent     uint64
	ResponsesReceived uint64
	BadPackets        uint64
	BadRoutes         uint64
	TriggeredUpdates  uint64
	RouteChanges      uint64
	mu                sync.RWMutex
}

// RIPManager RIP协议管理器
// 这是RIP协议的核心控制器，负责协议的所有功能
// 包括路由学习、路由通告、邻居管理等
type RIPManager struct {
	// routingTable 路由表引用
	// RIP管理器通过这个接口读取和更新路由表
	// 所有学习到的路由都会添加到这个路由表中
	routingTable routing.TableInterface

	// interfaceManager 接口管理器引用
	// 用于获取网络接口信息，确定在哪些接口上运行RIP
	// 只有状态为UP的接口才会参与RIP协议
	interfaceManager *interfaces.Manager

	// running 协议运行状态
	// 控制RIP协议是否处于活跃状态
	// 当为false时，停止所有RIP相关的处理
	running bool

	// mu 读写锁
	// 保护并发访问的数据结构
	// 使用读写锁提高并发性能
	mu sync.RWMutex

	// neighbors 邻居路由器信息
	// key: 邻居路由器的IP地址（字符串格式）
	// value: 最后一次收到该邻居更新的时间
	// 用于检测邻居是否超时，实现故障检测
	neighbors map[string]time.Time

	// 新增字段
	state      RIPState                  // 协议状态
	interfaces map[string]*RIPInterface  // RIP接口列表
	routes     map[string]*RIPRouteEntry // RIP路由表
	statistics *RIPStatistics            // 统计信息
	logger     *logging.Logger           // 日志记录器
}

// NewRIPManager 创建RIP协议管理器
// 这是RIP管理器的构造函数，初始化所有必要的组件
//
// 初始化过程：
// 1. 设置路由表和接口管理器的引用
// 2. 将运行状态设置为false（需要手动启动）
// 3. 初始化邻居映射表
//
// 参数：
//   - routingTable: 系统路由表的引用，用于读取和更新路由信息
//   - interfaceManager: 接口管理器的引用，用于获取网络接口状态
//
// 返回值：
//   - *RIPManager: 初始化完成的RIP管理器实例
//
// 使用示例：
//
//	ripManager := NewRIPManager(routingTable, interfaceManager)
//	err := ripManager.Start()
//	if err != nil {
//	    log.Printf("启动RIP协议失败: %v", err)
//	}
func NewRIPManager(routingTable routing.TableInterface, interfaceManager *interfaces.Manager) *RIPManager {
	return &RIPManager{
		routingTable:     routingTable,
		interfaceManager: interfaceManager,
		running:          false,
		neighbors:        make(map[string]time.Time),
		state:            RIPStateIdle,
		interfaces:       make(map[string]*RIPInterface),
		routes:           make(map[string]*RIPRouteEntry),
		statistics:       &RIPStatistics{},
		logger:           logging.NewLogger(logging.LogLevelInfo, "RIP"),
	}
}

// Start 启动RIP协议
// 这个方法启动RIP协议的所有核心功能，包括定期更新和邻居监控
//
// 启动过程：
// 1. 检查协议是否已经在运行，避免重复启动
// 2. 设置运行状态为true
// 3. 启动定期路由更新goroutine
// 4. 启动邻居超时检查goroutine
//
// RIP协议的两个核心定时器：
//   - 更新定时器：每30秒发送完整路由表
//   - 超时定时器：每30秒检查邻居是否超时
//
// 并发设计：
//   - 使用goroutine实现并发处理
//   - 每个定时器运行在独立的goroutine中
//   - 通过running标志控制所有goroutine的生命周期
//
// 返回值：
//   - error: 启动成功返回nil，如果已经在运行则返回错误
//
// 注意事项：
//   - 必须在配置完成后调用此方法
//   - 启动后会立即开始发送路由更新
//   - 确保网络接口已经配置并启用
func (rm *RIPManager) Start() error {
	// 获取写锁，确保启动过程的原子性
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// 检查是否已经在运行，防止重复启动
	if rm.running {
		return fmt.Errorf("RIP协议已经在运行")
	}

	// 设置运行状态
	rm.running = true
	rm.state = RIPStateRunning
	rm.logger.Info("启动RIP协议")

	// 初始化接口
	if err := rm.initializeInterfaces(); err != nil {
		rm.logger.Error("初始化接口失败: %v", err)
		return err
	}

	// 启动定期路由更新goroutine
	// 这个goroutine负责每30秒向所有邻居发送完整的路由表
	// 这是RIP协议的核心机制，确保网络收敛
	go rm.periodicUpdate()

	// 启动邻居超时检查goroutine
	// 这个goroutine负责检测邻居路由器是否失效
	// 如果180秒内没有收到邻居的更新，将其标记为不可达
	go rm.neighborTimeout()

	// 启动状态机
	go rm.stateMachine()

	return nil
}

// Stop 停止RIP协议
// 这个方法优雅地停止RIP协议的所有功能
//
// 停止过程：
// 1. 获取写锁确保操作的原子性
// 2. 设置running标志为false
// 3. 所有相关的goroutine会检测到这个标志并自动退出
//
// 停止后的状态：
//   - 不再发送路由更新
//   - 不再处理接收到的RIP数据包
//   - 不再检查邻居超时
//   - 已学习的路由仍保留在路由表中
//
// 优雅停止设计：
//   - 不强制杀死goroutine，而是通过标志位通知退出
//   - 各个goroutine会在下一次循环时检查标志并退出
//   - 避免了资源泄露和数据不一致的问题
//
// 使用场景：
//   - 系统关闭时
//   - 切换到其他路由协议时
//   - 网络维护期间临时停止
func (rm *RIPManager) Stop() {
	// 获取写锁，确保停止过程的原子性
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// 设置运行状态为false
	// 所有相关的goroutine会检测到这个变化并退出
	rm.running = false
	rm.state = RIPStateStopping
	rm.logger.Info("停止RIP协议")

	// 清理接口定时器
	for _, ripIface := range rm.interfaces {
		if ripIface.UpdateTimer != nil {
			ripIface.UpdateTimer.Stop()
		}
		if ripIface.TimeoutTimer != nil {
			ripIface.TimeoutTimer.Stop()
		}
		if ripIface.GarbageTimer != nil {
			ripIface.GarbageTimer.Stop()
		}
	}

	rm.state = RIPStateIdle
}

// periodicUpdate 定期发送路由更新
// 这是RIP协议的核心机制之一：定期广播路由信息
//
// RIP定期更新机制：
// 1. 每30秒发送一次完整的路由表
// 2. 向所有配置的接口广播路由信息
// 3. 确保网络中的路由信息保持同步
// 4. 即使没有路由变化也要发送（保活机制）
//
// 定期更新的作用：
//   - 邻居发现：让其他路由器知道本路由器的存在
//   - 路由同步：确保所有路由器有相同的网络视图
//   - 故障检测：如果路由器故障，其他路由器会检测到更新停止
//   - 网络收敛：新路由器加入时能快速学习到网络拓扑
//
// 定时器设计：
//   - 使用Go的time.Ticker实现精确定时
//   - 通过IsRunning()检查协议状态
//   - 在协议停止时自动退出循环
//
// 注意事项：
//   - 定期更新会产生网络开销
//   - 在大型网络中可能导致广播风暴
//   - 这是RIP协议的固有限制
func (rm *RIPManager) periodicUpdate() {
	// 创建定时器，每30秒触发一次
	// RIPUpdateTimer是RIP协议标准定义的更新间隔
	ticker := time.NewTicker(RIPUpdateTimer)
	defer ticker.Stop() // 确保在函数退出时清理定时器资源

	// 主循环：持续监听定时器信号
	for range ticker.C {
		// 定时器触发：检查协议状态并发送更新
		// 只有在协议运行状态下才发送更新
		if !rm.IsRunning() {
			// 协议已停止，退出循环
			return
		}
		// 发送路由更新到所有邻居
		rm.sendRoutingUpdate()
	}
}

// neighborTimeout 检查邻居超时
// 这是RIP协议的故障检测机制：监控邻居路由器的活跃状态
//
// 邻居超时检测机制：
// 1. 定期检查每个邻居的最后活跃时间
// 2. 如果邻居超过180秒没有发送更新，认为其故障
// 3. 删除来自故障邻居的所有路由
// 4. 触发路由重新计算和网络收敛
//
// 超时检测的重要性：
//   - 故障检测：及时发现邻居路由器故障
//   - 路由清理：删除无效路由，避免黑洞
//   - 网络收敛：触发替代路径的计算
//   - 资源管理：清理无用的邻居信息
//
// 超时处理流程：
//  1. 遍历所有已知邻居
//  2. 检查每个邻居的最后活跃时间
//  3. 标记超时的邻居为故障
//  4. 删除故障邻居的路由信息
//  5. 更新路由表并通知其他路由器
//
// 定时器配置：
//   - 检查间隔：每30秒检查一次
//   - 超时阈值：RIP标准定义为180秒
//   - 可配置性：支持根据网络环境调整
func (rm *RIPManager) neighborTimeout() {
	// 创建定时器，每30秒检查一次邻居状态
	// 检查频率高于超时时间，确保及时发现故障
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop() // 确保在函数退出时清理定时器资源

	// 主循环：持续监听定时器信号
	for range ticker.C {
		// 定时器触发：检查协议状态并执行超时检测
		// 只有在协议运行状态下才进行邻居检查
		if !rm.IsRunning() {
			// 协议已停止，退出循环
			return
		}
		// 检查所有邻居的超时状态
		rm.checkNeighborTimeout()
	}
}

// sendRoutingUpdate 发送路由更新
// 这是RIP协议的核心功能之一，负责向邻居路由器广播本地路由表
//
// 路由通告过程：
// 1. 获取当前路由表中的所有路由
// 2. 构建RIP响应数据包
// 3. 过滤无效路由（度量值>=16）
// 4. 向所有活跃接口发送更新
//
// RIP路由通告原则：
//   - 定期通告：每30秒发送一次完整路由表
//   - 触发更新：路由变化时立即发送（当前实现未包含）
//   - 水平分割：不向学习路由的接口发送该路由（防止环路）
//   - 毒性逆转：向学习路由的接口发送度量值为16的路由
//
// 数据包结构：
//   - Command: 2 (Response)
//   - Version: 2 (RIPv2)
//   - Entries: 路由条目列表（最多25个）
//
// 过滤规则：
//   - 跳过度量值>=16的路由（不可达路由）
//   - 跳过老化的路由
//   - 应用路由策略（如果配置）
//
// 使用场景：
//   - 定期更新：由periodicUpdate调用
//   - 响应请求：收到RIP请求时调用
//   - 触发更新：路由变化时调用（未实现）
func (rm *RIPManager) sendRoutingUpdate() {
	// 第一步：获取当前路由表中的所有路由
	// 这包括直连路由、静态路由和动态学习的路由
	routes := rm.routingTable.GetAllRoutes()

	// 第二步：构建RIP响应数据包
	// 设置数据包头部信息
	packet := &RIPPacket{
		Command: 2,                   // Response命令，表示这是路由信息响应
		Version: RIPVersion,          // 使用RIPv2版本
		Entries: make([]RIPEntry, 0), // 初始化空的路由条目列表
	}

	// 第三步：遍历所有路由，构建路由条目
	for _, route := range routes {
		// 过滤无效路由：跳过度量值为无穷大的路由
		// 度量值>=16表示路由不可达，不应该通告给邻居
		if route.Metric >= RIPMaxMetric {
			continue
		}

		// 构建RIP路由条目
		// 将内部路由格式转换为RIP协议格式
		entry := RIPEntry{
			Network: *route.Destination, // 目标网络（包含子网掩码）
			Metric:  route.Metric,       // 跳数（度量值）
			NextHop: route.Gateway,      // 下一跳地址
			Tag:     0,                  // 路由标签（当前设为0）
		}

		// 将路由条目添加到数据包中
		// 注意：一个RIP数据包最多包含25个路由条目
		// 如果路由表很大，需要分多个数据包发送
		packet.Entries = append(packet.Entries, entry)
	}

	// 第四步：向所有活跃接口发送更新
	// 只向状态为UP的接口发送RIP更新
	// 这确保了只在可用的网络链路上传播路由信息
	interfaces := rm.interfaceManager.GetActiveInterfaces()
	for _, iface := range interfaces {
		// 向每个接口发送相同的路由更新
		// 在真实实现中，这里应该应用水平分割规则
		// 即不向学习到路由的接口发送该路由信息
		rm.sendPacketToInterface(packet, iface)
	}
}

// sendPacketToInterface 向指定接口发送数据包
func (rm *RIPManager) sendPacketToInterface(packet *RIPPacket, iface *interfaces.Interface) {
	// 在真实实现中，这里会构建UDP数据包并发送到RIP端口
	// 这里只是模拟发送过程
	logging.Debug("向接口 %s 发送RIP更新，包含 %d 个路由条目", iface.Name, len(packet.Entries))
}

// ProcessRIPPacket 处理接收到的RIP数据包
// 这是RIP协议的数据包处理入口，负责解析和分发不同类型的RIP消息
//
// 处理流程：
// 1. 检查协议运行状态
// 2. 更新邻居活跃时间（邻居发现）
// 3. 根据命令类型分发处理
// 4. 执行相应的处理逻辑
//
// RIP命令类型：
//   - Command 1: Request（请求）
//   - 请求路由信息，通常在启动时发送
//   - 可以请求特定路由或完整路由表
//   - Command 2: Response（响应）
//   - 包含路由信息的响应
//   - 定期更新或对请求的回复
//
// 邻居管理：
//   - 记录每个邻居的最后活跃时间
//   - 用于检测邻居是否失效
//   - 超时的邻居会被从邻居表中移除
//
// 参数：
//   - packet: 接收到的RIP数据包
//   - sourceIP: 发送方的IP地址
//   - receivedInterface: 接收数据包的接口名称
//
// 返回值：
//   - error: 处理成功返回nil，失败返回错误信息
//
// 错误处理：
//   - 协议未运行：拒绝处理任何数据包
//   - 未知命令：记录错误并丢弃数据包
//   - 格式错误：记录错误并丢弃数据包
func (rm *RIPManager) ProcessRIPPacket(packet *RIPPacket, sourceIP net.IP, receivedInterface string) error {
	// 第一步：检查协议运行状态
	// 如果RIP协议未启动，拒绝处理任何数据包
	// 这防止了在协议停止期间的意外处理
	if !rm.IsRunning() {
		return fmt.Errorf("RIP协议未运行")
	}

	// 第二步：更新邻居信息（邻居发现机制）
	// 记录收到数据包的时间，用于邻居活跃性检测
	// 这是RIP协议邻居管理的核心机制
	rm.mu.Lock()
	rm.neighbors[sourceIP.String()] = time.Now()
	rm.mu.Unlock()

	// 第三步：根据命令类型分发处理
	// RIP协议定义了不同的命令类型，需要不同的处理逻辑
	switch packet.Command {
	case 1: // Request（请求）
		// 处理路由信息请求
		// 通常在路由器启动时发送，请求邻居的路由表
		return rm.handleRIPRequest(packet, sourceIP, receivedInterface)

	case 2: // Response（响应）
		// 处理路由信息响应
		// 这是最常见的RIP消息类型，包含路由更新信息
		return rm.handleRIPResponse(packet, sourceIP, receivedInterface)

	default:
		// 未知命令类型，记录错误并拒绝处理
		// 这有助于调试和安全防护
		return fmt.Errorf("未知的RIP命令: %d", packet.Command)
	}
}

// handleRIPRequest 处理RIP请求
func (rm *RIPManager) handleRIPRequest(packet *RIPPacket, sourceIP net.IP, receivedInterface string) error {
	// 发送完整的路由表作为响应
	rm.sendRoutingUpdate()
	return nil
}

// handleRIPResponse 处理RIP响应消息
// 这是RIP协议的核心功能：处理从邻居收到的路由更新信息
//
// RIP路由学习过程：
// 1. 解析响应消息中的路由条目
// 2. 验证路由的有效性（度量值检查）
// 3. 计算新的度量值（距离向量算法）
// 4. 创建路由条目并添加到路由表
// 5. 处理路由更新和替换
//
// 距离向量算法核心：
//   - 每个路由器维护到所有目标网络的距离（跳数）
//   - 定期与邻居交换路由信息
//   - 根据邻居的信息更新自己的路由表
//   - 选择最短路径作为最优路由
//
// 度量值处理：
//   - RIP使用跳数作为度量值
//   - 最大跳数为15，16表示无穷大（不可达）
//   - 收到路由后需要加1（到邻居的距离）
//   - 超过15跳的路由被认为不可达
//
// 路由更新策略：
//   - 更好的路由（更小的度量值）会替换现有路由
//   - 相同度量值的路由可能触发负载均衡
//   - 来自同一邻居的路由更新会覆盖旧信息
//
// 参数：
//   - packet: 包含路由信息的RIP响应数据包
//   - sourceIP: 发送响应的邻居路由器IP地址
//   - receivedInterface: 接收数据包的本地接口
//
// 返回值：
//   - error: 处理成功返回nil，失败返回错误信息
//
// 示例场景：
//
//	路由器A收到来自路由器B的响应：
//	- B报告到网络192.168.1.0/24的距离为2跳
//	- A计算自己到该网络的距离为3跳（2+1）
//	- 如果A当前没有到该网络的路由，或现有路由跳数>3，则更新路由表
func (rm *RIPManager) handleRIPResponse(packet *RIPPacket, sourceIP net.IP, receivedInterface string) error {
	// 遍历响应消息中的所有路由条目
	// 每个条目代表邻居知道的一个网络路径
	for _, entry := range packet.Entries {
		// 第一步：检查路由可达性
		// 度量值>=16表示路由不可达，需要特殊处理
		if entry.Metric >= RIPMaxMetric {
			// 路由不可达，从路由表中删除相关路由
			// 这是RIP协议的毒性逆转机制，用于快速传播路由失效信息
			_ = rm.routingTable.RemoveRoute(&entry.Network, entry.NextHop, receivedInterface)
			continue
		}

		// 第二步：计算新的度量值（距离向量算法核心）
		// RIP使用跳数作为度量值，每经过一个路由器跳数+1
		// 这体现了距离向量算法的"距离"概念
		metric := entry.Metric + 1

		// 第三步：检查度量值上限
		// RIP协议限制最大跳数为15，超过则认为不可达
		// 这防止了路由环路导致的无限计数问题
		if metric >= RIPMaxMetric {
			metric = RIPMaxMetric
		}

		// 第四步：创建路由条目
		// 将从邻居学到的路由信息转换为本地路由表条目
		route := routing.Route{
			Destination: &entry.Network,           // 目标网络地址
			Gateway:     sourceIP,                 // 下一跳地址（邻居的IP）
			Interface:   receivedInterface,        // 出接口（收到更新的接口）
			Metric:      metric,                   // 计算后的度量值
			Type:        routing.RouteTypeDynamic, // 动态路由类型
			TTL:         RIPTimeout,               // 路由生存时间
		}

		// 第五步：路由选择和更新
		// 检查是否存在到同一目标的更好路由
		// 只有当新路由更优（度量值更小）或不存在现有路由时才更新
		existingRoute, err := rm.routingTable.LookupRoute(entry.Network.IP)
		if err != nil || existingRoute.Metric > metric {
			// 新路由更优或不存在现有路由，添加到路由表
			// 路由表会自动处理路由替换和更新逻辑
			_ = rm.routingTable.AddRoute(route)
		}
	}

	return nil
}

// checkNeighborTimeout 检查邻居超时
func (rm *RIPManager) checkNeighborTimeout() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	now := time.Now()
	for neighbor, lastSeen := range rm.neighbors {
		if now.Sub(lastSeen) > RIPTimeout {
			// 邻居超时，删除相关路由
			delete(rm.neighbors, neighbor)
			rm.removeRoutesFromNeighbor(neighbor)
		}
	}
}

// removeRoutesFromNeighbor 删除来自指定邻居的路由
func (rm *RIPManager) removeRoutesFromNeighbor(neighbor string) {
	routes := rm.routingTable.GetAllRoutes()
	neighborIP := net.ParseIP(neighbor)

	for _, route := range routes {
		if route.Type == routing.RouteTypeDynamic && route.Gateway.Equal(neighborIP) {
			_ = rm.routingTable.RemoveRoute(route.Destination, route.Gateway, route.Interface)
		}
	}
}

// IsRunning 检查RIP是否在运行
func (rm *RIPManager) IsRunning() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.running
}

// GetNeighbors 获取邻居信息
func (rm *RIPManager) GetNeighbors() map[string]time.Time {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	neighbors := make(map[string]time.Time)
	for k, v := range rm.neighbors {
		neighbors[k] = v
	}
	return neighbors
}

// initializeInterfaces 初始化RIP接口
func (rm *RIPManager) initializeInterfaces() error {
	interfaces := rm.interfaceManager.GetActiveInterfaces()
	for _, iface := range interfaces {
		ripIface := &RIPInterface{
			Name:      iface.Name,
			Address:   iface.IPAddress,
			Network:   &net.IPNet{IP: iface.IPAddress.Mask(iface.Netmask), Mask: iface.Netmask},
			Neighbors: make(map[string]*RIPNeighbor),
			Config: &RIPInterfaceConfig{
				SendVersion:    RIPVersion,
				ReceiveVersion: RIPVersion,
				SplitHorizon:   true,
				PoisonReverse:  false,
				Passive:        false,
				UpdateTimer:    RIPUpdateTimer,
				TimeoutTimer:   RIPTimeout,
				GarbageTimer:   RIPTimeout * 2,
			},
		}
		rm.interfaces[iface.Name] = ripIface
		rm.logger.Debug("初始化RIP接口: %s", iface.Name)
	}
	return nil
}

// stateMachine RIP状态机
func (rm *RIPManager) stateMachine() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !rm.IsRunning() {
			return
		}
		rm.processStateMachine()
	}
}

// processStateMachine 处理状态机逻辑
func (rm *RIPManager) processStateMachine() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	switch rm.state {
	case RIPStateRunning:
		// 检查接口状态
		rm.checkInterfaceStates()
		// 处理邻居状态
		rm.processNeighborStates()
	case RIPStateStopping:
		// 清理资源
		rm.cleanupResources()
	default:
		rm.logger.Error("unhandled default case")
	}
}

// checkInterfaceStates 检查接口状态
func (rm *RIPManager) checkInterfaceStates() {
	activeInterfaces := rm.interfaceManager.GetActiveInterfaces()
	activeMap := make(map[string]bool)

	// 标记活跃接口
	for _, iface := range activeInterfaces {
		activeMap[iface.Name] = true
		if _, exists := rm.interfaces[iface.Name]; !exists {
			// 新接口，添加到RIP管理
			rm.addInterface(iface)
		}
	}

	// 移除非活跃接口
	for name, ripIface := range rm.interfaces {
		if !activeMap[name] {
			rm.removeInterface(ripIface)
			delete(rm.interfaces, name)
		}
	}
}

// processNeighborStates 处理邻居状态
func (rm *RIPManager) processNeighborStates() {
	now := time.Now()
	for _, ripIface := range rm.interfaces {
		for addr, neighbor := range ripIface.Neighbors {
			switch neighbor.State {
			case RIPNeighborUp:
				if now.Sub(neighbor.LastUpdate) > RIPTimeout {
					neighbor.State = RIPNeighborTimeout
					rm.logger.Info("邻居 %s 超时", addr)
				}
			case RIPNeighborTimeout:
				// 清理超时邻居的路由
				rm.removeNeighborRoutes(neighbor)
				delete(ripIface.Neighbors, addr)
				rm.logger.Info("删除超时邻居 %s", addr)
			}
		}
	}
}

// addInterface 添加接口到RIP管理
func (rm *RIPManager) addInterface(iface *interfaces.Interface) {
	ripIface := &RIPInterface{
		Name:      iface.Name,
		Address:   iface.IPAddress,
		Network:   &net.IPNet{IP: iface.IPAddress.Mask(iface.Netmask), Mask: iface.Netmask},
		Neighbors: make(map[string]*RIPNeighbor),
		Config: &RIPInterfaceConfig{
			SendVersion:    RIPVersion,
			ReceiveVersion: RIPVersion,
			SplitHorizon:   true,
			PoisonReverse:  false,
			Passive:        false,
			UpdateTimer:    RIPUpdateTimer,
			TimeoutTimer:   RIPTimeout,
			GarbageTimer:   RIPTimeout * 2,
		},
	}
	rm.interfaces[iface.Name] = ripIface
	rm.logger.Info("添加RIP接口: %s", iface.Name)
}

// removeInterface 从RIP管理中移除接口
func (rm *RIPManager) removeInterface(ripIface *RIPInterface) {
	// 停止定时器
	if ripIface.UpdateTimer != nil {
		ripIface.UpdateTimer.Stop()
	}
	if ripIface.TimeoutTimer != nil {
		ripIface.TimeoutTimer.Stop()
	}
	if ripIface.GarbageTimer != nil {
		ripIface.GarbageTimer.Stop()
	}

	// 清理邻居
	for _, neighbor := range ripIface.Neighbors {
		rm.removeNeighborRoutes(neighbor)
	}

	rm.logger.Info("移除RIP接口: %s", ripIface.Name)
}

// removeNeighborRoutes 删除邻居的路由
func (rm *RIPManager) removeNeighborRoutes(neighbor *RIPNeighbor) {
	for _, route := range neighbor.Routes {
		_ = rm.routingTable.RemoveRoute(&route.Network, neighbor.Address, neighbor.Interface)
	}
}

// cleanupResources 清理资源
func (rm *RIPManager) cleanupResources() {
	// 清理所有接口
	for name, ripIface := range rm.interfaces {
		rm.removeInterface(ripIface)
		delete(rm.interfaces, name)
	}

	// 清理邻居信息
	rm.neighbors = make(map[string]time.Time)

	// 清理路由
	rm.routes = make(map[string]*RIPRouteEntry)
}

// GetStatistics 获取RIP统计信息
func (rm *RIPManager) GetStatistics() *RIPStatistics {
	rm.statistics.mu.RLock()
	defer rm.statistics.mu.RUnlock()

	stats := &RIPStatistics{
		PacketsSent:       rm.statistics.PacketsSent,
		PacketsReceived:   rm.statistics.PacketsReceived,
		RequestsSent:      rm.statistics.RequestsSent,
		RequestsReceived:  rm.statistics.RequestsReceived,
		ResponsesSent:     rm.statistics.ResponsesSent,
		ResponsesReceived: rm.statistics.ResponsesReceived,
		BadPackets:        rm.statistics.BadPackets,
		BadRoutes:         rm.statistics.BadRoutes,
		TriggeredUpdates:  rm.statistics.TriggeredUpdates,
		RouteChanges:      rm.statistics.RouteChanges,
	}
	return stats
}

// GetState 获取RIP状态
func (rm *RIPManager) GetState() RIPState {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.state
}

// GetInterfaces 获取RIP接口信息
func (rm *RIPManager) GetInterfaces() map[string]*RIPInterface {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	interfaces := make(map[string]*RIPInterface)
	for k, v := range rm.interfaces {
		interfaces[k] = v
	}
	return interfaces
}
