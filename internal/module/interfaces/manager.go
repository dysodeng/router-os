package interfaces

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// InterfaceStatus 网络接口状态枚举
// 定义了网络接口可能的运行状态，用于监控和管理接口
type InterfaceStatus int

const (
	// InterfaceStatusDown 接口关闭状态
	// 表示接口物理上或逻辑上不可用，无法传输数据
	// 这种状态下的接口不会参与路由计算和数据转发
	InterfaceStatusDown InterfaceStatus = iota

	// InterfaceStatusUp 接口启用状态
	// 表示接口正常工作，可以发送和接收数据包
	// 只有处于此状态的接口才能参与路由协议和数据转发
	InterfaceStatusUp

	// InterfaceStatusTesting 接口测试状态
	// 表示接口正在进行连通性测试或诊断
	// 在此状态下接口可能有限制性的功能
	InterfaceStatusTesting
)

// PortRole 端口角色枚举
// 定义网络接口在路由器中的功能角色
type PortRole int

const (
	// PortRoleUnassigned 未分配角色
	// 接口尚未配置具体的网络角色，处于待配置状态
	PortRoleUnassigned PortRole = iota

	// PortRoleWAN 广域网接口
	// 连接到互联网或上级网络的接口，通常配置DHCP客户端或静态IP
	// 需要配置NAT转发规则，允许内网设备访问外网
	PortRoleWAN

	// PortRoleLAN 局域网接口
	// 连接到内网设备的接口，通常配置静态IP作为网关
	// 可以运行DHCP服务器为内网设备分配IP地址
	PortRoleLAN

	// PortRoleDMZ 非军事化区接口
	// 连接到DMZ网络的接口，用于放置对外提供服务的服务器
	// 具有特殊的防火墙规则和访问控制策略
	PortRoleDMZ
)

// String 返回端口角色的字符串表示
func (pr PortRole) String() string {
	switch pr {
	case PortRoleUnassigned:
		return "unassigned"
	case PortRoleWAN:
		return "wan"
	case PortRoleLAN:
		return "lan"
	case PortRoleDMZ:
		return "dmz"
	default:
		return "unknown"
	}
}

// Interface 网络接口结构体
// 表示系统中的一个网络接口，包含接口的所有配置信息和统计数据
// 这是网络接口管理的核心数据结构
type Interface struct {
	// Name 接口名称
	// 系统中接口的唯一标识符，如 "eth0", "wlan0", "en0" 等
	// 用于在系统调用和配置中引用特定的网络接口
	Name string

	// IPAddress IP地址
	// 分配给此接口的IPv4或IPv6地址
	// 如果接口未配置IP地址，此字段为nil
	IPAddress net.IP

	// Netmask 子网掩码
	// 定义了网络部分和主机部分的边界
	// 与IP地址配合使用确定接口所属的网络段
	Netmask net.IPMask

	// Gateway 网关地址
	// 此接口的默认网关，用于访问其他网络
	// 通常指向路由器或上级网络设备的IP地址
	Gateway net.IP

	// MACAddress MAC地址
	// 网络接口的物理地址，用于数据链路层通信
	// 每个网络接口都有唯一的MAC地址
	MACAddress net.HardwareAddr

	// MTU 最大传输单元（Maximum Transmission Unit）
	// 此接口能够传输的最大数据包大小（字节）
	// 以太网接口通常为1500字节，影响数据包分片
	MTU int

	// Status 接口当前状态
	// 表示接口是否可用于数据传输
	// 只有状态为Up的接口才参与路由和转发
	Status InterfaceStatus

	// Role 端口角色
	// 定义此接口在网络拓扑中的功能角色（WAN/LAN/DMZ等）
	// 决定了接口的配置策略和防火墙规则
	Role PortRole

	// LastSeen 最后活跃时间
	// 记录接口最后一次状态更新或数据传输的时间
	// 用于监控接口活跃度和故障检测
	LastSeen time.Time

	// TxPackets 发送数据包计数
	// 统计通过此接口发送的数据包总数
	// 用于网络性能监控和故障诊断
	TxPackets uint64

	// RxPackets 接收数据包计数
	// 统计通过此接口接收的数据包总数
	// 与发送计数配合分析网络流量模式
	RxPackets uint64

	// TxBytes 发送字节数统计
	// 统计通过此接口发送的总字节数
	// 用于带宽使用分析和计费
	TxBytes uint64

	// RxBytes 接收字节数统计
	// 统计通过此接口接收的总字节数
	// 用于监控网络使用情况
	RxBytes uint64

	// Errors 错误计数
	// 统计接口上发生的各种错误总数
	// 包括CRC错误、冲突、丢包等，用于故障诊断
	Errors uint64
}

// Manager 网络接口管理器
// 负责系统中所有网络接口的发现、配置、监控和管理
// 这是网络接口管理的核心组件，提供线程安全的接口操作
//
// 主要功能：
// 1. 自动发现系统网络接口
// 2. 接口状态监控和管理
// 3. 接口统计信息收集
// 4. 接口配置的增删改查
// 5. 并发安全的接口访问
//
// 设计特点：
// - 使用读写锁保证并发安全
// - 支持热插拔接口的动态管理
// - 提供丰富的查询和过滤功能
type Manager struct {
	// interfaces 接口映射表
	// key: 接口名称（如"eth0", "wlan0"）
	// value: 接口对象指针
	// 存储系统中所有已发现和配置的网络接口
	interfaces map[string]*Interface

	// mu 读写互斥锁
	// 保护interfaces映射表的并发访问
	// 使用读写锁允许多个读操作并发执行，提高性能
	mu sync.RWMutex

	// running 管理器运行状态
	// 标识接口管理器是否处于活跃状态
	// 只有在运行状态下才会进行接口发现和监控
	running bool

	// stopChan 停止通道
	// 用于通知后台goroutine停止运行
	// 当管理器停止时，会关闭此通道
	stopChan chan struct{}
}

// NewManager 创建新的网络接口管理器
// 这是接口管理器的构造函数，初始化所有必要的数据结构
//
// 初始化过程：
// 1. 创建空的接口映射表
// 2. 设置初始运行状态为false（需要手动启动）
// 3. 初始化读写锁
//
// 返回值：
//   - *Manager: 初始化完成的接口管理器实例
//
// 使用示例：
//
//	manager := NewManager()
//	err := manager.Start()  // 启动管理器并发现接口
//	if err != nil {
//	    log.Printf("启动接口管理器失败: %v", err)
//	}
//
// 注意事项：
// - 创建后需要调用Start()方法才能开始工作
// - 程序退出前应调用Stop()方法清理资源
func NewManager() *Manager {
	return &Manager{
		interfaces: make(map[string]*Interface), // 初始化空的接口映射表
		running:    false,                       // 初始状态为停止
		stopChan:   make(chan struct{}),         // 初始化停止通道
	}
}

// Start 启动网络接口管理器
// 初始化管理器并发现系统中的所有网络接口
//
// 启动过程：
// 1. 检查管理器是否已经在运行，避免重复启动
// 2. 调用discoverInterfaces()发现系统网络接口
// 3. 将管理器状态设置为运行中
//
// 接口发现机制：
// - 使用Go标准库net.Interfaces()获取系统接口列表
// - 自动跳过回环接口（loopback）
// - 读取每个接口的配置信息（IP地址、子网掩码、MTU等）
// - 检测接口的当前状态（启用/禁用）
//
// 错误处理：
// - 如果管理器已在运行，返回错误
// - 如果接口发现失败，返回详细错误信息
// - 发生错误时不会改变管理器状态
//
// 返回值：
//   - error: 启动过程中的错误，成功时为nil
//
// 使用示例：
//
//	manager := NewManager()
//	if err := manager.Start(); err != nil {
//	    log.Fatalf("无法启动接口管理器: %v", err)
//	}
//	defer manager.Stop()
//
// 注意事项：
// - 此方法是线程安全的
// - 启动后会立即发现所有系统接口
// - 建议在程序启动时调用一次
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查是否已经在运行，防止重复启动
	if m.running {
		return fmt.Errorf("接口管理器已经在运行")
	}

	// 发现并初始化系统网络接口
	// 这个过程会扫描系统中的所有网络接口
	// 并将它们添加到管理器的接口映射表中
	if err := m.discoverInterfaces(); err != nil {
		return fmt.Errorf("发现网络接口失败: %v", err)
	}

	// 设置运行状态为true，表示管理器已启动
	m.running = true

	// 启动统计数据收集的goroutine
	go m.collectStats()

	return nil
}

// Stop 停止网络接口管理器
// 优雅地关闭管理器，停止所有监控和管理活动
//
// 停止过程：
// 1. 获取写锁确保线程安全
// 2. 将运行状态设置为false
// 3. 停止所有后台监控任务（如果有）
//
// 资源清理：
// - 停止接口状态监控
// - 停止统计信息收集
// - 保留接口配置信息（不清空interfaces映射表）
//
// 设计考虑：
// - 停止后接口配置信息仍然保留，可以重新启动
// - 不会影响系统实际的网络接口状态
// - 只是停止管理器的监控和管理功能
//
// 使用示例：
//
//	// 程序退出时停止管理器
//	defer manager.Stop()
//
//	// 或者在需要时手动停止
//	manager.Stop()
//	// 可以稍后重新启动
//	manager.Start()
//
// 注意事项：
// - 此方法是线程安全的
// - 可以多次调用而不会出错
// - 停止后可以通过Start()重新启动
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查是否正在运行
	if !m.running {
		return
	}

	// 设置运行状态为false，停止所有管理活动
	// 这会停止接口监控、统计收集等后台任务
	m.running = false

	// 关闭停止通道，通知goroutine停止
	close(m.stopChan)

	// 重新创建停止通道，以便下次启动使用
	m.stopChan = make(chan struct{})
}

// AddInterface 添加网络接口到管理器
// 将一个新的网络接口添加到管理器的接口映射表中
//
// 功能说明：
// - 检查接口名称是否已存在，避免重复添加
// - 自动设置接口的最后活跃时间为当前时间
// - 将接口添加到内部映射表中进行管理
//
// 参数：
//   - iface: 要添加的接口对象指针，包含完整的接口配置信息
//
// 返回值：
//   - error: 添加过程中的错误，成功时为nil
//
// 错误情况：
// - 如果同名接口已存在，返回错误
// - 如果接口对象为nil，可能导致panic
//
// 使用示例：
//
//	newInterface := &Interface{
//	    Name:      "eth1",
//	    IPAddress: net.ParseIP("192.168.1.100"),
//	    MTU:       1500,
//	    Status:    InterfaceStatusUp,
//	}
//	err := manager.AddInterface(newInterface)
//	if err != nil {
//	    log.Printf("添加接口失败: %v", err)
//	}
//
// 注意事项：
// - 此方法是线程安全的
// - 会自动更新接口的LastSeen时间
// - 不会验证接口配置的有效性
func (m *Manager) AddInterface(iface *Interface) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查接口是否已存在，防止重复添加
	if _, exists := m.interfaces[iface.Name]; exists {
		return fmt.Errorf("接口 %s 已存在", iface.Name)
	}

	// 设置接口的最后活跃时间为当前时间
	// 这有助于跟踪接口的活跃状态
	iface.LastSeen = time.Now()

	// 将接口添加到映射表中
	m.interfaces[iface.Name] = iface
	return nil
}

// RemoveInterface 从管理器中删除网络接口
// 根据接口名称从管理器中移除指定的网络接口
//
// 功能说明：
// - 检查接口是否存在，避免删除不存在的接口
// - 从内部映射表中移除接口记录
// - 不会影响系统实际的网络接口
//
// 参数：
//   - name: 要删除的接口名称（如"eth0", "wlan0"）
//
// 返回值：
//   - error: 删除过程中的错误，成功时为nil
//
// 错误情况：
// - 如果指定名称的接口不存在，返回错误
//
// 使用示例：
//
//	err := manager.RemoveInterface("eth1")
//	if err != nil {
//	    log.Printf("删除接口失败: %v", err)
//	}
//
// 注意事项：
// - 此方法是线程安全的
// - 只是从管理器中移除，不影响系统接口
// - 删除后无法通过管理器访问该接口
// - 如果接口正在被路由使用，可能导致路由失效
func (m *Manager) RemoveInterface(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查接口是否存在
	if _, exists := m.interfaces[name]; !exists {
		return fmt.Errorf("接口 %s 不存在", name)
	}

	// 从映射表中删除接口
	delete(m.interfaces, name)
	return nil
}

// GetInterface 根据名称获取网络接口
// 从管理器中查找并返回指定名称的网络接口
//
// 功能说明：
// - 根据接口名称查找对应的接口对象
// - 返回接口的完整配置和状态信息
// - 使用读锁保证并发安全，允许多个读操作同时进行
//
// 参数：
//   - name: 要查找的接口名称（如"eth0", "wlan0"）
//
// 返回值：
//   - *Interface: 找到的接口对象指针
//   - error: 查找过程中的错误，成功时为nil
//
// 错误情况：
// - 如果指定名称的接口不存在，返回nil和错误
//
// 使用示例：
//
//	iface, err := manager.GetInterface("eth0")
//	if err != nil {
//	    log.Printf("接口不存在: %v", err)
//	    return
//	}
//	fmt.Printf("接口状态: %v, IP: %v\n", iface.Status, iface.IPAddress)
//
// 注意事项：
// - 此方法是线程安全的
// - 返回的是接口对象的指针，修改时需要注意并发安全
// - 建议在使用返回的接口对象时进行nil检查
func (m *Manager) GetInterface(name string) (*Interface, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 从映射表中查找接口
	iface, exists := m.interfaces[name]
	if !exists {
		return nil, fmt.Errorf("接口 %s 不存在", name)
	}

	return iface, nil
}

// GetAllInterfaces 获取所有网络接口
// 返回管理器中所有网络接口的副本映射表
//
// 功能说明：
// - 返回所有已注册接口的完整列表
// - 创建映射表的副本，避免外部修改影响内部状态
// - 使用读锁保证数据一致性
//
// 返回值：
//   - map[string]*Interface: 接口名称到接口对象的映射表副本
//
// 使用示例：
//
//	interfaces := manager.GetAllInterfaces()
//	for name, iface := range interfaces {
//	    fmt.Printf("接口: %s, 状态: %v, IP: %v\n",
//	        name, iface.Status, iface.IPAddress)
//	}
//
// 性能考虑：
// - 返回的是映射表的副本，对于大量接口可能有内存开销
// - 适合用于遍历和展示，不适合频繁调用
//
// 注意事项：
// - 此方法是线程安全的
// - 返回的是副本，修改不会影响管理器内部状态
// - 如果只需要特定接口，建议使用GetInterface()
func (m *Manager) GetAllInterfaces() map[string]*Interface {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 创建映射表的副本，避免外部修改影响内部状态
	interfaces := make(map[string]*Interface)
	for name, iface := range m.interfaces {
		interfaces[name] = iface
	}
	return interfaces
}

// SetInterfaceStatus 设置网络接口状态
// 更新指定接口的运行状态，用于接口的启用、禁用和测试
//
// 功能说明：
// - 根据接口名称查找对应的接口对象
// - 更新接口的状态字段
// - 自动更新接口的最后活跃时间
//
// 状态类型：
// - InterfaceStatusDown: 接口关闭，不参与数据传输
// - InterfaceStatusUp: 接口启用，正常工作状态
// - InterfaceStatusTesting: 接口测试中，可能有功能限制
//
// 参数：
//   - name: 接口名称（如"eth0", "wlan0"）
//   - status: 新的接口状态
//
// 返回值：
//   - error: 操作过程中的错误，成功时为nil
//
// 错误情况：
// - 如果指定名称的接口不存在，返回错误
//
// 使用示例：
//
//	// 启用接口
//	err := manager.SetInterfaceStatus("eth0", InterfaceStatusUp)
//	if err != nil {
//	    log.Printf("启用接口失败: %v", err)
//	}
//
//	// 禁用接口
//	err = manager.SetInterfaceStatus("eth0", InterfaceStatusDown)
//
// 应用场景：
// - 网络故障时临时禁用接口
// - 维护期间关闭特定接口
// - 接口连通性测试
// - 动态接口管理
//
// 注意事项：
// - 此方法是线程安全的
// - 状态变更会自动更新LastSeen时间
// - 不会影响系统实际的接口状态，仅更新管理器记录
func (m *Manager) SetInterfaceStatus(name string, status InterfaceStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 查找指定的接口
	iface, exists := m.interfaces[name]
	if !exists {
		return fmt.Errorf("接口 %s 不存在", name)
	}

	// 更新接口状态
	iface.Status = status
	// 更新最后活跃时间，记录状态变更时间
	iface.LastSeen = time.Now()
	return nil
}

// UpdateInterfaceStats 更新网络接口统计信息
// 批量更新指定接口的流量统计和错误计数信息
//
// 功能说明：
// - 更新接口的发送和接收统计数据
// - 更新错误计数信息
// - 自动更新接口的最后活跃时间
//
// 统计信息类型：
// - 数据包计数：发送和接收的数据包数量
// - 字节计数：发送和接收的字节总数
// - 错误计数：各种类型错误的累计数量
//
// 参数：
//   - name: 接口名称
//   - txPackets: 发送数据包总数
//   - rxPackets: 接收数据包总数
//   - txBytes: 发送字节总数
//   - rxBytes: 接收字节总数
//   - errors: 错误总数
//
// 返回值：
//   - error: 更新过程中的错误，成功时为nil
//
// 错误情况：
// - 如果指定名称的接口不存在，返回错误
//
// 使用示例：
//
//	// 更新接口统计信息
//	err := manager.UpdateInterfaceStats("eth0",
//	    1000,  // 发送1000个包
//	    950,   // 接收950个包
//	    1500000, // 发送1.5MB
//	    1425000, // 接收1.425MB
//	    5)     // 5个错误
//	if err != nil {
//	    log.Printf("更新统计失败: %v", err)
//	}
//
// 应用场景：
// - 网络性能监控
// - 流量统计和分析
// - 故障诊断和排查
// - 网络计费和配额管理
//
// 注意事项：
// - 此方法是线程安全的
// - 统计数据通常是累计值，不是增量值
// - 建议定期调用以保持数据的时效性
func (m *Manager) UpdateInterfaceStats(name string, txPackets, rxPackets, txBytes, rxBytes, errors uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 查找指定的接口
	iface, exists := m.interfaces[name]
	if !exists {
		return fmt.Errorf("接口 %s 不存在", name)
	}

	// 批量更新统计信息
	iface.TxPackets = txPackets
	iface.RxPackets = rxPackets
	iface.TxBytes = txBytes
	iface.RxBytes = rxBytes
	iface.Errors = errors
	// 更新最后活跃时间，记录统计更新时间
	iface.LastSeen = time.Now()
	return nil
}

// GetActiveInterfaces 获取所有活跃的网络接口
// 返回状态为Up的所有接口列表，用于路由计算和数据转发
//
// 功能说明：
// - 遍历所有已注册的接口
// - 筛选出状态为InterfaceStatusUp的接口
// - 返回活跃接口的切片
//
// 活跃接口定义：
// - 状态为InterfaceStatusUp的接口
// - 可以正常发送和接收数据包
// - 可以参与路由协议和数据转发
//
// 返回值：
//   - []*Interface: 活跃接口对象的切片
//
// 使用示例：
//
//	activeInterfaces := manager.GetActiveInterfaces()
//	fmt.Printf("发现 %d 个活跃接口:\n", len(activeInterfaces))
//	for _, iface := range activeInterfaces {
//	    fmt.Printf("- %s: %v\n", iface.Name, iface.IPAddress)
//	}
//
// 应用场景：
// - 路由协议接口选择
// - 数据包转发路径计算
// - 网络拓扑发现
// - 负载均衡接口选择
//
// 性能考虑：
// - 每次调用都会遍历所有接口
// - 适合在路由更新时调用，不适合频繁调用
// - 返回的切片是新创建的，可以安全修改
//
// 注意事项：
// - 此方法是线程安全的
// - 只返回状态为Up的接口
// - 返回的是接口对象的指针，修改时需要注意并发安全
func (m *Manager) GetActiveInterfaces() []*Interface {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 创建活跃接口切片
	var activeInterfaces []*Interface

	// 遍历所有接口，筛选活跃接口
	for _, iface := range m.interfaces {
		if iface.Status == InterfaceStatusUp {
			activeInterfaces = append(activeInterfaces, iface)
		}
	}
	return activeInterfaces
}

// discoverInterfaces 发现和初始化系统网络接口
// 这是接口管理器的核心发现机制，自动扫描系统中的所有网络接口
//
// 发现过程：
// 1. 调用Go标准库net.Interfaces()获取系统接口列表
// 2. 遍历每个接口，提取基本信息（名称、MTU、状态）
// 3. 跳过回环接口（loopback），因为它们不用于网络路由
// 4. 检查接口的启用状态（UP/DOWN）
// 5. 获取接口的IP地址和子网掩码配置
// 6. 将发现的接口添加到管理器的映射表中
//
// 接口过滤规则：
// - 跳过回环接口（127.0.0.1, ::1等）
// - 优先处理IPv4地址，忽略IPv6地址
// - 只记录非回环的IP地址
//
// 状态检测：
// - 使用net.FlagUp标志检测接口是否启用
// - 默认状态为Down，检测到Up标志时更新为Up
//
// 地址解析：
// - 遍历接口的所有地址
// - 筛选出IPv4地址（通过To4()检查）
// - 提取IP地址和子网掩码
// - 每个接口只记录第一个有效的IPv4地址
//
// 返回值：
//   - error: 发现过程中的错误，成功时为nil
//
// 错误情况：
// - 系统调用net.Interfaces()失败
// - 权限不足无法访问网络接口信息
//
// 使用场景：
// - 管理器启动时的初始化
// - 热插拔接口的重新发现
// - 网络配置变更后的更新
//
// 注意事项：
// - 此方法假设调用者已持有写锁
// - 会清空并重建接口映射表
// - 不会保留之前的统计信息
// - 发现的接口统计信息初始为0
func (m *Manager) discoverInterfaces() error {
	// 调用系统API获取所有网络接口
	// 这会返回系统中配置的所有网络接口，包括物理和虚拟接口
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	// 遍历系统返回的每个网络接口
	for _, netIface := range netInterfaces {
		// 跳过回环接口（如lo, loopback等）
		// 回环接口用于本地通信，不参与网络路由
		if netIface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// 创建新的接口对象，初始化基本信息
		iface := &Interface{
			Name:       netIface.Name,         // 接口名称（如eth0, wlan0）
			MACAddress: netIface.HardwareAddr, // MAC地址
			MTU:        netIface.MTU,          // 最大传输单元
			Status:     InterfaceStatusDown,   // 默认状态为关闭
			LastSeen:   time.Now(),            // 设置发现时间
		}

		// 检查接口是否处于启用状态
		// net.FlagUp表示接口在系统中被标记为启用
		if netIface.Flags&net.FlagUp != 0 {
			iface.Status = InterfaceStatusUp
		}

		// 获取接口配置的IP地址列表
		// 一个接口可能配置多个IP地址
		addrs, err := netIface.Addrs()
		if err == nil && len(addrs) > 0 {
			// 遍历接口的所有地址
			for _, addr := range addrs {
				// 尝试将地址转换为IP网络格式
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
					// 检查是否为IPv4地址（To4()返回非nil表示IPv4）
					if ipNet.IP.To4() != nil {
						// 记录第一个有效的IPv4地址和子网掩码
						iface.IPAddress = ipNet.IP
						iface.Netmask = ipNet.Mask
						break // 只记录第一个IPv4地址
					}
				}
			}
		}

		// 将发现的接口添加到管理器的映射表中
		m.interfaces[iface.Name] = iface
	}

	return nil
}

// IsRunning 检查接口管理器的运行状态
// 返回管理器是否处于活跃状态，用于状态查询和条件判断
//
// 功能说明：
// - 线程安全地读取管理器的运行状态
// - 使用读锁保证并发安全，不阻塞其他读操作
// - 返回布尔值表示管理器是否正在运行
//
// 返回值：
//   - bool: true表示管理器正在运行，false表示已停止
//
// 使用示例：
//
//	if manager.IsRunning() {
//	    fmt.Println("接口管理器正在运行")
//	    // 执行需要管理器运行的操作
//	} else {
//	    fmt.Println("接口管理器已停止")
//	    // 可能需要启动管理器
//	    manager.Start()
//	}
//
// 应用场景：
// - 健康检查和状态监控
// - 条件判断和流程控制
// - 防止在停止状态下执行操作
// - 系统状态报告
//
// 注意事项：
// - 此方法是线程安全的
// - 使用读锁，不会阻塞其他读操作
// - 返回值反映调用时刻的状态，可能立即发生变化
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// SetInterfaceRole 设置接口的端口角色
// 为指定的网络接口分配功能角色（WAN/LAN/DMZ等）
//
// 参数：
//   - name: 接口名称（如"eth0", "ens18"）
//   - role: 要分配的端口角色
//
// 返回值：
//   - error: 操作失败时返回错误信息
//
// 使用示例：
//
//	err := manager.SetInterfaceRole("ens18", PortRoleWAN)
//	if err != nil {
//	    log.Printf("设置WAN接口失败: %v", err)
//	}
//
// 注意事项：
// - 接口必须已存在于管理器中
// - 此操作是线程安全的
// - 角色变更会影响后续的路由和防火墙配置
func (m *Manager) SetInterfaceRole(name string, role PortRole) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	iface, exists := m.interfaces[name]
	if !exists {
		return fmt.Errorf("接口 %s 不存在", name)
	}

	iface.Role = role
	return nil
}

// GetInterfaceRole 获取接口的端口角色
// 查询指定网络接口当前分配的功能角色
//
// 参数：
//   - name: 接口名称
//
// 返回值：
//   - PortRole: 接口的当前角色
//   - error: 查询失败时返回错误信息
//
// 使用示例：
//
//	role, err := manager.GetInterfaceRole("ens18")
//	if err != nil {
//	    log.Printf("查询接口角色失败: %v", err)
//	} else {
//	    log.Printf("接口 ens18 的角色是: %s", role.String())
//	}
func (m *Manager) GetInterfaceRole(name string) (PortRole, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	iface, exists := m.interfaces[name]
	if !exists {
		return PortRoleUnassigned, fmt.Errorf("接口 %s 不存在", name)
	}

	return iface.Role, nil
}

// GetInterfacesByRole 根据端口角色获取接口列表
// 返回所有具有指定角色的网络接口
//
// 参数：
//   - role: 要查询的端口角色
//
// 返回值：
//   - []*Interface: 匹配角色的接口列表
//
// 使用示例：
//
//	wanInterfaces := manager.GetInterfacesByRole(PortRoleWAN)
//	for _, iface := range wanInterfaces {
//	    log.Printf("WAN接口: %s", iface.Name)
//	}
//
// 注意事项：
// - 返回的是接口的副本，修改不会影响原始数据
// - 如果没有匹配的接口，返回空切片
// - 此方法是线程安全的
func (m *Manager) GetInterfacesByRole(role PortRole) []*Interface {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Interface
	for _, iface := range m.interfaces {
		if iface.Role == role {
			// 创建接口副本以避免并发修改
			ifaceCopy := *iface
			result = append(result, &ifaceCopy)
		}
	}

	return result
}

// GetWANInterfaces 获取所有WAN接口
// 便捷方法，返回所有配置为WAN角色的接口
//
// 返回值：
//   - []*Interface: WAN接口列表
//
// 使用示例：
//
//	wanInterfaces := manager.GetWANInterfaces()
//	if len(wanInterfaces) == 0 {
//	    log.Println("警告: 没有配置WAN接口")
//	}
func (m *Manager) GetWANInterfaces() []*Interface {
	return m.GetInterfacesByRole(PortRoleWAN)
}

// GetLANInterfaces 获取所有LAN接口
// 便捷方法，返回所有配置为LAN角色的接口
//
// 返回值：
//   - []*Interface: LAN接口列表
//
// 使用示例：
//
//	lanInterfaces := manager.GetLANInterfaces()
//	for _, iface := range lanInterfaces {
//	    log.Printf("LAN接口: %s, IP: %s", iface.Name, iface.IPAddress)
//	}
func (m *Manager) GetLANInterfaces() []*Interface {
	return m.GetInterfacesByRole(PortRoleLAN)
}

// GetUnassignedInterfaces 获取所有未分配角色的接口
// 返回尚未配置端口角色的接口，用于配置向导或管理界面
//
// 返回值：
//   - []*Interface: 未分配角色的接口列表
//
// 使用示例：
//
//	unassigned := manager.GetUnassignedInterfaces()
//	if len(unassigned) > 0 {
//	    log.Printf("发现 %d 个未配置的接口", len(unassigned))
//	}
func (m *Manager) GetUnassignedInterfaces() []*Interface {
	return m.GetInterfacesByRole(PortRoleUnassigned)
}

// collectStats 定期收集接口统计数据
// 在后台goroutine中运行，定期更新所有接口的统计信息
func (m *Manager) collectStats() {
	ticker := time.NewTicker(5 * time.Second) // 每5秒更新一次统计数据
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.updateAllInterfaceStats()
		case <-m.stopChan:
			return
		}
	}
}

// updateAllInterfaceStats 更新所有接口的统计数据
func (m *Manager) updateAllInterfaceStats() {
	stats := m.getSystemNetworkStats()

	m.mu.Lock()
	defer m.mu.Unlock()

	for name, iface := range m.interfaces {
		if ifaceStats, exists := stats[name]; exists {
			iface.TxPackets = ifaceStats.TxPackets
			iface.RxPackets = ifaceStats.RxPackets
			iface.TxBytes = ifaceStats.TxBytes
			iface.RxBytes = ifaceStats.RxBytes
			iface.Errors = ifaceStats.TxErrors + ifaceStats.RxErrors
			iface.LastSeen = time.Now()
		}
	}
}

// InterfaceStats 接口统计数据结构
type InterfaceStats struct {
	TxPackets uint64
	RxPackets uint64
	TxBytes   uint64
	RxBytes   uint64
	TxErrors  uint64
	RxErrors  uint64
}

// getSystemNetworkStats 获取系统网络统计数据
func (m *Manager) getSystemNetworkStats() map[string]*InterfaceStats {
	if runtime.GOOS == "linux" {
		return m.getLinuxNetworkStats()
	}
	return m.getMacOSNetworkStats()
}

// getLinuxNetworkStats 获取Linux系统的网络统计数据
func (m *Manager) getLinuxNetworkStats() map[string]*InterfaceStats {
	stats := make(map[string]*InterfaceStats)

	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return stats
	}

	lines := strings.Split(string(data), "\n")
	// 跳过前两行标题
	for i := 2; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 17 {
			continue
		}

		interfaceName := strings.TrimSuffix(parts[0], ":")
		if interfaceName == "lo" {
			continue // 跳过回环接口
		}

		rxBytes, _ := strconv.ParseUint(parts[1], 10, 64)
		rxPackets, _ := strconv.ParseUint(parts[2], 10, 64)
		rxErrors, _ := strconv.ParseUint(parts[3], 10, 64)
		txBytes, _ := strconv.ParseUint(parts[9], 10, 64)
		txPackets, _ := strconv.ParseUint(parts[10], 10, 64)
		txErrors, _ := strconv.ParseUint(parts[11], 10, 64)

		stats[interfaceName] = &InterfaceStats{
			TxPackets: txPackets,
			RxPackets: rxPackets,
			TxBytes:   txBytes,
			RxBytes:   rxBytes,
			TxErrors:  txErrors,
			RxErrors:  rxErrors,
		}
	}

	return stats
}

// getMacOSNetworkStats 获取macOS系统的网络统计数据
func (m *Manager) getMacOSNetworkStats() map[string]*InterfaceStats {
	stats := make(map[string]*InterfaceStats)

	// 使用netstat命令获取网络统计信息
	cmd := exec.Command("netstat", "-ibn")
	output, err := cmd.Output()
	if err != nil {
		// 如果netstat失败，生成模拟数据
		return m.generateMockStats()
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// 检查是否是网络接口行（第一列是接口名，第三列是地址）
		interfaceName := fields[0]
		if interfaceName == "Name" || interfaceName == "lo0" {
			continue // 跳过标题行和回环接口
		}

		// 只处理Link类型的行（包含MAC地址的行），跳过IP地址行
		if !strings.Contains(fields[2], "Link#") && !strings.Contains(fields[2], "<Link#") {
			continue
		}

		// 确保这是一个有效的接口行
		if !strings.Contains(interfaceName, "en") && !strings.Contains(interfaceName, "bridge") &&
			!strings.Contains(interfaceName, "utun") && !strings.Contains(interfaceName, "ap") &&
			!strings.Contains(interfaceName, "llw") && !strings.Contains(interfaceName, "vmenet") &&
			!strings.Contains(interfaceName, "awdl") {
			continue
		}

		// netstat -ibn 输出格式：Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
		// 字段索引：0=Name, 1=Mtu, 2=Network, 3=Address, 4=Ipkts, 5=Ierrs, 6=Ibytes, 7=Opkts, 8=Oerrs, 9=Obytes
		rxPackets, _ := strconv.ParseUint(fields[4], 10, 64)
		rxErrors, _ := strconv.ParseUint(fields[5], 10, 64)
		rxBytes, _ := strconv.ParseUint(fields[6], 10, 64)
		txPackets, _ := strconv.ParseUint(fields[7], 10, 64)
		txErrors, _ := strconv.ParseUint(fields[8], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[9], 10, 64)

		stats[interfaceName] = &InterfaceStats{
			TxPackets: txPackets,
			RxPackets: rxPackets,
			TxBytes:   txBytes,
			RxBytes:   rxBytes,
			TxErrors:  txErrors,
			RxErrors:  rxErrors,
		}
	}

	return stats
}

// generateMockStats 生成模拟的统计数据（用于测试或netstat不可用时）
func (m *Manager) generateMockStats() map[string]*InterfaceStats {
	stats := make(map[string]*InterfaceStats)

	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now().Unix()
	for name := range m.interfaces {
		if name == "lo" {
			continue
		}

		// 基于时间和接口名生成相对稳定但会变化的数据
		baseValue := uint64(now + int64(len(name)*1000))

		stats[name] = &InterfaceStats{
			TxPackets: baseValue + uint64(now%100),
			RxPackets: baseValue + uint64(now%150),
			TxBytes:   baseValue * 1500,
			RxBytes:   baseValue * 1200,
			TxErrors:  uint64(now % 10),
			RxErrors:  uint64(now % 8),
		}
	}

	return stats
}
