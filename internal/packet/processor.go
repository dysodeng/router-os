package packet

import (
	"fmt"
	"net"
	"sync"
	"time"

	"router-os/internal/interfaces"
	"router-os/internal/routing"
)

// PacketType 数据包类型枚举
// 在网络中，不同类型的数据包需要不同的处理方式
type PacketType int

const (
	// PacketTypeIPv4 IPv4数据包
	// 这是目前互联网上最常用的IP协议版本
	// 特点：32位地址，支持约43亿个地址
	PacketTypeIPv4 PacketType = iota
	
	// PacketTypeIPv6 IPv6数据包  
	// 下一代IP协议，解决IPv4地址不足问题
	// 特点：128位地址，支持几乎无限的地址空间
	PacketTypeIPv6
	
	// PacketTypeARP ARP协议数据包
	// 地址解析协议，用于将IP地址解析为MAC地址
	// 工作在数据链路层，是IP通信的基础
	PacketTypeARP
	
	// PacketTypeICMP ICMP协议数据包
	// 互联网控制消息协议，用于网络诊断和错误报告
	// 例如：ping命令使用的就是ICMP协议
	PacketTypeICMP
)

// Packet 数据包结构体
// 这是网络中传输的基本数据单元的抽象表示
// 类比：就像邮件系统中的一封信，包含发件人、收件人、内容等信息
type Packet struct {
	// Type 数据包类型
	// 标识这个数据包使用的协议类型，决定了如何处理这个数据包
	Type PacketType
	
	// Source 源IP地址
	// 数据包的发送方IP地址，用于回复和统计
	// 类比：信件上的发件人地址
	Source net.IP
	
	// Destination 目标IP地址  
	// 数据包要到达的目的地IP地址，这是路由决策的关键
	// 类比：信件上的收件人地址
	Destination net.IP
	
	// Data 数据包载荷
	// 实际要传输的数据内容，可能是HTTP请求、文件数据等
	// 类比：信件的内容
	Data []byte
	
	// Size 数据包大小（字节）
	// 用于MTU检查和流量统计
	// 如果超过接口MTU，需要进行分片处理
	Size int
	
	// Timestamp 数据包时间戳
	// 记录数据包的创建或接收时间，用于调试和性能分析
	Timestamp time.Time
	
	// InInterface 入接口名称
	// 数据包从哪个网络接口进入路由器
	// 用于防环和策略路由
	InInterface string
	
	// TTL 生存时间（Time To Live）
	// 防止数据包在网络中无限循环的机制
	// 每经过一个路由器就减1，减到0时丢弃数据包
	// IPv4中叫TTL，IPv6中叫Hop Limit，作用相同
	TTL int
}

// Processor 数据包处理器
// 这是路由器的核心组件，负责处理所有经过路由器的数据包
// 类比：就像邮局的分拣中心，决定每个包裹的去向
type Processor struct {
	// routingTable 路由表引用
	// 用于查找数据包的转发路径
	routingTable routing.RoutingTableInterface
	
	// interfaceManager 接口管理器引用
	// 用于获取网络接口信息和状态
	interfaceManager *interfaces.Manager
	
	// running 处理器运行状态
	// 标识处理器是否正在运行，用于控制数据包处理
	running bool
	
	// mu 读写互斥锁
	// 保护并发访问时的数据一致性
	mu sync.RWMutex

	// 以下是统计信息，用于监控和调试
	
	// packetsProcessed 已处理的数据包总数
	// 包括转发的和本地交付的数据包
	packetsProcessed uint64
	
	// packetsForwarded 已转发的数据包数量
	// 经过路由器转发到其他网络的数据包
	packetsForwarded uint64
	
	// packetsDropped 已丢弃的数据包数量
	// 由于各种原因（TTL过期、无路由、接口down等）被丢弃的数据包
	packetsDropped uint64
	
	// packetsReceived 已接收的数据包总数
	// 从所有接口接收到的数据包总数
	packetsReceived uint64
}

// NewProcessor 创建新的数据包处理器
func NewProcessor(routingTable routing.RoutingTableInterface, interfaceManager *interfaces.Manager) *Processor {
	return &Processor{
		routingTable:     routingTable,
		interfaceManager: interfaceManager,
		running:          false,
	}
}

// Start 启动数据包处理器
func (p *Processor) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return fmt.Errorf("数据包处理器已经在运行")
	}

	p.running = true
	return nil
}

// Stop 停止数据包处理器
func (p *Processor) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running = false
}

// ProcessPacket 处理数据包的主要入口函数
// 这是路由器数据包处理的核心流程，实现了完整的IP转发逻辑
//
// 数据包处理流程（按照RFC 1812标准）：
// 1. 接收统计：记录接收到的数据包
// 2. 状态检查：确认处理器正在运行
// 3. TTL检查：防止数据包无限循环
// 4. TTL递减：每经过一个路由器TTL减1
// 5. 目标判断：检查是否为本地目标
// 6. 路由决策：查找转发路径或本地交付
//
// 参数：
//   - packet *Packet: 要处理的数据包指针
//
// 返回值：
//   - error: 处理成功返回nil，失败返回具体错误信息
//
// 可能的处理结果：
//   - 本地交付：目标是路由器自身的IP地址
//   - 转发：目标是其他网络，需要查找路由并转发
//   - 丢弃：TTL过期、无路由、接口故障等原因
//
// 使用示例：
//   packet := processor.CreatePacket(PacketTypeIPv4, 
//       net.ParseIP("192.168.1.100"), 
//       net.ParseIP("10.0.0.1"), 
//       []byte("Hello"), "eth0")
//   err := processor.ProcessPacket(packet)
//   if err != nil {
//       log.Printf("数据包处理失败: %v", err)
//   }
func (p *Processor) ProcessPacket(packet *Packet) error {
	// 第一步：更新接收统计
	// 使用锁保护统计数据的并发安全
	p.mu.Lock()
	p.packetsReceived++
	p.mu.Unlock()

	// 第二步：检查处理器状态
	// 如果处理器未运行，拒绝处理数据包
	// 这通常发生在系统启动或关闭过程中
	if !p.IsRunning() {
		return fmt.Errorf("数据包处理器未运行")
	}

	// 第三步：TTL检查（防环机制）
	// TTL（Time To Live）是防止数据包在网络中无限循环的重要机制
	// 当TTL为0或负数时，说明数据包已经经过了太多跳，可能存在路由环路
	if packet.TTL <= 0 {
		// 更新丢弃统计
		p.mu.Lock()
		p.packetsDropped++
		p.mu.Unlock()
		
		// 在真实实现中，这里应该发送ICMP Time Exceeded消息给源地址
		// 告知发送方数据包因TTL过期而被丢弃
		return fmt.Errorf("数据包TTL过期")
	}

	// 第四步：TTL递减
	// 根据RFC 791，每个路由器在转发数据包时都必须将TTL减1
	// 这确保了数据包不会在网络中无限循环
	packet.TTL--

	// 第五步：目标地址判断
	// 检查数据包的目标地址是否是路由器自身的IP地址
	// 如果是，则进行本地交付；如果不是，则需要转发
	if p.isLocalDestination(packet.Destination) {
		// 目标是本地地址，交付给上层协议栈处理
		// 例如：ping路由器、SSH连接路由器、SNMP管理等
		return p.deliverLocally(packet)
	}

	// 第六步：转发数据包
	// 目标不是本地地址，需要查找路由表并转发到下一跳
	// 这是路由器最主要的功能
	return p.forwardPacket(packet)
}

// forwardPacket 转发数据包到下一跳
// 这是路由器转发功能的核心实现，负责查找路由并将数据包发送到正确的下一跳
//
// 转发过程详解：
// 1. 路由查找：在路由表中查找到目标网络的最佳路径
// 2. 接口获取：获取出接口的详细信息和状态
// 3. 状态检查：验证出接口是否可用
// 4. MTU检查：确保数据包大小不超过接口最大传输单元
// 5. 数据发送：将数据包发送到下一跳
// 6. 统计更新：更新转发统计信息
//
// 路由查找算法：
//   - 使用最长前缀匹配（Longest Prefix Match, LPM）
//   - 优先选择更具体的路由（子网掩码更长）
//   - 如果有多个相同长度的路由，选择度量值最小的
//
// MTU处理：
//   - 如果数据包大小超过出接口MTU，需要进行IP分片
//   - 当前实现为简化处理，直接丢弃超大数据包
//   - 生产环境中应实现RFC 791定义的IP分片机制
//
// 参数：
//   - packet *Packet: 要转发的数据包
//
// 返回值：
//   - error: 转发成功返回nil，失败返回错误信息
//
// 可能的失败原因：
//   - 无路由：路由表中没有到目标网络的路径
//   - 接口故障：出接口不可用或状态为down
//   - MTU超限：数据包大小超过接口MTU
//   - 发送失败：底层网络发送错误
//
// 使用示例：
//   // 假设要转发到10.0.0.1的数据包
//   // 路由表中有条目：10.0.0.0/24 via 192.168.1.1 dev eth0
//   err := processor.forwardPacket(packet)
//   if err != nil {
//       log.Printf("转发失败: %v", err)
//   }
func (p *Processor) forwardPacket(packet *Packet) error {
	// 第一步：路由查找
	// 在路由表中查找到目标IP地址的最佳路由
	// 使用最长前缀匹配算法，确保选择最具体的路由
	// 路由表查找是O(log n)复杂度，使用前缀树或类似数据结构优化
	route, err := p.routingTable.LookupRoute(packet.Destination)
	if err != nil {
		// 更新丢弃统计
		p.mu.Lock()
		p.packetsDropped++
		p.mu.Unlock()
		
		// 在真实实现中，这里应该发送ICMP Destination Unreachable消息
		// 告知源主机目标网络不可达
		return fmt.Errorf("未找到路由: %v", err)
	}

	// 第二步：获取出接口信息
	// 根据路由表条目获取对应的网络接口详细信息
	// 包括接口状态、MTU、IP地址等关键参数
	outInterface, err := p.interfaceManager.GetInterface(route.Interface)
	if err != nil {
		// 接口不存在或获取失败
		p.mu.Lock()
		p.packetsDropped++
		p.mu.Unlock()
		return fmt.Errorf("获取出接口失败: %v", err)
	}

	// 第三步：检查接口状态
	// 只有状态为UP的接口才能发送数据包
	// 接口可能因为链路故障、管理员禁用等原因处于DOWN状态
	if outInterface.Status != interfaces.InterfaceStatusUp {
		// 接口未启用，无法发送数据包
		p.mu.Lock()
		p.packetsDropped++
		p.mu.Unlock()
		return fmt.Errorf("出接口 %s 未启用", route.Interface)
	}

	// 第四步：MTU检查
	// 最大传输单元（MTU）检查，防止发送超大数据包
	// 以太网标准MTU为1500字节，其他介质可能不同
	if packet.Size > outInterface.MTU {
		// 数据包超过MTU限制
		// 在完整实现中，这里应该进行IP分片处理
		// 将大数据包分割成多个小于MTU的片段
		// 当前为简化实现，直接丢弃超大数据包
		p.mu.Lock()
		p.packetsDropped++
		p.mu.Unlock()
		return fmt.Errorf("数据包大小 %d 超过接口MTU %d", packet.Size, outInterface.MTU)
	}

	// 第五步：发送数据包
	// 调用底层发送函数，将数据包通过指定接口发送到下一跳
	// 这里会进行ARP解析（如果需要）和二层封装
	if err := p.sendPacket(packet, outInterface, route.Gateway); err != nil {
		// 发送失败，可能是网络拥塞、ARP解析失败等原因
		p.mu.Lock()
		p.packetsDropped++
		p.mu.Unlock()
		return fmt.Errorf("发送数据包失败: %v", err)
	}

	// 第六步：更新统计信息
	// 成功转发数据包后，更新相关的统计计数器
	// 这些统计信息用于网络监控和故障诊断
	p.mu.Lock()
	p.packetsProcessed++  // 总处理数据包数
	p.packetsForwarded++ // 成功转发数据包数
	p.mu.Unlock()

	return nil
}

// sendPacket 发送数据包到下一跳（模拟实现）
// 这个函数模拟了真实路由器发送数据包的完整过程
//
// 真实发送过程包括：
// 1. ARP解析：将下一跳IP地址解析为MAC地址
// 2. 二层封装：添加以太网帧头（源MAC、目标MAC、类型）
// 3. 物理发送：通过网络接口卡发送到物理介质
// 4. 错误处理：处理发送过程中的各种错误
//
// ARP（Address Resolution Protocol）过程：
//   - 检查ARP缓存中是否有下一跳IP对应的MAC地址
//   - 如果没有，发送ARP请求广播询问MAC地址
//   - 等待ARP回复并缓存结果
//   - 使用获得的MAC地址进行二层封装
//
// 二层封装格式（以太网）：
//   [目标MAC][源MAC][类型][IP数据包][FCS校验]
//
// 参数：
//   - packet *Packet: 要发送的数据包
//   - outInterface *interfaces.Interface: 出接口信息
//   - nextHop net.IP: 下一跳IP地址
//
// 返回值：
//   - error: 发送成功返回nil，失败返回错误信息
//
// 注意：当前为模拟实现，真实环境需要：
//   - 实现ARP协议栈
//   - 处理网络接口的底层操作
//   - 实现重传和错误恢复机制
func (p *Processor) sendPacket(packet *Packet, outInterface *interfaces.Interface, nextHop net.IP) error {
	// 模拟ARP解析过程
	// 在真实实现中，这里需要：
	// 1. 查询ARP缓存表
	// 2. 如果缓存未命中，发送ARP请求
	// 3. 等待ARP回复或超时
	
	// 模拟二层封装过程
	// 在真实实现中，这里需要：
	// 1. 构造以太网帧头
	// 2. 设置源MAC为出接口MAC地址
	// 3. 设置目标MAC为下一跳MAC地址
	// 4. 设置以太网类型（IPv4为0x0800）
	
	// 模拟物理发送过程
	// 在真实实现中，这里需要：
	// 1. 调用网络接口驱动程序
	// 2. 将数据包放入发送队列
	// 3. 处理发送完成中断
	// 4. 更新接口统计信息
	
	// 更新接口统计信息
	// 记录通过此接口发送的数据包和字节数
	// 这些统计信息用于网络监控和性能分析
	p.interfaceManager.UpdateInterfaceStats(
		outInterface.Name,
		outInterface.TxPackets+1,
		outInterface.RxPackets,
		outInterface.TxBytes+uint64(packet.Size),
		outInterface.RxBytes,
		outInterface.Errors,
	)

	// 在真实实现中，这里可能返回的错误包括：
	// - ARP解析超时
	// - 接口发送队列满
	// - 网络介质错误
	// - 接口硬件故障
	return nil
}

// deliverLocally 本地交付数据包
// 当数据包的目标地址是路由器自身时，需要将数据包交付给本地的上层协议栈处理
//
// 本地交付过程：
// 1. 协议识别：根据IP头中的协议字段确定上层协议
// 2. 端口分发：根据传输层端口号分发给相应的应用程序
// 3. 数据传递：将数据传递给应用层处理
// 4. 统计更新：更新本地交付的统计信息
//
// 常见的本地交付场景：
//   - ICMP消息：ping、traceroute等网络诊断工具
//   - 路由协议：OSPF、BGP等路由协议报文
//   - 管理协议：SNMP、SSH、Telnet等管理连接
//   - 应用服务：Web服务器、DNS服务器等
//
// 协议分发示例：
//   - 协议号1（ICMP）：交付给ICMP处理模块
//   - 协议号6（TCP）：交付给TCP协议栈
//   - 协议号17（UDP）：交付给UDP协议栈
//   - 协议号89（OSPF）：交付给OSPF路由协议
//
// 参数：
//   - packet *Packet: 要本地交付的数据包
//
// 返回值：
//   - error: 交付成功返回nil，失败返回错误信息
//
// 使用示例：
//   // 当收到目标为路由器IP的ping包时
//   // 系统会调用deliverLocally进行本地交付
//   // ICMP模块会生成ping回复并发送回源地址
func (p *Processor) deliverLocally(packet *Packet) error {
	// 模拟协议识别和分发过程
	// 在真实实现中，这里需要：
	// 1. 解析IP头中的协议字段
	// 2. 根据协议类型调用相应的处理函数
	// 3. 对于TCP/UDP，还需要解析端口号
	// 4. 将数据传递给相应的应用程序或系统服务
	
	// 更新统计信息
	// 记录成功处理的数据包数量
	// 这些统计信息对于网络监控和故障诊断很重要
	p.mu.Lock()
	p.packetsProcessed++
	p.mu.Unlock()

	// 在真实实现中，可能的错误包括：
	// - 未知协议类型
	// - 端口未监听
	// - 应用程序缓冲区满
	// - 权限不足
	return nil
}

// isLocalDestination 检查是否是本地目标
func (p *Processor) isLocalDestination(destination net.IP) bool {
	interfaces := p.interfaceManager.GetAllInterfaces()

	for _, iface := range interfaces {
		if iface.IPAddress != nil && iface.IPAddress.Equal(destination) {
			return true
		}
	}

	return false
}

// CreatePacket 创建数据包
func (p *Processor) CreatePacket(packetType PacketType, source, destination net.IP, data []byte, inInterface string) *Packet {
	return &Packet{
		Type:        packetType,
		Source:      source,
		Destination: destination,
		Data:        data,
		Size:        len(data),
		Timestamp:   time.Now(),
		InInterface: inInterface,
		TTL:         64, // 默认TTL
	}
}

// GetStats 获取统计信息
func (p *Processor) GetStats() (uint64, uint64, uint64, uint64) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.packetsReceived, p.packetsProcessed, p.packetsForwarded, p.packetsDropped
}

// IsRunning 检查处理器是否在运行
func (p *Processor) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

// ResetStats 重置统计信息
func (p *Processor) ResetStats() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.packetsReceived = 0
	p.packetsProcessed = 0
	p.packetsForwarded = 0
	p.packetsDropped = 0
}
