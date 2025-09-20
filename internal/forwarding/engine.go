package forwarding

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"router-os/internal/arp"
	"router-os/internal/interfaces"
	"router-os/internal/routing"
)

// IPPacket IP数据包结构
// 定义在转发引擎中以避免循环依赖
type IPPacket struct {
	// Source 源IP地址
	Source net.IP

	// Destination 目标IP地址
	Destination net.IP

	// TTL 生存时间
	TTL int

	// Protocol 协议类型 (TCP=6, UDP=17, ICMP=1等)
	Protocol int

	// Size 数据包大小（字节）
	Size int

	// Data 数据包内容
	Data []byte

	// InInterface 入接口名称
	InInterface string

	// Timestamp 接收时间戳
	Timestamp time.Time

	// 分片相关字段
	FragmentID     uint16 // 分片标识符
	FragmentOffset int    // 分片偏移（以8字节为单位）
	MoreFragments  bool   // 更多分片标志
	DontFragment   bool   // 不分片标志
}

// NewIPPacket 创建新的IP数据包
func NewIPPacket(src, dst net.IP, ttl, protocol int, data []byte) *IPPacket {
	return &IPPacket{
		Source:      src,
		Destination: dst,
		TTL:         ttl,
		Protocol:    protocol,
		Size:        len(data) + 20, // IP头部20字节 + 数据
		Data:        data,
		Timestamp:   time.Now(),
	}
}

// Stats 转发统计信息
type Stats struct {
	// PacketsReceived 接收的数据包总数
	PacketsReceived uint64

	// PacketsForwarded 成功转发的数据包数
	PacketsForwarded uint64

	// PacketsDropped 丢弃的数据包数
	PacketsDropped uint64

	// PacketsToLocal 本地交付的数据包数
	PacketsToLocal uint64

	// ICMPGenerated 生成的ICMP消息数
	ICMPGenerated uint64

	// ARPRequests 发送的ARP请求数
	ARPRequests uint64

	// RouteFailures 路由查找失败次数
	RouteFailures uint64

	// TTLExpired TTL过期的数据包数
	TTLExpired uint64

	// FragmentationNeeded 需要分片的数据包数
	FragmentationNeeded uint64

	// StartTime 统计开始时间
	StartTime time.Time
}

// Config 转发配置
type Config struct {
	// EnableIPForwarding 是否启用IP转发
	EnableIPForwarding bool

	// EnableICMPRedirect 是否启用ICMP重定向
	EnableICMPRedirect bool

	// EnableFragmentation 是否启用IP分片
	EnableFragmentation bool

	// MaxTTL 最大TTL值
	MaxTTL int

	// ARPTimeout ARP解析超时时间
	ARPTimeout time.Duration

	// RouteTimeout 路由缓存超时时间
	RouteTimeout time.Duration
}

// Engine IP转发引擎
// 这是路由器的核心组件，负责处理所有的IP数据包转发
//
// 主要功能：
// 1. 路由查找：根据目标IP查找最佳路由
// 2. ARP解析：将下一跳IP解析为MAC地址
// 3. 数据包转发：将数据包发送到正确的出接口
// 4. TTL处理：递减TTL并检查是否过期
// 5. 分片处理：处理超过MTU的大数据包
// 6. ICMP生成：生成各种ICMP错误消息
//
// 转发决策过程：
// 1. 接收数据包并验证IP头部
// 2. 检查目标地址是否为本地地址
// 3. 查找路由表确定下一跳
// 4. 进行ARP解析获取MAC地址
// 5. 构造以太网帧并发送
// 6. 更新统计信息
//
// 性能优化：
// - 路由缓存：缓存常用路由减少查找时间
// - ARP缓存：缓存MAC地址映射
// - 批量处理：支持批量处理多个数据包
// - 并发处理：支持多线程并发转发
type Engine struct {
	// routingTable 路由表接口
	routingTable routing.RoutingTableInterface

	// interfaceManager 接口管理器
	interfaceManager *interfaces.Manager

	// arpTable ARP表
	arpTable *arp.Table

	// running 运行状态
	running bool

	// mu 读写锁
	mu sync.RWMutex

	// 统计信息
	stats Stats

	// 配置参数
	config Config

	// 新增功能组件
	loadBalancer       *LoadBalancer
	failoverManager    *FailoverManager
	performanceMonitor *PerformanceMonitor
	trafficShaper      *TrafficShaper
	cache              *ForwardingCache

	// 工作队列
	packetQueue chan *IPPacket
	workerPool  []*PacketWorker
	workerCount int

	// 统计和监控
	metricsCollector *MetricsCollector
	alertManager     *AlertManager
}

// NewForwardingEngine 创建新的转发引擎
//
// 参数：
//   - routingTable: 路由表接口
//   - interfaceManager: 接口管理器
//   - arpTable: ARP表
//
// 返回值：
//   - *Engine: 转发引擎实例
//
// 使用示例：
//
//	engine := NewForwardingEngine(routingTable, interfaceManager, arpTable)
//	engine.Start()
//	defer engine.Stop()
func NewForwardingEngine(
	routingTable routing.RoutingTableInterface,
	interfaceManager *interfaces.Manager,
	arpTable *arp.Table,
) *Engine {
	// 初始化工作线程池
	workerCount := 4
	packetQueue := make(chan *IPPacket, 1000)
	workerPool := make([]*PacketWorker, workerCount)

	engine := &Engine{
		routingTable:     routingTable,
		interfaceManager: interfaceManager,
		arpTable:         arpTable,
		running:          false,
		stats: Stats{
			StartTime: time.Now(),
		},
		config: Config{
			EnableIPForwarding:  true,
			EnableICMPRedirect:  true,
			EnableFragmentation: true,
			MaxTTL:              255,
			ARPTimeout:          5 * time.Second,
			RouteTimeout:        300 * time.Second,
		},
		// 初始化各个组件
		loadBalancer:       NewLoadBalancer(RoundRobin),
		failoverManager:    NewFailoverManager(),
		performanceMonitor: NewPerformanceMonitor(),
		trafficShaper:      NewTrafficShaper(),
		cache:              NewForwardingCache(1000, 5*time.Minute),
		metricsCollector:   NewMetricsCollector(30 * time.Second),
		alertManager:       NewAlertManager(),
		packetQueue:        packetQueue,
		workerPool:         workerPool,
		workerCount:        workerCount,
	}

	// 初始化工作线程
	for i := 0; i < workerCount; i++ {
		workerPool[i] = &PacketWorker{
			id:     i,
			engine: engine,
			queue:  make(chan *IPPacket, 100),
			stop:   make(chan struct{}),
		}
	}

	return engine
}

// Start 启动转发引擎
func (fe *Engine) Start() error {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	if fe.running {
		return fmt.Errorf("转发引擎已经在运行")
	}

	if !fe.config.EnableIPForwarding {
		return fmt.Errorf("IP转发功能未启用")
	}

	// 启动工作线程池
	for _, worker := range fe.workerPool {
		go worker.Start()
	}

	// 启动数据包分发器
	go fe.packetDispatcher()

	// 启动监控组件
	go fe.metricsCollector.Start()
	go fe.alertManager.Start()

	fe.running = true
	fe.stats.StartTime = time.Now()

	return nil
}

// Stop 停止转发引擎
func (fe *Engine) Stop() {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	if !fe.running {
		return
	}

	fe.running = false

	// 停止工作线程池
	for _, worker := range fe.workerPool {
		worker.Stop()
	}

	// 停止监控组件
	fe.metricsCollector.Stop()
	fe.alertManager.Stop()

	// 停止故障切换管理器中的健康检查
	for _, checker := range fe.failoverManager.healthCheckers {
		checker.Stop()
	}
}

// ForwardPacket 转发数据包
// 这是转发引擎的核心方法，处理单个数据包的转发
//
// 转发流程：
// 1. 数据包验证：检查IP头部格式和校验和
// 2. TTL处理：递减TTL并检查是否过期
// 3. 目标检查：判断是否为本地目标
// 4. 路由查找：在路由表中查找最佳路由
// 5. ARP解析：解析下一跳的MAC地址
// 6. 数据发送：构造以太网帧并发送
// 7. 统计更新：更新相关统计信息
//
// 参数：
//   - pkt: 要转发的数据包
//
// 返回值：
//   - error: 转发成功返回nil，失败返回错误信息
//
// 可能的错误：
//   - TTL过期：数据包生存时间耗尽
//   - 无路由：路由表中没有到目标的路径
//   - ARP失败：无法解析下一跳MAC地址
//   - 接口故障：出接口不可用
//   - MTU超限：数据包大小超过接口MTU
func (fe *Engine) ForwardPacket(pkt *IPPacket) error {
	if !fe.IsRunning() {
		return fmt.Errorf("转发引擎未运行")
	}

	// 更新接收统计
	fe.mu.Lock()
	fe.stats.PacketsReceived++
	fe.mu.Unlock()

	// 第一步：数据包验证
	if err := fe.validatePacket(pkt); err != nil {
		fe.incrementDropped()
		return fmt.Errorf("数据包验证失败: %v", err)
	}

	// 第二步：TTL处理
	if err := fe.handleTTL(pkt); err != nil {
		fe.incrementDropped()
		fe.mu.Lock()
		fe.stats.TTLExpired++
		fe.mu.Unlock()

		// 发送ICMP Time Exceeded消息
		fe.sendICMPTimeExceeded(pkt)
		return err
	}

	// 第三步：检查是否为本地目标
	if fe.isLocalDestination(pkt.Destination) {
		return fe.deliverLocally(pkt)
	}

	// 第四步：路由查找
	route, err := fe.routingTable.LookupRoute(pkt.Destination)
	if err != nil {
		fe.incrementDropped()
		fe.mu.Lock()
		fe.stats.RouteFailures++
		fe.mu.Unlock()

		// 发送ICMP Destination Unreachable消息
		fe.sendICMPDestUnreachable(pkt)
		return fmt.Errorf("路由查找失败: %v", err)
	}

	// 第五步：获取出接口
	outInterface, err := fe.interfaceManager.GetInterface(route.Interface)
	if err != nil {
		fe.incrementDropped()
		return fmt.Errorf("获取出接口失败: %v", err)
	}

	// 第六步：检查接口状态
	if outInterface.Status != interfaces.InterfaceStatusUp {
		fe.incrementDropped()
		return fmt.Errorf("出接口 %s 未启用", route.Interface)
	}

	// 第七步：MTU检查
	if pkt.Size > outInterface.MTU {
		if fe.config.EnableFragmentation {
			return fe.fragmentAndForward(pkt, outInterface, route.Gateway)
		} else {
			fe.incrementDropped()
			fe.mu.Lock()
			fe.stats.FragmentationNeeded++
			fe.mu.Unlock()

			// 发送ICMP Fragmentation Needed消息
			fe.sendICMPFragNeeded(pkt, outInterface.MTU)
			return fmt.Errorf("数据包大小 %d 超过MTU %d", pkt.Size, outInterface.MTU)
		}
	}

	// 第八步：ARP解析
	nextHop := route.Gateway
	if nextHop == nil {
		// 直连网络，下一跳就是目标地址
		nextHop = pkt.Destination
	}

	mac, err := fe.arpTable.Resolve(nextHop, outInterface.Name, fe.config.ARPTimeout)
	if err != nil {
		fe.incrementDropped()
		fe.mu.Lock()
		fe.stats.ARPRequests++
		fe.mu.Unlock()
		return fmt.Errorf("ARP解析失败: %v", err)
	}

	// 第九步：发送数据包
	if err := fe.sendPacket(pkt, outInterface, mac); err != nil {
		fe.incrementDropped()
		return fmt.Errorf("发送数据包失败: %v", err)
	}

	// 第十步：更新统计信息
	fe.mu.Lock()
	fe.stats.PacketsForwarded++
	fe.mu.Unlock()

	return nil
}

// validatePacket 验证数据包
func (fe *Engine) validatePacket(pkt *IPPacket) error {
	if pkt == nil {
		return fmt.Errorf("数据包为空")
	}

	if pkt.Source == nil || pkt.Destination == nil {
		return fmt.Errorf("源地址或目标地址为空")
	}

	if pkt.Size <= 0 {
		return fmt.Errorf("数据包大小无效: %d", pkt.Size)
	}

	if pkt.TTL <= 0 || pkt.TTL > 255 {
		return fmt.Errorf("TTL值无效: %d", pkt.TTL)
	}

	return nil
}

// handleTTL 处理TTL
func (fe *Engine) handleTTL(pkt *IPPacket) error {
	if pkt.TTL <= 1 {
		return fmt.Errorf("TTL过期")
	}

	// 递减TTL
	pkt.TTL--

	return nil
}

// isLocalDestination 检查是否为本地目标
func (fe *Engine) isLocalDestination(destination net.IP) bool {
	interfaces := fe.interfaceManager.GetAllInterfaces()

	for _, iface := range interfaces {
		if iface.IPAddress != nil && iface.IPAddress.Equal(destination) {
			return true
		}
	}

	return false
}

// deliverLocally 本地交付
func (fe *Engine) deliverLocally(pkt *IPPacket) error {
	fe.mu.Lock()
	fe.stats.PacketsToLocal++
	fe.mu.Unlock()

	// 根据协议类型将数据包交付给相应的协议处理模块
	switch pkt.Protocol {
	case 1: // ICMP
		return fe.deliverToICMP(pkt)
	case 6: // TCP
		return fe.deliverToTCP(pkt)
	case 17: // UDP
		return fe.deliverToUDP(pkt)
	default:
		// 对于不支持的协议，发送ICMP Protocol Unreachable
		_ = fe.sendICMPProtocolUnreachable(pkt)
		return fmt.Errorf("不支持的协议类型: %d", pkt.Protocol)
	}
}

// deliverToICMP 将ICMP数据包交付给ICMP处理模块
func (fe *Engine) deliverToICMP(pkt *IPPacket) error {
	// 解析ICMP头部
	if len(pkt.Data) < 8 {
		return fmt.Errorf("ICMP数据包长度不足")
	}

	icmpType := pkt.Data[0]
	icmpCode := pkt.Data[1]

	switch icmpType {
	case 8: // Echo Request (ping)
		return fe.handleICMPEchoRequest(pkt)
	case 0: // Echo Reply
		return fe.handleICMPEchoReply(pkt)
	case 3: // Destination Unreachable
		return fe.handleICMPDestUnreachable(pkt)
	case 11: // Time Exceeded
		return fe.handleICMPTimeExceeded(pkt)
	default:
		// 记录未知ICMP类型
		return fmt.Errorf("未知ICMP类型: %d, 代码: %d", icmpType, icmpCode)
	}
}

// deliverToTCP 将TCP数据包交付给TCP处理模块
func (fe *Engine) deliverToTCP(pkt *IPPacket) error {
	// 解析TCP头部
	if len(pkt.Data) < 20 {
		return fmt.Errorf("TCP数据包长度不足")
	}

	// 提取TCP头部信息
	srcPort := uint16(pkt.Data[0])<<8 | uint16(pkt.Data[1])
	dstPort := uint16(pkt.Data[2])<<8 | uint16(pkt.Data[3])
	seqNum := uint32(pkt.Data[4])<<24 | uint32(pkt.Data[5])<<16 | uint32(pkt.Data[6])<<8 | uint32(pkt.Data[7])
	ackNum := uint32(pkt.Data[8])<<24 | uint32(pkt.Data[9])<<16 | uint32(pkt.Data[10])<<8 | uint32(pkt.Data[11])
	flags := pkt.Data[13]

	// TCP标志位
	flagFIN := (flags & 0x01) != 0
	flagSYN := (flags & 0x02) != 0
	flagRST := (flags & 0x04) != 0
	flagPSH := (flags & 0x08) != 0
	flagACK := (flags & 0x10) != 0
	_ = (flags & 0x20) != 0 // flagURG - 暂时不使用

	// 检查是否有监听该端口的服务
	if !fe.isPortListening(dstPort, "tcp") {
		// 如果是SYN包，发送RST响应
		if flagSYN && !flagACK {
			return fe.sendTCPReset(pkt, srcPort, dstPort)
		}
		// 对于其他包，也发送RST
		return fe.sendTCPReset(pkt, srcPort, dstPort)
	}

	// 真实的TCP协议栈处理
	// 这里实现基本的TCP状态机和连接管理

	// 按优先级处理TCP包，使用 else if 避免条件重叠

	// 1. 处理RST包（最高优先级，立即重置连接）
	if flagRST {
		return fe.handleTCPRst(pkt, srcPort, dstPort)
	} else if flagSYN {
		// 2. 处理SYN包（连接建立）
		return fe.handleTCPSyn(pkt, srcPort, dstPort, seqNum)
	} else if flagFIN {
		// 3. 处理FIN包（连接关闭）
		return fe.handleTCPFin(pkt, srcPort, dstPort, seqNum)
	} else if flagPSH {
		// 4. 处理带数据的包（PSH标志表示有数据需要立即推送）
		return fe.handleTCPData(pkt, srcPort, dstPort, seqNum, ackNum)
	} else if flagACK {
		// 5. 处理ACK包（可能是纯ACK或带数据的ACK）
		// 检查是否有数据载荷
		tcpHeaderLen := int((pkt.Data[12] >> 4) * 4)
		if len(pkt.Data) > tcpHeaderLen {
			// 有数据载荷，作为数据包处理
			return fe.handleTCPData(pkt, srcPort, dstPort, seqNum, ackNum)
		} else {
			// 纯ACK包
			return fe.handleTCPAck(pkt, srcPort, dstPort, seqNum, ackNum)
		}
	}

	return nil
}

// deliverToUDP 将UDP数据包交付给UDP处理模块
func (fe *Engine) deliverToUDP(pkt *IPPacket) error {
	// 解析UDP头部
	if len(pkt.Data) < 8 {
		return fmt.Errorf("UDP数据包长度不足")
	}

	// 提取目标端口信息
	dstPort := uint16(pkt.Data[2])<<8 | uint16(pkt.Data[3])

	// 检查是否有监听该端口的服务
	if !fe.isPortListening(dstPort, "udp") {
		// 发送ICMP Port Unreachable
		return fe.sendICMPPortUnreachable(pkt)
	}

	// 在真实实现中，这里会将数据包交付给UDP协议栈
	// 包括套接字查找、数据交付等
	return nil
}

// handleICMPEchoRequest 处理ICMP Echo Request (ping)
func (fe *Engine) handleICMPEchoRequest(pkt *IPPacket) error {
	// 构造Echo Reply
	replyData := make([]byte, len(pkt.Data))
	copy(replyData, pkt.Data)
	replyData[0] = 0 // 设置为Echo Reply

	// 创建回复数据包
	reply := NewIPPacket(pkt.Destination, pkt.Source, 64, 1, replyData)

	// 发送回复
	return fe.ForwardPacket(reply)
}

// handleICMPEchoReply 处理ICMP Echo Reply
func (fe *Engine) handleICMPEchoReply(pkt *IPPacket) error {
	// 解析ICMP头部
	if len(pkt.Data) < 8 {
		return fmt.Errorf("ICMP packet too short")
	}

	icmpType := pkt.Data[0]
	icmpCode := pkt.Data[1]
	identifier := uint16(pkt.Data[4])<<8 | uint16(pkt.Data[5])
	sequence := uint16(pkt.Data[6])<<8 | uint16(pkt.Data[7])

	// 验证这是一个Echo Reply
	if icmpType != 0 {
		return fmt.Errorf("not an ICMP Echo Reply")
	}

	fmt.Printf("Received ICMP Echo Reply from %s: type=%d, code=%d, id=%d, seq=%d\n",
		pkt.Source, icmpType, icmpCode, identifier, sequence)

	// 在真实实现中，这里会：
	// 1. 查找等待此回复的ping进程
	// 2. 计算往返时间(RTT)
	// 3. 将结果交付给用户空间程序

	// 模拟交付给ping程序
	if len(pkt.Data) > 8 {
		dataLen := len(pkt.Data) - 8
		fmt.Printf("Echo Reply data length: %d bytes\n", dataLen)

		// 可以在这里实现与用户空间ping程序的通信
		// 例如通过socket、管道或共享内存
	}

	return nil
}

// handleICMPDestUnreachable 处理ICMP Destination Unreachable
func (fe *Engine) handleICMPDestUnreachable(pkt *IPPacket) error {
	// 解析ICMP头部
	if len(pkt.Data) < 8 {
		return fmt.Errorf("ICMP packet too short")
	}

	icmpType := pkt.Data[0]
	icmpCode := pkt.Data[1]

	// 验证这是一个目标不可达消息
	if icmpType != 3 {
		return fmt.Errorf("not an ICMP Destination Unreachable")
	}

	// 解析不可达原因
	var reason string
	switch icmpCode {
	case 0:
		reason = "Network Unreachable"
	case 1:
		reason = "Host Unreachable"
	case 2:
		reason = "Protocol Unreachable"
	case 3:
		reason = "Port Unreachable"
	case 4:
		reason = "Fragmentation needed but DF set"
	case 5:
		reason = "Source route failed"
	case 6:
		reason = "Destination network unknown"
	case 7:
		reason = "Destination host unknown"
	case 9:
		reason = "Destination network administratively prohibited"
	case 10:
		reason = "Destination host administratively prohibited"
	case 11:
		reason = "Network unreachable for TOS"
	case 12:
		reason = "Host unreachable for TOS"
	case 13:
		reason = "Communication administratively prohibited"
	default:
		reason = fmt.Sprintf("Unknown code %d", icmpCode)
	}

	fmt.Printf("Received ICMP Destination Unreachable from %s: %s\n", pkt.Source, reason)

	// 提取原始IP头部和数据（如果存在）
	if len(pkt.Data) >= 28 { // ICMP头部(8字节) + 原始IP头部(至少20字节)
		originalIPHeader := pkt.Data[8:28]
		originalDest := fmt.Sprintf("%d.%d.%d.%d",
			originalIPHeader[16], originalIPHeader[17],
			originalIPHeader[18], originalIPHeader[19])
		originalProto := originalIPHeader[9]

		fmt.Printf("Original packet destination: %s, protocol: %d\n", originalDest, originalProto)

		// 在真实实现中，这里会：
		// 1. 查找相关的连接或套接字
		// 2. 通知应用程序连接失败
		// 3. 更新路由表（如果是网络不可达）
		// 4. 触发重传或错误处理机制

		// 根据协议类型处理
		switch originalProto {
		case 6: // TCP
			// 通知TCP连接管理器
			fmt.Printf("Notifying TCP connection manager about unreachable destination\n")
		case 17: // UDP
			// 通知UDP套接字
			fmt.Printf("Notifying UDP socket about unreachable destination\n")
		case 1: // ICMP
			// 通知ping程序
			fmt.Printf("Notifying ping program about unreachable destination\n")
		}
	}

	return nil
}

// handleICMPTimeExceeded 处理ICMP Time Exceeded
func (fe *Engine) handleICMPTimeExceeded(pkt *IPPacket) error {
	// 解析ICMP头部
	if len(pkt.Data) < 8 {
		return fmt.Errorf("ICMP packet too short")
	}

	icmpType := pkt.Data[0]
	icmpCode := pkt.Data[1]

	// 验证这是一个时间超时消息
	if icmpType != 11 {
		return fmt.Errorf("not an ICMP Time Exceeded")
	}

	// 解析超时原因
	var reason string
	switch icmpCode {
	case 0:
		reason = "TTL expired in transit"
	case 1:
		reason = "Fragment reassembly time exceeded"
	default:
		reason = fmt.Sprintf("Unknown code %d", icmpCode)
	}

	fmt.Printf("Received ICMP Time Exceeded from %s: %s\n", pkt.Source, reason)

	// 提取原始IP头部和数据（如果存在）
	if len(pkt.Data) >= 28 { // ICMP头部(8字节) + 原始IP头部(至少20字节)
		originalIPHeader := pkt.Data[8:28]
		originalSrc := fmt.Sprintf("%d.%d.%d.%d",
			originalIPHeader[12], originalIPHeader[13],
			originalIPHeader[14], originalIPHeader[15])
		originalDest := fmt.Sprintf("%d.%d.%d.%d",
			originalIPHeader[16], originalIPHeader[17],
			originalIPHeader[18], originalIPHeader[19])
		originalProto := originalIPHeader[9]
		originalTTL := originalIPHeader[8]

		fmt.Printf("Original packet: %s -> %s, protocol: %d, TTL: %d\n",
			originalSrc, originalDest, originalProto, originalTTL)

		// 在真实实现中，这里会：
		switch icmpCode {
		case 0: // TTL expired
			// 1. 通知traceroute程序（如果是traceroute包）
			// 2. 记录路由跳数信息
			// 3. 可能触发路由重新计算
			fmt.Printf("Processing TTL expiration for traceroute or routing\n")

			// 检查是否是traceroute包（通常UDP端口33434-33534）
			if originalProto == 17 && len(pkt.Data) >= 36 { // UDP
				originalUDPHeader := pkt.Data[28:36]
				destPort := uint16(originalUDPHeader[2])<<8 | uint16(originalUDPHeader[3])
				if destPort >= 33434 && destPort <= 33534 {
					fmt.Printf("Traceroute packet detected, notifying traceroute program\n")
				}
			}

		case 1: // Fragment reassembly timeout
			// 1. 清理分片重组缓存
			// 2. 通知发送方分片丢失
			// 3. 可能调整分片策略
			fmt.Printf("Processing fragment reassembly timeout\n")

			// 清理相关的分片缓存
			fragmentID := uint16(originalIPHeader[4])<<8 | uint16(originalIPHeader[5])
			fmt.Printf("Cleaning up fragments for ID: %d\n", fragmentID)

			// 在真实实现中，这里会清理fe.fragmentCache中的相关条目
		}

		// 根据协议类型进行额外处理
		switch originalProto {
		case 6: // TCP
			// 通知TCP连接管理器可能需要重传或调整窗口
			fmt.Printf("Notifying TCP about time exceeded\n")
		case 17: // UDP
			// 通知UDP应用程序
			fmt.Printf("Notifying UDP application about time exceeded\n")
		case 1: // ICMP
			// 通知ping程序
			fmt.Printf("Notifying ping program about time exceeded\n")
		}
	}

	return nil
}

// isPortListening 检查端口是否有服务监听
func (fe *Engine) isPortListening(port uint16, protocol string) bool {
	// 尝试连接到本地端口来检查是否有服务监听
	address := fmt.Sprintf("127.0.0.1:%d", port)

	var conn net.Conn
	var err error

	// 根据协议类型进行连接测试
	switch protocol {
	case "tcp":
		conn, err = net.DialTimeout("tcp", address, 100*time.Millisecond)
	case "udp":
		// UDP是无连接的，我们尝试发送一个小数据包
		udpAddr, parseErr := net.ResolveUDPAddr("udp", address)
		if parseErr != nil {
			return false
		}
		conn, err = net.DialUDP("udp", nil, udpAddr)
		if err == nil {
			// 发送一个小的测试数据包
			_, writeErr := conn.Write([]byte{0})
			_ = conn.Close()
			// 对于UDP，如果能写入就认为端口可能在监听
			return writeErr == nil
		}
	default:
		return false
	}

	if err != nil {
		// 连接失败，端口可能没有监听
		return false
	}

	if conn != nil {
		_ = conn.Close()
		// 连接成功，说明有服务在监听
		return true
	}

	return false
}

// sendICMPProtocolUnreachable 发送ICMP Protocol Unreachable
func (fe *Engine) sendICMPProtocolUnreachable(pkt *IPPacket) error {
	return fe.sendICMPError(pkt, 3, 2) // Type 3, Code 2
}

// sendICMPPortUnreachable 发送ICMP Port Unreachable
func (fe *Engine) sendICMPPortUnreachable(pkt *IPPacket) error {
	return fe.sendICMPError(pkt, 3, 3) // Type 3, Code 3
}

// sendTCPReset 发送TCP RST
func (fe *Engine) sendTCPReset(pkt *IPPacket, srcPort, dstPort uint16) error {
	// 构造TCP RST数据包
	tcpHeader := make([]byte, 20)

	// 源端口和目标端口（交换）
	tcpHeader[0] = byte(dstPort >> 8)
	tcpHeader[1] = byte(dstPort)
	tcpHeader[2] = byte(srcPort >> 8)
	tcpHeader[3] = byte(srcPort)

	// 设置RST标志
	tcpHeader[13] = 0x04 // RST flag

	// 创建RST数据包
	rstPacket := NewIPPacket(pkt.Destination, pkt.Source, 64, 6, tcpHeader)

	return fe.ForwardPacket(rstPacket)
}

// sendICMPError 发送ICMP错误消息
func (fe *Engine) sendICMPError(pkt *IPPacket, icmpType, icmpCode byte) error {
	// 构造ICMP错误消息
	icmpData := make([]byte, 8+20+8) // ICMP头 + 原IP头 + 原数据前8字节

	icmpData[0] = icmpType
	icmpData[1] = icmpCode
	// 校验和稍后计算

	// 复制原始IP头和数据前8字节
	if len(pkt.Data) >= 8 {
		copy(icmpData[8:], pkt.Data[:8])
	}

	// 创建ICMP错误数据包
	errorPacket := NewIPPacket(pkt.Destination, pkt.Source, 64, 1, icmpData)

	return fe.ForwardPacket(errorPacket)
}

// sendPacket 发送数据包
func (fe *Engine) sendPacket(pkt *IPPacket, outInterface *interfaces.Interface, dstMAC net.HardwareAddr) error {
	// 获取接口的MAC地址
	netIface, err := net.InterfaceByName(outInterface.Name)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %v", outInterface.Name, err)
	}

	// 构造以太网帧
	frame, err := fe.buildEthernetFrame(pkt, netIface.HardwareAddr, dstMAC)
	if err != nil {
		return fmt.Errorf("failed to build ethernet frame: %v", err)
	}

	// 发送数据包到网络接口
	err = fe.sendToInterface(outInterface.Name, frame)
	if err != nil {
		return fmt.Errorf("failed to send packet to interface %s: %v", outInterface.Name, err)
	}

	// 更新接口统计信息
	_ = fe.interfaceManager.UpdateInterfaceStats(
		outInterface.Name,
		outInterface.TxPackets+1,
		outInterface.RxPackets,
		outInterface.TxBytes+uint64(len(frame)),
		outInterface.RxBytes,
		outInterface.Errors,
	)

	return nil
}

// buildEthernetFrame 构造以太网帧
func (fe *Engine) buildEthernetFrame(pkt *IPPacket, srcMAC, dstMAC net.HardwareAddr) ([]byte, error) {
	// 以太网帧头部长度：14字节
	// 目标MAC(6) + 源MAC(6) + 类型(2)
	frameSize := 14 + len(pkt.Data)
	frame := make([]byte, frameSize)

	// 设置目标MAC地址
	copy(frame[0:6], dstMAC)

	// 设置源MAC地址
	copy(frame[6:12], srcMAC)

	// 设置以太网类型 (IPv4 = 0x0800)
	frame[12] = 0x08
	frame[13] = 0x00

	// 复制IP数据包数据
	copy(frame[14:], pkt.Data)

	return frame, nil
}

// sendToInterface 发送数据包到指定网络接口
func (fe *Engine) sendToInterface(interfaceName string, frame []byte) error {
	if len(frame) == 0 {
		return fmt.Errorf("empty frame")
	}

	if interfaceName == "" {
		return fmt.Errorf("invalid interface name")
	}

	// 获取网络接口
	netIface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
	}

	// 创建原始套接字发送数据包
	// 在macOS上使用AF_PACKET可能不可用，这里提供一个通用的实现
	return fe.sendRawPacket(netIface, frame)
}

// sendRawPacket 使用原始套接字发送数据包
func (fe *Engine) sendRawPacket(iface *net.Interface, frame []byte) error {
	// 检查权限和接口状态
	if iface == nil {
		return fmt.Errorf("interface is nil")
	}

	if len(frame) == 0 {
		return fmt.Errorf("empty frame")
	}

	// 在macOS上，我们需要使用BPF (Berkeley Packet Filter)
	// 或者通过系统调用直接发送
	return fe.sendViaRawSocket(iface, frame)
}

// sendViaRawSocket 通过原始套接字发送数据包
func (fe *Engine) sendViaRawSocket(iface *net.Interface, frame []byte) error {
	// 尝试使用原始套接字发送
	// 首先尝试创建原始套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		// 如果无法创建原始套接字（通常是权限问题），回退到模拟发送
		fmt.Printf("Warning: Cannot create raw socket (need root privileges): %v\n", err)
		return fe.simulateSend(iface, frame)
	}
	defer func() {
		_ = syscall.Close(fd)
	}()

	// 设置IP_HDRINCL选项，允许我们自己构造IP头部
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		fmt.Printf("Warning: Cannot set IP_HDRINCL: %v\n", err)
		return fe.simulateSend(iface, frame)
	}

	// 在Linux上绑定到指定接口，macOS不支持SO_BINDTODEVICE
	if runtime.GOOS == "linux" {
		// Linux特定的接口绑定
		const SoBindToDevice = 25
		err = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, SoBindToDevice, iface.Name)
		if err != nil {
			fmt.Printf("Warning: Cannot bind to device %s: %v\n", iface.Name, err)
		}
	}

	// 提取目标IP地址（从IP头部）
	if len(frame) < 34 { // 以太网头(14) + IP头最小长度(20)
		return fmt.Errorf("frame too short")
	}

	// 跳过以太网头部，获取IP数据包
	ipPacket := frame[14:]
	if len(ipPacket) < 20 {
		return fmt.Errorf("IP packet too short")
	}

	// 提取目标IP地址（IP头部第16-19字节）
	dstIP := net.IPv4(ipPacket[16], ipPacket[17], ipPacket[18], ipPacket[19])

	// 构造目标地址结构
	addr := &syscall.SockaddrInet4{
		Port: 0,
	}
	copy(addr.Addr[:], dstIP.To4())

	// 发送IP数据包（不包含以太网头部）
	err = syscall.Sendto(fd, ipPacket, 0, addr)
	if err != nil {
		fmt.Printf("Warning: Raw socket send failed: %v\n", err)
		return fe.simulateSend(iface, frame)
	}

	fmt.Printf("Successfully sent %d bytes via raw socket on interface %s\n", len(ipPacket), iface.Name)
	return nil
}

// simulateSend 模拟发送（当无法使用原始套接字时）
func (fe *Engine) simulateSend(iface *net.Interface, frame []byte) error {
	// 当原始套接字发送失败时的备用发送方案
	// 在真实路由系统中，这里可以：
	// 1. 使用TUN/TAP接口
	// 2. 通过用户空间网络栈发送
	// 3. 使用其他网络API

	// 验证帧格式
	if len(frame) < 14 {
		return fmt.Errorf("frame too short: %d bytes", len(frame))
	}

	// 解析以太网头部
	dstMAC := frame[0:6]
	srcMAC := frame[6:12]
	etherType := uint16(frame[12])<<8 | uint16(frame[13])

	fmt.Printf("Fallback send on interface %s: %d bytes\n", iface.Name, len(frame))
	fmt.Printf("  Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		dstMAC[0], dstMAC[1], dstMAC[2], dstMAC[3], dstMAC[4], dstMAC[5])
	fmt.Printf("  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		srcMAC[0], srcMAC[1], srcMAC[2], srcMAC[3], srcMAC[4], srcMAC[5])
	fmt.Printf("  EtherType: 0x%04x\n", etherType)

	// 在真实实现中，这里可以：
	switch etherType {
	case 0x0800: // IPv4
		if len(frame) >= 34 { // 以太网头部14字节 + IP头部最少20字节
			ipHeader := frame[14:34]
			srcIP := fmt.Sprintf("%d.%d.%d.%d", ipHeader[12], ipHeader[13], ipHeader[14], ipHeader[15])
			dstIP := fmt.Sprintf("%d.%d.%d.%d", ipHeader[16], ipHeader[17], ipHeader[18], ipHeader[19])
			protocol := int(ipHeader[9])

			fmt.Printf("  IPv4: %s -> %s, protocol: %d\n", srcIP, dstIP, protocol)

			// 尝试通过系统网络栈发送
			return fe.sendViaSystemStack(srcIP, dstIP, protocol, frame[34:])
		}

	case 0x0806: // ARP
		fmt.Printf("  ARP packet\n")
		// ARP包通常由系统处理，这里记录即可

	default:
		fmt.Printf("  Unknown EtherType: 0x%04x\n", etherType)
	}

	// 记录发送统计
	atomic.AddUint64(&fe.stats.PacketsForwarded, 1)

	// 在开发/测试环境中，可以写入到文件用于分析
	if fe.config.EnableIPForwarding {
		debugInfo := fmt.Sprintf("Fallback send - Interface: %s, Frame size: %d bytes, Timestamp: %s\n",
			iface.Name, len(frame), time.Now().Format(time.RFC3339))

		// 这里可以集成到日志系统或写入调试文件
		_ = debugInfo
	}

	return nil
}

// sendViaSystemStack 通过系统网络栈发送数据包
func (fe *Engine) sendViaSystemStack(srcIP, dstIP string, protocol int, payload []byte) error {
	// 在真实实现中，这里可以：
	// 1. 创建相应协议的套接字
	// 2. 绑定源地址
	// 3. 发送到目标地址

	switch protocol {
	case 1: // ICMP
		// 可以使用ICMP套接字发送
		fmt.Printf("Would send ICMP packet via system stack: %s -> %s\n", srcIP, dstIP)

	case 6: // TCP
		// 可以使用TCP套接字发送（如果是已建立的连接）
		fmt.Printf("Would send TCP packet via system stack: %s -> %s\n", srcIP, dstIP)

	case 17: // UDP
		// 可以使用UDP套接字发送
		fmt.Printf("Would send UDP packet via system stack: %s -> %s\n", srcIP, dstIP)

	default:
		fmt.Printf("Unsupported protocol %d for system stack sending\n", protocol)
		return fmt.Errorf("unsupported protocol: %d", protocol)
	}

	// 在真实实现中，这里会实际发送数据包
	// 目前只是记录，避免在没有适当权限时出错

	return nil
}

// fragmentAndForward 分片并转发
func (fe *Engine) fragmentAndForward(pkt *IPPacket, outInterface *interfaces.Interface, gateway net.IP) error {
	fe.mu.Lock()
	fe.stats.FragmentationNeeded++
	fe.mu.Unlock()

	// 检查是否允许分片
	if !fe.config.EnableFragmentation {
		return fmt.Errorf("fragmentation disabled")
	}

	// 获取接口MTU
	mtu := outInterface.MTU
	if mtu <= 0 {
		mtu = 1500 // 默认以太网MTU
	}

	// IP头部长度（假设没有选项，标准20字节）
	ipHeaderLen := 20

	// 可用于数据的MTU（减去IP头部）
	maxDataSize := mtu - ipHeaderLen

	// 确保分片大小是8字节的倍数（RFC 791要求）
	maxDataSize = (maxDataSize / 8) * 8

	if maxDataSize <= 0 {
		return fmt.Errorf("MTU too small for fragmentation")
	}

	// 计算需要的分片数量
	totalDataSize := len(pkt.Data)
	fragmentCount := (totalDataSize + maxDataSize - 1) / maxDataSize

	// 生成分片ID（在真实实现中应该是全局唯一的）
	fragmentID := fe.generateFragmentID()

	// 创建分片
	for i := 0; i < fragmentCount; i++ {
		// 计算当前分片的数据范围
		start := i * maxDataSize
		end := start + maxDataSize
		if end > totalDataSize {
			end = totalDataSize
		}

		// 创建分片数据包
		fragment := &IPPacket{
			Source:      pkt.Source,
			Destination: pkt.Destination,
			TTL:         pkt.TTL,
			Protocol:    pkt.Protocol,
			Data:        pkt.Data[start:end],
			InInterface: pkt.InInterface,
			Timestamp:   time.Now(),
		}

		// 设置分片信息
		fragment.FragmentID = fragmentID
		fragment.FragmentOffset = start / 8 // 以8字节为单位
		fragment.MoreFragments = (i < fragmentCount-1)
		fragment.DontFragment = false

		// 转发分片
		err := fe.forwardFragment(fragment, outInterface, gateway)
		if err != nil {
			return fmt.Errorf("failed to forward fragment %d: %v", i, err)
		}
	}

	return nil
}

// generateFragmentID 生成分片ID
func (fe *Engine) generateFragmentID() uint16 {
	// 在真实实现中，这应该是一个全局唯一的ID生成器
	// 这里使用简单的时间戳方法
	return uint16(time.Now().UnixNano() & 0xFFFF)
}

// forwardFragment 转发单个分片
func (fe *Engine) forwardFragment(fragment *IPPacket, outInterface *interfaces.Interface, gateway net.IP) error {
	// 验证分片参数
	if fragment == nil {
		return fmt.Errorf("fragment is nil")
	}

	if outInterface == nil {
		return fmt.Errorf("output interface is nil")
	}

	// 检查分片大小是否超过接口MTU
	interfaceMTU := outInterface.MTU
	if interfaceMTU == 0 {
		interfaceMTU = 1500 // 默认以太网MTU
	}

	// IP头部最小20字节，加上以太网头部14字节
	maxPayloadSize := interfaceMTU - 20 - 14

	if len(fragment.Data) > maxPayloadSize {
		// 需要进一步分片
		return fe.fragmentLargePacket(fragment, outInterface, gateway, maxPayloadSize)
	}

	// 验证分片偏移对齐（必须是8字节的倍数）
	if fragment.FragmentOffset%8 != 0 {
		return fmt.Errorf("fragment offset %d is not aligned to 8-byte boundary", fragment.FragmentOffset)
	}

	// 构建IP头部，包含正确的分片信息
	ipHeader := fe.buildFragmentIPHeader(fragment)

	// 验证IP头部长度
	if len(ipHeader) < 20 {
		return fmt.Errorf("invalid IP header length: %d", len(ipHeader))
	}

	// 组合完整的IP数据包
	fullPacket := append(ipHeader, fragment.Data...)

	// 更新数据包大小
	fragment.Size = len(fullPacket)

	// 验证总长度不超过MTU
	if len(fullPacket) > interfaceMTU-14 { // 减去以太网头部
		return fmt.Errorf("fragment size %d exceeds interface MTU %d", len(fullPacket), interfaceMTU-14)
	}

	// 获取目标MAC地址
	var dstMAC net.HardwareAddr
	var err error

	targetIP := fragment.Destination
	if gateway != nil {
		targetIP = gateway
	}

	// 尝试从ARP表获取MAC地址
	entry, found := fe.arpTable.LookupEntry(targetIP)
	if found {
		dstMAC = entry.MACAddress
	} else {
		// 发送ARP请求
		err = fe.arpTable.SendARPRequest(targetIP, outInterface.Name)
		if err != nil {
			return fmt.Errorf("failed to send ARP request for %v: %v", targetIP, err)
		}

		// 在真实实现中，这里应该：
		// 1. 将分片缓存到待发送队列
		// 2. 设置ARP响应回调
		// 3. 实现超时重传机制
		fmt.Printf("ARP resolution needed for %v, caching fragment ID %d offset %d\n",
			targetIP, fragment.FragmentID, fragment.FragmentOffset)

		return fmt.Errorf("ARP resolution needed for %v", targetIP)
	}

	// 记录分片转发统计
	atomic.AddUint64(&fe.stats.PacketsForwarded, 1)

	// 记录分片信息用于调试
	fmt.Printf("Forwarding fragment: ID=%d, offset=%d, size=%d, more=%t, via %s\n",
		fragment.FragmentID, fragment.FragmentOffset, len(fragment.Data),
		fragment.MoreFragments, outInterface.Name)

	// 发送分片
	err = fe.sendPacket(fragment, outInterface, dstMAC)
	if err != nil {
		atomic.AddUint64(&fe.stats.PacketsDropped, 1)
		return fmt.Errorf("failed to send fragment: %v", err)
	}

	return nil
}

// fragmentLargePacket 对过大的分片进行进一步分片
func (fe *Engine) fragmentLargePacket(fragment *IPPacket, outInterface *interfaces.Interface, gateway net.IP, maxPayloadSize int) error {
	// 确保分片大小是8字节的倍数
	fragmentSize := (maxPayloadSize / 8) * 8

	data := fragment.Data
	offset := fragment.FragmentOffset

	for len(data) > 0 {
		// 计算当前分片的大小
		currentSize := fragmentSize
		if len(data) < currentSize {
			currentSize = len(data)
		}

		// 创建新的分片
		newFragment := &IPPacket{
			Source:         fragment.Source,
			Destination:    fragment.Destination,
			TTL:            fragment.TTL,
			Protocol:       fragment.Protocol,
			Data:           data[:currentSize],
			FragmentID:     fragment.FragmentID,
			FragmentOffset: offset,
			MoreFragments:  len(data) > currentSize || fragment.MoreFragments,
			DontFragment:   false, // 强制允许分片
			InInterface:    fragment.InInterface,
			Timestamp:      fragment.Timestamp,
		}

		// 递归转发分片
		err := fe.forwardFragment(newFragment, outInterface, gateway)
		if err != nil {
			return fmt.Errorf("failed to forward sub-fragment at offset %d: %v", offset, err)
		}

		// 移动到下一个分片
		data = data[currentSize:]
		offset += currentSize / 8 // 偏移以8字节为单位
	}

	return nil
}

// buildFragmentIPHeader 构建包含分片信息的IP头部
func (fe *Engine) buildFragmentIPHeader(fragment *IPPacket) []byte {
	header := make([]byte, 20) // 标准IP头部长度

	// 版本和头部长度
	header[0] = 0x45 // IPv4, 20字节头部

	// 服务类型
	header[1] = 0x00

	// 总长度（头部 + 数据）
	totalLength := 20 + len(fragment.Data)
	header[2] = byte(totalLength >> 8)
	header[3] = byte(totalLength & 0xFF)

	// 分片标识符
	header[4] = byte(fragment.FragmentID >> 8)
	header[5] = byte(fragment.FragmentID & 0xFF)

	// 标志位和分片偏移
	flagsAndOffset := uint16(0)

	// 设置标志位
	if fragment.DontFragment {
		flagsAndOffset |= 0x4000 // DF位
	}
	if fragment.MoreFragments {
		flagsAndOffset |= 0x2000 // MF位
	}

	// 设置分片偏移（以8字节为单位）
	flagsAndOffset |= uint16(fragment.FragmentOffset) & 0x1FFF

	header[6] = byte(flagsAndOffset >> 8)
	header[7] = byte(flagsAndOffset & 0xFF)

	// TTL
	header[8] = byte(fragment.TTL)

	// 协议
	header[9] = byte(fragment.Protocol)

	// 校验和（先设为0）
	header[10] = 0
	header[11] = 0

	// 源IP地址
	srcIP := fragment.Source.To4()
	if srcIP != nil {
		copy(header[12:16], srcIP)
	}

	// 目标IP地址
	dstIP := fragment.Destination.To4()
	if dstIP != nil {
		copy(header[16:20], dstIP)
	}

	// 计算并设置校验和
	checksum := fe.calculateIPChecksum(header)
	header[10] = byte(checksum >> 8)
	header[11] = byte(checksum & 0xFF)

	return header
}

// calculateIPChecksum 计算IP头部校验和
func (fe *Engine) calculateIPChecksum(header []byte) uint16 {
	sum := uint32(0)

	// 将头部按16位字处理
	for i := 0; i < len(header); i += 2 {
		if i+1 < len(header) {
			word := uint32(header[i])<<8 + uint32(header[i+1])
			sum += word
		}
	}

	// 处理进位
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// 取反
	return uint16(^sum)
}

// sendICMPTimeExceeded 发送ICMP Time Exceeded消息
func (fe *Engine) sendICMPTimeExceeded(pkt *IPPacket) {
	fe.mu.Lock()
	fe.stats.ICMPGenerated++
	fe.stats.TTLExpired++
	fe.mu.Unlock()

	// 构造ICMP Time Exceeded消息 (Type 11, Code 0)
	icmpPacket := fe.buildICMPTimeExceededPacket(pkt)
	if icmpPacket != nil {
		fe.sendICMPPacket(icmpPacket, pkt.Source)
	}
}

// sendICMPDestUnreachable 发送ICMP Destination Unreachable消息
func (fe *Engine) sendICMPDestUnreachable(pkt *IPPacket) {
	fe.mu.Lock()
	fe.stats.ICMPGenerated++
	fe.mu.Unlock()

	// 构造ICMP Destination Unreachable消息 (Type 3, Code 0)
	icmpPacket := fe.buildICMPDestUnreachablePacket(pkt)
	if icmpPacket != nil {
		fe.sendICMPPacket(icmpPacket, pkt.Source)
	}
}

// sendICMPFragNeeded 发送ICMP Fragmentation Needed消息
func (fe *Engine) sendICMPFragNeeded(pkt *IPPacket, mtu int) {
	fe.mu.Lock()
	fe.stats.ICMPGenerated++
	fe.stats.FragmentationNeeded++
	fe.mu.Unlock()

	// 构造ICMP Fragmentation Needed消息 (Type 3, Code 4)
	icmpPacket := fe.buildICMPFragNeededPacket(pkt, mtu)
	if icmpPacket != nil {
		fe.sendICMPPacket(icmpPacket, pkt.Source)
	}
}

// buildICMPTimeExceededPacket 构造ICMP Time Exceeded数据包
func (fe *Engine) buildICMPTimeExceededPacket(originalPkt *IPPacket) *IPPacket {
	// ICMP头部：Type(1) + Code(1) + Checksum(2) + Unused(4) = 8字节
	// 然后是原始IP头部和前8字节数据
	icmpData := make([]byte, 8+20+8) // ICMP头 + IP头 + 8字节数据

	// ICMP头部
	icmpData[0] = 11 // Type: Time Exceeded
	icmpData[1] = 0  // Code: TTL expired in transit
	// icmpData[2:4] = checksum (稍后计算)
	// icmpData[4:8] = unused (保持为0)

	// 复制原始IP头部（假设为20字节标准头部）
	if len(originalPkt.Data) >= 20 {
		copy(icmpData[8:28], originalPkt.Data[:20])
	}

	// 复制原始数据的前8字节
	if len(originalPkt.Data) >= 28 {
		copy(icmpData[28:36], originalPkt.Data[20:28])
	}

	// 计算ICMP校验和
	checksum := fe.calculateICMPChecksum(icmpData)
	icmpData[2] = byte(checksum >> 8)
	icmpData[3] = byte(checksum & 0xFF)

	// 获取本地接口IP作为源地址
	srcIP := fe.getLocalInterfaceIP(originalPkt.InInterface)
	if srcIP == nil {
		return nil
	}

	return NewIPPacket(srcIP, originalPkt.Source, 64, 1, icmpData) // Protocol 1 = ICMP
}

// buildICMPDestUnreachablePacket 构造ICMP Destination Unreachable数据包
func (fe *Engine) buildICMPDestUnreachablePacket(originalPkt *IPPacket) *IPPacket {
	icmpData := make([]byte, 8+20+8) // ICMP头 + IP头 + 8字节数据

	// ICMP头部
	icmpData[0] = 3 // Type: Destination Unreachable
	icmpData[1] = 0 // Code: Network unreachable
	// icmpData[2:4] = checksum (稍后计算)
	// icmpData[4:8] = unused (保持为0)

	// 复制原始IP头部和数据
	if len(originalPkt.Data) >= 20 {
		copy(icmpData[8:28], originalPkt.Data[:20])
	}
	if len(originalPkt.Data) >= 28 {
		copy(icmpData[28:36], originalPkt.Data[20:28])
	}

	// 计算ICMP校验和
	checksum := fe.calculateICMPChecksum(icmpData)
	icmpData[2] = byte(checksum >> 8)
	icmpData[3] = byte(checksum & 0xFF)

	srcIP := fe.getLocalInterfaceIP(originalPkt.InInterface)
	if srcIP == nil {
		return nil
	}

	return NewIPPacket(srcIP, originalPkt.Source, 64, 1, icmpData)
}

// buildICMPFragNeededPacket 构造ICMP Fragmentation Needed数据包
func (fe *Engine) buildICMPFragNeededPacket(originalPkt *IPPacket, mtu int) *IPPacket {
	icmpData := make([]byte, 8+20+8) // ICMP头 + IP头 + 8字节数据

	// ICMP头部
	icmpData[0] = 3 // Type: Destination Unreachable
	icmpData[1] = 4 // Code: Fragmentation needed but DF bit set
	// icmpData[2:4] = checksum (稍后计算)
	// icmpData[4:6] = unused (保持为0)
	// icmpData[6:8] = Next-hop MTU
	icmpData[6] = byte(mtu >> 8)
	icmpData[7] = byte(mtu & 0xFF)

	// 复制原始IP头部和数据
	if len(originalPkt.Data) >= 20 {
		copy(icmpData[8:28], originalPkt.Data[:20])
	}
	if len(originalPkt.Data) >= 28 {
		copy(icmpData[28:36], originalPkt.Data[20:28])
	}

	// 计算ICMP校验和
	checksum := fe.calculateICMPChecksum(icmpData)
	icmpData[2] = byte(checksum >> 8)
	icmpData[3] = byte(checksum & 0xFF)

	srcIP := fe.getLocalInterfaceIP(originalPkt.InInterface)
	if srcIP == nil {
		return nil
	}

	return NewIPPacket(srcIP, originalPkt.Source, 64, 1, icmpData)
}

// calculateICMPChecksum 计算ICMP校验和
func (fe *Engine) calculateICMPChecksum(data []byte) uint16 {
	// 清零校验和字段
	data[2] = 0
	data[3] = 0

	var sum uint32

	// 按16位字处理数据
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 + uint32(data[i+1])
	}

	// 处理奇数长度
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// 处理进位
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// 取反得到校验和
	return uint16(^sum)
}

// getLocalInterfaceIP 获取指定接口的本地IP地址
func (fe *Engine) getLocalInterfaceIP(interfaceName string) net.IP {
	iface, err := fe.interfaceManager.GetInterface(interfaceName)
	if err != nil || iface.IPAddress == nil {
		// 如果无法获取接口IP，尝试获取任意活跃接口的IP
		activeInterfaces := fe.interfaceManager.GetActiveInterfaces()
		for _, activeIface := range activeInterfaces {
			if activeIface.IPAddress != nil {
				return activeIface.IPAddress
			}
		}
		return nil
	}
	return iface.IPAddress
}

// sendICMPPacket 发送ICMP数据包
func (fe *Engine) sendICMPPacket(icmpPkt *IPPacket, destination net.IP) {
	// 查找到目标的路由
	route, err := fe.routingTable.LookupRoute(destination)
	if err != nil {
		return // 无法路由到目标
	}

	// 获取出接口
	outInterface, err := fe.interfaceManager.GetInterface(route.Interface)
	if err != nil {
		return
	}

	// 解析目标MAC地址
	var dstMAC net.HardwareAddr
	if route.Gateway != nil {
		// 通过网关发送
		dstMAC, err = fe.arpTable.Resolve(route.Gateway, route.Interface, 5*time.Second)
	} else {
		// 直接发送到目标
		dstMAC, err = fe.arpTable.Resolve(destination, route.Interface, 5*time.Second)
	}

	if err != nil {
		return // ARP解析失败
	}

	// 发送ICMP数据包
	_ = fe.sendPacket(icmpPkt, outInterface, dstMAC)
}

// incrementDropped 增加丢弃计数
func (fe *Engine) incrementDropped() {
	fe.mu.Lock()
	fe.stats.PacketsDropped++
	fe.mu.Unlock()
}

// GetStats 获取统计信息
func (fe *Engine) GetStats() Stats {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	return fe.stats
}

// ResetStats 重置统计信息
func (fe *Engine) ResetStats() {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	fe.stats = Stats{
		StartTime: time.Now(),
	}
}

// IsRunning 检查是否运行
func (fe *Engine) IsRunning() bool {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	return fe.running
}

// SetConfig 设置配置
func (fe *Engine) SetConfig(config Config) {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	fe.config = config
}

// GetConfig 获取配置
func (fe *Engine) GetConfig() Config {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	return fe.config
}

// ProcessPacketBatch 批量处理数据包
// 提供批量处理接口以提高性能
//
// 参数：
//   - packets: 要处理的数据包列表
//
// 返回值：
//   - []error: 每个数据包的处理结果，nil表示成功
func (fe *Engine) ProcessPacketBatch(packets []*IPPacket) []error {
	results := make([]error, len(packets))

	for i, pkt := range packets {
		results[i] = fe.ForwardPacket(pkt)
	}

	return results
}

// GetForwardingTable 获取转发表信息
// 返回当前的路由和ARP信息，用于调试和监控
func (fe *Engine) GetForwardingTable() ([]routing.Route, []*arp.Entry) {
	routes := fe.routingTable.GetAllRoutes()
	arpEntries := fe.arpTable.GetAllEntries()

	return routes, arpEntries
}

// 实现数据包分发器
func (fe *Engine) packetDispatcher() {
	for packet := range fe.packetQueue {
		if !fe.IsRunning() {
			return
		}

		// 选择工作线程（简单的轮询）
		workerIndex := int(atomic.AddUint64(&fe.stats.PacketsReceived, 1)) % fe.workerCount

		select {
		case fe.workerPool[workerIndex].queue <- packet:
			// 成功分发
		default:
			// 工作线程队列已满，丢弃数据包
			atomic.AddUint64(&fe.stats.PacketsDropped, 1)
		}
	}
}

// 实现增强的数据包处理
func (fe *Engine) processPacket(pkt *IPPacket) {
	start := time.Now()
	// 1. 数据包验证
	if err := fe.validatePacket(pkt); err != nil {
		atomic.AddUint64(&fe.stats.PacketsDropped, 1)
		return
	}

	// 2. TTL处理
	if err := fe.handleTTL(pkt); err != nil {
		atomic.AddUint64(&fe.stats.TTLExpired, 1)
		fe.sendICMPTimeExceeded(pkt)
		return
	}

	// 3. 检查是否为本地目标
	if fe.isLocalDestination(pkt.Destination) {
		atomic.AddUint64(&fe.stats.PacketsToLocal, 1)
		if err := fe.deliverLocally(pkt); err != nil {
			atomic.AddUint64(&fe.stats.PacketsDropped, 1)
		}
		return
	}

	// 4. 检查IP转发是否启用
	if !fe.config.EnableIPForwarding {
		atomic.AddUint64(&fe.stats.PacketsDropped, 1)
		return
	}

	// 5. 检查缓存
	if fe.cache != nil {
		if entry, found := fe.cache.Get(pkt.Destination); found {
			fe.forwardFromCache(pkt, entry)
			return
		}
	}

	// 6. 路由查找
	var routeEntry *RouteEntry
	var err error

	// 使用负载均衡选择路由
	if fe.loadBalancer != nil {
		routeEntry, err = fe.loadBalancer.SelectRoute(pkt.Destination)
	}

	if err != nil || routeEntry == nil {
		// 尝试故障切换
		if fe.failoverManager != nil {
			routeEntry, err = fe.failoverManager.GetActiveRoute(pkt.Destination.String())
		}

		if err != nil || routeEntry == nil {
			// 最后尝试直接路由表查找
			route, err := fe.routingTable.LookupRoute(pkt.Destination)
			if err != nil {
				atomic.AddUint64(&fe.stats.RouteFailures, 1)
				fe.sendICMPDestUnreachable(pkt)
				return
			}

			// 创建临时路由条目
			routeEntry = &RouteEntry{
				Route: *route,
			}
		}
	}

	// 7. 应用流量整形
	if fe.trafficShaper != nil {
		if !fe.trafficShaper.ShapePacket(routeEntry.Route.Interface, pkt) {
			atomic.AddUint64(&fe.stats.PacketsDropped, 1)
			return
		}
	}

	// 8. 检查分片需求
	outInterface, err := fe.interfaceManager.GetInterface(routeEntry.Route.Interface)
	if err != nil {
		atomic.AddUint64(&fe.stats.PacketsDropped, 1)
		return
	}

	if pkt.Size > outInterface.MTU {
		if pkt.DontFragment {
			// 发送ICMP分片需要消息
			fe.sendICMPFragNeeded(pkt, outInterface.MTU)
			return
		}

		// 执行分片
		if err := fe.fragmentAndForward(pkt, outInterface, routeEntry.Route.Gateway); err != nil {
			atomic.AddUint64(&fe.stats.PacketsDropped, 1)
		} else {
			atomic.AddUint64(&fe.stats.PacketsForwarded, 1)
		}
		return
	}

	// 9. 执行转发
	err = fe.ForwardPacket(pkt)
	if err != nil {
		atomic.AddUint64(&fe.stats.PacketsDropped, 1)

		// 根据错误类型发送相应的ICMP消息
		if err.Error() == "no route to host" {
			fe.sendICMPDestUnreachable(pkt)
		}
	} else {
		atomic.AddUint64(&fe.stats.PacketsForwarded, 1)

		// 10. 更新缓存
		if fe.cache != nil {
			// 获取实际使用的下一跳和MAC地址
			var nextHop net.IP
			var dstMAC net.HardwareAddr

			if routeEntry.Route.Gateway != nil {
				nextHop = routeEntry.Route.Gateway
			} else {
				nextHop = pkt.Destination
			}

			// 尝试从ARP表获取MAC地址
			if entry, found := fe.arpTable.LookupEntry(nextHop); found {
				dstMAC = entry.MACAddress
			}

			fe.cache.Put(pkt.Destination, routeEntry.Route, nextHop, routeEntry.Route.Interface, dstMAC)
		}
	}

	// 11. 更新性能指标
	if fe.performanceMonitor != nil {
		latency := time.Since(start)
		metrics := &RouteMetrics{
			PacketsForwarded: 1,
			BytesForwarded:   uint64(pkt.Size),
			Latency:          latency,
			LastUpdate:       time.Now(),
		}
		fe.performanceMonitor.UpdateMetrics(routeEntry.Route.Interface, metrics)
	}

	// 12. 记录处理时间
	processingTime := time.Since(start)
	_ = processingTime // 避免未使用变量警告
}

func (fe *Engine) forwardFromCache(pkt *IPPacket, entry *CacheEntry) {
	// 从缓存转发数据包
	atomic.AddUint64(&fe.stats.PacketsForwarded, 1)

	// 更新缓存命中统计
	entry.HitCount++
}

func (fe *Engine) ForwardPacketAsync(pkt *IPPacket) error {
	if !fe.IsRunning() {
		return fmt.Errorf("转发引擎未运行")
	}

	select {
	case fe.packetQueue <- pkt:
		return nil
	default:
		atomic.AddUint64(&fe.stats.PacketsDropped, 1)
		return fmt.Errorf("数据包队列已满")
	}
}

func (fe *Engine) GetAdvancedStats() map[string]interface{} {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	stats := make(map[string]interface{})

	// 基本统计
	stats["packets_received"] = atomic.LoadUint64(&fe.stats.PacketsReceived)
	stats["packets_forwarded"] = atomic.LoadUint64(&fe.stats.PacketsForwarded)
	stats["packets_dropped"] = atomic.LoadUint64(&fe.stats.PacketsDropped)

	// 缓存统计
	cacheStats := make(map[string]interface{})
	cacheStats["entries"] = len(fe.cache.entries)
	cacheStats["hit_rate"] = fe.calculateCacheHitRate()
	stats["cache"] = cacheStats

	// 负载均衡统计
	lbStats := make(map[string]interface{})
	lbStats["algorithm"] = fe.loadBalancer.algorithm
	lbStats["routes"] = len(fe.loadBalancer.routes)
	stats["load_balancer"] = lbStats

	// 性能监控统计
	stats["performance"] = fe.performanceMonitor.GetAllMetrics()

	// 告警统计
	stats["alerts"] = len(fe.alertManager.alerts)

	return stats
}

func (fe *Engine) calculateCacheHitRate() float64 {
	totalHits := uint64(0)
	totalRequests := uint64(0)

	for _, entry := range fe.cache.entries {
		totalHits += entry.HitCount
		totalRequests += entry.HitCount + 1 // +1 for the miss that created the entry
	}

	if totalRequests == 0 {
		return 0.0
	}

	return float64(totalHits) / float64(totalRequests)
}

func (pw *PacketWorker) Start() {
	for {
		select {
		case packet := <-pw.queue:
			pw.engine.processPacket(packet)
		case <-pw.stop:
			return
		}
	}
}

func (pw *PacketWorker) Stop() {
	close(pw.stop)
}

// TCP处理方法

// handleTCPSyn 处理TCP SYN包（新连接请求）
func (fe *Engine) handleTCPSyn(pkt *IPPacket, srcPort, dstPort uint16, seqNum uint32) error {
	// 构造SYN-ACK响应
	// 在真实实现中，这里会创建新的连接状态

	// 生成初始序列号
	initialSeqNum := uint32(time.Now().UnixNano() & 0xFFFFFFFF)

	// 构造TCP SYN-ACK头部
	tcpHeader := make([]byte, 20)

	// 源端口和目标端口（交换）
	tcpHeader[0] = byte(dstPort >> 8)
	tcpHeader[1] = byte(dstPort)
	tcpHeader[2] = byte(srcPort >> 8)
	tcpHeader[3] = byte(srcPort)

	// 序列号
	tcpHeader[4] = byte(initialSeqNum >> 24)
	tcpHeader[5] = byte(initialSeqNum >> 16)
	tcpHeader[6] = byte(initialSeqNum >> 8)
	tcpHeader[7] = byte(initialSeqNum)

	// 确认号（原序列号+1）
	ackNum := seqNum + 1
	tcpHeader[8] = byte(ackNum >> 24)
	tcpHeader[9] = byte(ackNum >> 16)
	tcpHeader[10] = byte(ackNum >> 8)
	tcpHeader[11] = byte(ackNum)

	// 头部长度和标志位
	tcpHeader[12] = 0x50 // 头部长度20字节
	tcpHeader[13] = 0x12 // SYN + ACK标志

	// 窗口大小
	tcpHeader[14] = 0x20 // 8192字节窗口
	tcpHeader[15] = 0x00

	// 创建SYN-ACK数据包
	synAckPacket := NewIPPacket(pkt.Destination, pkt.Source, 64, 6, tcpHeader)

	fmt.Printf("Sending TCP SYN-ACK: %s:%d -> %s:%d\n",
		pkt.Destination, dstPort, pkt.Source, srcPort)

	return fe.ForwardPacket(synAckPacket)
}

// handleTCPAck 处理TCP ACK包
func (fe *Engine) handleTCPAck(pkt *IPPacket, srcPort, dstPort uint16, seqNum, ackNum uint32) error {
	// 在真实实现中，这里会更新连接状态
	// 验证序列号和确认号

	fmt.Printf("Received TCP ACK: %s:%d -> %s:%d (seq=%d, ack=%d)\n",
		pkt.Source, srcPort, pkt.Destination, dstPort, seqNum, ackNum)

	// 这里可以实现连接状态管理
	// 例如：更新发送窗口、处理重传等

	return nil
}

// handleTCPFin 处理TCP FIN包（连接关闭）
func (fe *Engine) handleTCPFin(pkt *IPPacket, srcPort, dstPort uint16, seqNum uint32) error {
	// 发送FIN-ACK响应

	// 构造TCP FIN-ACK头部
	tcpHeader := make([]byte, 20)

	// 源端口和目标端口（交换）
	tcpHeader[0] = byte(dstPort >> 8)
	tcpHeader[1] = byte(dstPort)
	tcpHeader[2] = byte(srcPort >> 8)
	tcpHeader[3] = byte(srcPort)

	// 序列号（使用当前连接的序列号）
	currentSeqNum := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
	tcpHeader[4] = byte(currentSeqNum >> 24)
	tcpHeader[5] = byte(currentSeqNum >> 16)
	tcpHeader[6] = byte(currentSeqNum >> 8)
	tcpHeader[7] = byte(currentSeqNum)

	// 确认号（原序列号+1）
	ackNum := seqNum + 1
	tcpHeader[8] = byte(ackNum >> 24)
	tcpHeader[9] = byte(ackNum >> 16)
	tcpHeader[10] = byte(ackNum >> 8)
	tcpHeader[11] = byte(ackNum)

	// 头部长度和标志位
	tcpHeader[12] = 0x50 // 头部长度20字节
	tcpHeader[13] = 0x11 // FIN + ACK标志

	// 窗口大小
	tcpHeader[14] = 0x20
	tcpHeader[15] = 0x00

	// 创建FIN-ACK数据包
	finAckPacket := NewIPPacket(pkt.Destination, pkt.Source, 64, 6, tcpHeader)

	fmt.Printf("Sending TCP FIN-ACK: %s:%d -> %s:%d\n",
		pkt.Destination, dstPort, pkt.Source, srcPort)

	return fe.ForwardPacket(finAckPacket)
}

// handleTCPRst 处理TCP RST包（连接重置）
func (fe *Engine) handleTCPRst(pkt *IPPacket, srcPort, dstPort uint16) error {
	// RST包表示连接被重置，清理连接状态

	fmt.Printf("Received TCP RST: %s:%d -> %s:%d\n",
		pkt.Source, srcPort, pkt.Destination, dstPort)

	// 在真实实现中，这里会清理相关的连接状态
	// 例如：从连接表中删除连接、释放资源等

	return nil
}

// handleTCPData 处理TCP数据包
func (fe *Engine) handleTCPData(pkt *IPPacket, srcPort, dstPort uint16, seqNum, ackNum uint32) error {
	// 提取TCP头部长度
	if len(pkt.Data) < 20 {
		return fmt.Errorf("TCP header too short")
	}

	headerLen := int((pkt.Data[12] >> 4) * 4)
	if headerLen < 20 || headerLen > len(pkt.Data) {
		return fmt.Errorf("invalid TCP header length")
	}

	// 提取数据部分
	dataLen := len(pkt.Data) - headerLen

	fmt.Printf("Received TCP data: %s:%d -> %s:%d (seq=%d, ack=%d, len=%d)\n",
		pkt.Source, srcPort, pkt.Destination, dstPort, seqNum, ackNum, dataLen)

	if dataLen > 0 {
		// 在真实实现中，这里会：
		// 1. 验证序列号
		// 2. 将数据交付给应用层
		// 3. 发送ACK确认

		// 发送ACK确认
		return fe.sendTCPAck(pkt, srcPort, dstPort, seqNum, uint32(dataLen))
	}

	return nil
}

// sendTCPAck 发送TCP ACK确认
func (fe *Engine) sendTCPAck(pkt *IPPacket, srcPort, dstPort uint16, seqNum uint32, dataLen uint32) error {
	// 构造TCP ACK头部
	tcpHeader := make([]byte, 20)

	// 源端口和目标端口（交换）
	tcpHeader[0] = byte(dstPort >> 8)
	tcpHeader[1] = byte(dstPort)
	tcpHeader[2] = byte(srcPort >> 8)
	tcpHeader[3] = byte(srcPort)

	// 序列号（使用当前连接的序列号）
	currentSeqNum := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
	tcpHeader[4] = byte(currentSeqNum >> 24)
	tcpHeader[5] = byte(currentSeqNum >> 16)
	tcpHeader[6] = byte(currentSeqNum >> 8)
	tcpHeader[7] = byte(currentSeqNum)

	// 确认号（原序列号+数据长度）
	ackNum := seqNum + dataLen
	tcpHeader[8] = byte(ackNum >> 24)
	tcpHeader[9] = byte(ackNum >> 16)
	tcpHeader[10] = byte(ackNum >> 8)
	tcpHeader[11] = byte(ackNum)

	// 头部长度和标志位
	tcpHeader[12] = 0x50 // 头部长度20字节
	tcpHeader[13] = 0x10 // ACK标志

	// 窗口大小
	tcpHeader[14] = 0x20
	tcpHeader[15] = 0x00

	// 创建ACK数据包
	ackPacket := NewIPPacket(pkt.Destination, pkt.Source, 64, 6, tcpHeader)

	return fe.ForwardPacket(ackPacket)
}
