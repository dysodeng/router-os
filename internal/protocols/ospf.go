// Package protocols 实现OSPF（Open Shortest Path First）协议
// OSPF是一种基于链路状态算法的内部网关协议（IGP）
// 本实现遵循RFC 2328标准，支持区域划分、SPF算法、LSA传播等核心功能
package protocols

import (
	"container/heap"
	"fmt"
	"net"
	"sync"
	"time"

	"router-os/internal/interfaces"
	"router-os/internal/logging"
	"router-os/internal/routing"
)

// OSPF协议相关常量定义
const (
	// OSPFAllSPFRouters OSPF所有SPF路由器组播地址
	OSPFAllSPFRouters = "224.0.0.5"

	// OSPFAllDRRouters OSPF所有DR路由器组播地址
	OSPFAllDRRouters = "224.0.0.6"

	// OSPFProtocolNumber OSPF协议号
	OSPFProtocolNumber = 89

	// OSPFVersion OSPF版本号
	OSPFVersion = 2

	// OSPFHelloInterval Hello包发送间隔
	OSPFHelloInterval = 10 * time.Second

	// OSPFDeadInterval 邻居死亡间隔
	OSPFDeadInterval = 40 * time.Second

	// OSPFLSAMaxAge LSA最大生存时间
	OSPFLSAMaxAge = 3600 * time.Second

	// OSPFLSRefreshTime LSA刷新时间
	OSPFLSRefreshTime = 1800 * time.Second

	// OSPFBackboneArea 骨干区域ID
	OSPFBackboneArea = 0
)

// OSPFPacketType OSPF数据包类型
type OSPFPacketType uint8

const (
	OSPFHello     OSPFPacketType = 1
	OSPFDBDesc    OSPFPacketType = 2
	OSPFLSRequest OSPFPacketType = 3
	OSPFLSUpdate  OSPFPacketType = 4
	OSPFLSAck     OSPFPacketType = 5
)

// OSPFLSAType LSA类型
type OSPFLSAType uint8

const (
	RouterLSA   OSPFLSAType = 1
	NetworkLSA  OSPFLSAType = 2
	SummaryLSA  OSPFLSAType = 3
	ASBRSummary OSPFLSAType = 4
	ExternalLSA OSPFLSAType = 5
)

// OSPFNeighborState 邻居状态
type OSPFNeighborState uint8

const (
	NeighborDown     OSPFNeighborState = 0
	NeighborInit     OSPFNeighborState = 1
	NeighborTwoWay   OSPFNeighborState = 2
	NeighborExStart  OSPFNeighborState = 3
	NeighborExchange OSPFNeighborState = 4
	NeighborLoading  OSPFNeighborState = 5
	NeighborFull     OSPFNeighborState = 6
)

// OSPFInterfaceType 接口类型
type OSPFInterfaceType uint8

const (
	PointToPoint      OSPFInterfaceType = 1
	Broadcast         OSPFInterfaceType = 2
	NBMA              OSPFInterfaceType = 3
	PointToMultipoint OSPFInterfaceType = 4
)

// OSPFHeader OSPF数据包头部
type OSPFHeader struct {
	Version  uint8          // OSPF版本号
	Type     OSPFPacketType // 数据包类型
	Length   uint16         // 数据包长度
	RouterID uint32         // 路由器ID
	AreaID   uint32         // 区域ID
	Checksum uint16         // 校验和
	AuthType uint16         // 认证类型
	AuthData [8]byte        // 认证数据
}

// OSPFHelloPacket Hello数据包
type OSPFHelloPacket struct {
	Header             OSPFHeader
	NetworkMask        net.IPMask // 网络掩码
	HelloInterval      uint16     // Hello间隔
	Options            uint8      // 选项
	RouterPriority     uint8      // 路由器优先级
	RouterDeadInterval uint32     // 路由器死亡间隔
	DesignatedRouter   net.IP     // 指定路由器
	BackupDR           net.IP     // 备份指定路由器
	Neighbors          []net.IP   // 邻居列表
}

// OSPFLSA LSA头部
type OSPFLSA struct {
	Age         uint16      // LSA年龄
	Options     uint8       // 选项
	Type        OSPFLSAType // LSA类型
	LinkStateID uint32      // 链路状态ID
	AdvRouter   uint32      // 通告路由器
	SeqNumber   uint32      // 序列号
	Checksum    uint16      // 校验和
	Length      uint16      // 长度
	Data        []byte      // LSA数据
}

// OSPFRouterLSA 路由器LSA
type OSPFRouterLSA struct {
	Flags    uint8      // 标志位
	NumLinks uint16     // 链路数量
	Links    []OSPFLink // 链路列表
}

// OSPFLink 路由器链路
type OSPFLink struct {
	LinkID   uint32 // 链路ID
	LinkData uint32 // 链路数据
	Type     uint8  // 链路类型
	NumTOS   uint8  // TOS数量
	Metric   uint16 // 度量值
}

// OSPFNetworkLSA 网络LSA
type OSPFNetworkLSA struct {
	NetworkMask net.IPMask // 网络掩码
	Routers     []uint32   // 连接的路由器列表
}

// OSPFArea OSPF区域
type OSPFArea struct {
	AreaID     uint32                    // 区域ID
	Interfaces map[string]*OSPFInterface // 接口列表
	LSDB       map[string]*OSPFLSA       // 链路状态数据库
	mu         sync.RWMutex              // 读写锁
}

// OSPFInterface OSPF接口
type OSPFInterface struct {
	Name             string                   // 接口名称
	Type             OSPFInterfaceType        // 接口类型
	State            uint8                    // 接口状态
	IPAddress        net.IP                   // IP地址
	NetworkMask      net.IPMask               // 网络掩码
	AreaID           uint32                   // 所属区域ID
	Cost             uint16                   // 接口开销
	Priority         uint8                    // 路由器优先级
	HelloInterval    time.Duration            // Hello间隔
	DeadInterval     time.Duration            // 死亡间隔
	DesignatedRouter net.IP                   // 指定路由器
	BackupDR         net.IP                   // 备份指定路由器
	Neighbors        map[string]*OSPFNeighbor // 邻居列表
	mu               sync.RWMutex             // 读写锁
}

// OSPFNeighbor OSPF邻居
type OSPFNeighbor struct {
	RouterID         uint32            // 路由器ID
	IPAddress        net.IP            // IP地址
	State            OSPFNeighborState // 邻居状态
	Priority         uint8             // 优先级
	DesignatedRouter net.IP            // 指定路由器
	BackupDR         net.IP            // 备份指定路由器
	LastSeen         time.Time         // 最后见到时间
	DBSummary        []*OSPFLSA        // 数据库摘要
	LSRequestList    []*OSPFLSA        // LSA请求列表
	LSRetransList    []*OSPFLSA        // LSA重传列表
	mu               sync.RWMutex      // 读写锁
}

// OSPFManager OSPF协议管理器
type OSPFManager struct {
	routerID         uint32                        // 路由器ID
	areas            map[uint32]*OSPFArea          // 区域列表
	routingTable     routing.RoutingTableInterface // 路由表
	interfaceManager *interfaces.Manager           // 接口管理器
	running          bool                          // 运行状态
	mu               sync.RWMutex                  // 读写锁
	logger           *logging.Logger               // 日志记录器
}

// NewOSPFManager 创建OSPF管理器
func NewOSPFManager(routingTable routing.RoutingTableInterface, interfaceManager *interfaces.Manager) *OSPFManager {
	return &OSPFManager{
		routerID:         generateRouterID(),
		areas:            make(map[uint32]*OSPFArea),
		routingTable:     routingTable,
		interfaceManager: interfaceManager,
		running:          false,
		logger:           logging.GetLogger(),
	}
}

// Start 启动OSPF协议
func (om *OSPFManager) Start() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if om.running {
		return fmt.Errorf("OSPF协议已经在运行")
	}

	om.logger.Info("启动OSPF协议")

	// 创建骨干区域
	om.areas[OSPFBackboneArea] = &OSPFArea{
		AreaID:     OSPFBackboneArea,
		Interfaces: make(map[string]*OSPFInterface),
		LSDB:       make(map[string]*OSPFLSA),
	}

	// 初始化接口
	if err := om.initializeInterfaces(); err != nil {
		return fmt.Errorf("初始化接口失败: %v", err)
	}

	om.running = true

	// 启动定时器
	go om.helloTimer()
	go om.lsaAging()
	go om.spfCalculation()

	return nil
}

// Stop 停止OSPF协议
func (om *OSPFManager) Stop() {
	om.mu.Lock()
	defer om.mu.Unlock()

	if !om.running {
		return
	}

	om.logger.Info("停止OSPF协议")
	om.running = false

	// 清理资源
	for _, area := range om.areas {
		for _, iface := range area.Interfaces {
			for _, neighbor := range iface.Neighbors {
				neighbor.State = NeighborDown
			}
		}
	}
}

// IsRunning 检查OSPF是否运行
func (om *OSPFManager) IsRunning() bool {
	om.mu.RLock()
	defer om.mu.RUnlock()
	return om.running
}

// initializeInterfaces 初始化接口
func (om *OSPFManager) initializeInterfaces() error {
	interfaces := om.interfaceManager.GetAllInterfaces()

	for _, iface := range interfaces {
		if iface.Status != 0 { // 只处理UP状态的接口
			continue
		}

		ospfIface := &OSPFInterface{
			Name:          iface.Name,
			Type:          Broadcast, // 默认为广播类型
			IPAddress:     iface.IPAddress,
			NetworkMask:   iface.Netmask,
			AreaID:        OSPFBackboneArea, // 默认加入骨干区域
			Cost:          calculateInterfaceCost(iface),
			Priority:      1,
			HelloInterval: OSPFHelloInterval,
			DeadInterval:  OSPFDeadInterval,
			Neighbors:     make(map[string]*OSPFNeighbor),
		}

		om.areas[OSPFBackboneArea].Interfaces[iface.Name] = ospfIface
		om.logger.Info(fmt.Sprintf("OSPF接口 %s 已初始化", iface.Name))
	}

	return nil
}

// helloTimer Hello定时器
func (om *OSPFManager) helloTimer() {
	ticker := time.NewTicker(OSPFHelloInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !om.IsRunning() {
				return
			}
			om.sendHelloPackets()
		}
	}
}

// sendHelloPackets 发送Hello数据包
func (om *OSPFManager) sendHelloPackets() {
	om.mu.RLock()
	defer om.mu.RUnlock()

	for _, area := range om.areas {
		for _, iface := range area.Interfaces {
			om.sendHelloPacket(iface)
		}
	}
}

// sendHelloPacket 发送Hello数据包到指定接口
func (om *OSPFManager) sendHelloPacket(iface *OSPFInterface) {
	hello := &OSPFHelloPacket{
		Header: OSPFHeader{
			Version:  OSPFVersion,
			Type:     OSPFHello,
			RouterID: om.routerID,
			AreaID:   iface.AreaID,
		},
		NetworkMask:        iface.NetworkMask,
		HelloInterval:      uint16(iface.HelloInterval.Seconds()),
		RouterPriority:     iface.Priority,
		RouterDeadInterval: uint32(iface.DeadInterval.Seconds()),
		DesignatedRouter:   iface.DesignatedRouter,
		BackupDR:           iface.BackupDR,
	}

	// 添加邻居列表
	iface.mu.RLock()
	for _, neighbor := range iface.Neighbors {
		hello.Neighbors = append(hello.Neighbors, neighbor.IPAddress)
	}
	iface.mu.RUnlock()

	om.logger.Debug(fmt.Sprintf("发送Hello数据包到接口 %s", iface.Name))
	// 这里应该实际发送数据包，简化实现
}

// ProcessHelloPacket 处理Hello数据包
func (om *OSPFManager) ProcessHelloPacket(packet *OSPFHelloPacket, sourceIP net.IP, receivedInterface string) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	// 查找接口
	var targetInterface *OSPFInterface
	for _, area := range om.areas {
		if iface, exists := area.Interfaces[receivedInterface]; exists {
			targetInterface = iface
			break
		}
	}

	if targetInterface == nil {
		return fmt.Errorf("未找到接口 %s", receivedInterface)
	}

	// 检查网络掩码
	if packet.NetworkMask.String() != targetInterface.NetworkMask.String() {
		om.logger.Warn(fmt.Sprintf("Hello数据包网络掩码不匹配: %s", sourceIP))
		return nil
	}

	// 检查Hello间隔和死亡间隔
	if time.Duration(packet.HelloInterval)*time.Second != targetInterface.HelloInterval ||
		time.Duration(packet.RouterDeadInterval)*time.Second != targetInterface.DeadInterval {
		om.logger.Warn(fmt.Sprintf("Hello数据包定时器参数不匹配: %s", sourceIP))
		return nil
	}

	// 处理邻居
	neighborKey := sourceIP.String()
	neighbor, exists := targetInterface.Neighbors[neighborKey]

	if !exists {
		// 创建新邻居
		neighbor = &OSPFNeighbor{
			RouterID:         packet.Header.RouterID,
			IPAddress:        sourceIP,
			State:            NeighborInit,
			Priority:         packet.RouterPriority,
			DesignatedRouter: packet.DesignatedRouter,
			BackupDR:         packet.BackupDR,
			LastSeen:         time.Now(),
		}
		targetInterface.Neighbors[neighborKey] = neighbor
		om.logger.Info(fmt.Sprintf("发现新邻居: %s", sourceIP))
	} else {
		// 更新现有邻居
		neighbor.LastSeen = time.Now()
		neighbor.Priority = packet.RouterPriority
		neighbor.DesignatedRouter = packet.DesignatedRouter
		neighbor.BackupDR = packet.BackupDR
	}

	// 检查是否在邻居列表中看到自己
	myIP := targetInterface.IPAddress
	for _, neighborIP := range packet.Neighbors {
		if neighborIP.Equal(myIP) {
			if neighbor.State == NeighborInit {
				neighbor.State = NeighborTwoWay
				om.logger.Info(fmt.Sprintf("邻居 %s 状态变为TwoWay", sourceIP))
			}
			break
		}
	}

	return nil
}

// lsaAging LSA老化处理
func (om *OSPFManager) lsaAging() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !om.IsRunning() {
				return
			}
			om.ageLSAs()
		}
	}
}

// ageLSAs 老化LSA
func (om *OSPFManager) ageLSAs() {
	om.mu.Lock()
	defer om.mu.Unlock()

	for _, area := range om.areas {
		area.mu.Lock()
		for lsaKey, lsa := range area.LSDB {
			lsa.Age++
			if time.Duration(lsa.Age)*time.Second >= OSPFLSAMaxAge {
				delete(area.LSDB, lsaKey)
				om.logger.Debug(fmt.Sprintf("LSA %s 已过期并删除", lsaKey))
			}
		}
		area.mu.Unlock()
	}
}

// spfCalculation SPF计算
func (om *OSPFManager) spfCalculation() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !om.IsRunning() {
				return
			}
			om.calculateSPF()
		}
	}
}

// calculateSPF 计算最短路径优先
func (om *OSPFManager) calculateSPF() {
	om.mu.RLock()
	defer om.mu.RUnlock()

	for areaID, area := range om.areas {
		om.logger.Debug(fmt.Sprintf("开始计算区域 %d 的SPF", areaID))
		om.dijkstra(area)
	}
}

// SPFNode SPF节点
type SPFNode struct {
	RouterID uint32
	Cost     uint32
	Parent   uint32
	Index    int // 用于堆操作
}

// PriorityQueue 优先队列实现
type PriorityQueue []*SPFNode

func (pq PriorityQueue) Len() int           { return len(pq) }
func (pq PriorityQueue) Less(i, j int) bool { return pq[i].Cost < pq[j].Cost }
func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].Index = i
	pq[j].Index = j
}
func (pq *PriorityQueue) Push(x interface{}) {
	n := len(*pq)
	node := x.(*SPFNode)
	node.Index = n
	*pq = append(*pq, node)
}
func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	node := old[n-1]
	old[n-1] = nil
	node.Index = -1
	*pq = old[0 : n-1]
	return node
}

// dijkstra Dijkstra算法实现
func (om *OSPFManager) dijkstra(area *OSPFArea) {
	// 初始化
	distances := make(map[uint32]uint32)
	previous := make(map[uint32]uint32)
	visited := make(map[uint32]bool)

	pq := &PriorityQueue{}
	heap.Init(pq)

	// 添加根节点（本路由器）
	root := &SPFNode{
		RouterID: om.routerID,
		Cost:     0,
		Parent:   0,
	}
	heap.Push(pq, root)
	distances[om.routerID] = 0

	// Dijkstra主循环
	for pq.Len() > 0 {
		current := heap.Pop(pq).(*SPFNode)

		if visited[current.RouterID] {
			continue
		}
		visited[current.RouterID] = true

		// 处理邻接节点
		om.processAdjacentNodes(area, current, distances, previous, pq, visited)
	}

	// 根据SPF结果更新路由表
	om.updateRoutingTableFromSPF(area, distances, previous)
}

// processAdjacentNodes 处理邻接节点
func (om *OSPFManager) processAdjacentNodes(area *OSPFArea, current *SPFNode,
	distances map[uint32]uint32, previous map[uint32]uint32,
	pq *PriorityQueue, visited map[uint32]bool) {

	// 查找当前节点的LSA
	area.mu.RLock()
	defer area.mu.RUnlock()

	for _, lsa := range area.LSDB {
		if lsa.Type == RouterLSA && lsa.AdvRouter == current.RouterID {
			// 解析路由器LSA
			routerLSA := om.parseRouterLSA(lsa.Data)

			for _, link := range routerLSA.Links {
				neighborID := link.LinkID
				cost := current.Cost + uint32(link.Metric)

				if visited[neighborID] {
					continue
				}

				if existingCost, exists := distances[neighborID]; !exists || cost < existingCost {
					distances[neighborID] = cost
					previous[neighborID] = current.RouterID

					neighbor := &SPFNode{
						RouterID: neighborID,
						Cost:     cost,
						Parent:   current.RouterID,
					}
					heap.Push(pq, neighbor)
				}
			}
		}
	}
}

// parseRouterLSA 解析路由器LSA
func (om *OSPFManager) parseRouterLSA(data []byte) *OSPFRouterLSA {
	// 简化实现，实际应该解析二进制数据
	return &OSPFRouterLSA{
		Flags:    0,
		NumLinks: 0,
		Links:    []OSPFLink{},
	}
}

// updateRoutingTableFromSPF 根据SPF结果更新路由表
func (om *OSPFManager) updateRoutingTableFromSPF(area *OSPFArea, distances map[uint32]uint32, previous map[uint32]uint32) {
	// 遍历SPF树，为每个目标创建路由
	for routerID, cost := range distances {
		if routerID == om.routerID {
			continue // 跳过自己
		}

		// 查找下一跳
		nextHop := om.findNextHop(routerID, previous)
		if nextHop == 0 {
			continue
		}

		// 查找下一跳对应的接口和IP
		nextHopIP, iface := om.findNextHopInterface(nextHop)
		if nextHopIP == nil || iface == "" {
			continue
		}

		// 创建路由条目
		destination := &net.IPNet{
			IP:   intToIP(routerID),
			Mask: net.CIDRMask(32, 32), // 主机路由
		}

		route := &routing.Route{
			Destination: destination,
			Gateway:     nextHopIP,
			Interface:   iface,
			Metric:      int(cost),
			Type:        3, // OSPF路由类型
			Age:         time.Now(),
		}

		// 添加到路由表
		om.routingTable.AddRoute(*route)
	}
}

// findNextHop 查找下一跳
func (om *OSPFManager) findNextHop(target uint32, previous map[uint32]uint32) uint32 {
	current := target
	for {
		parent, exists := previous[current]
		if !exists || parent == om.routerID {
			return current
		}
		current = parent
	}
}

// findNextHopInterface 查找下一跳对应的接口
func (om *OSPFManager) findNextHopInterface(nextHop uint32) (net.IP, string) {
	for _, area := range om.areas {
		for ifaceName, iface := range area.Interfaces {
			for _, neighbor := range iface.Neighbors {
				if neighbor.RouterID == nextHop {
					return neighbor.IPAddress, ifaceName
				}
			}
		}
	}
	return nil, ""
}

// 辅助函数

// generateRouterID 生成路由器ID
func generateRouterID() uint32 {
	// 简化实现，实际应该基于接口IP地址
	return 0x01010101 // 1.1.1.1
}

// calculateInterfaceCost 计算接口开销
func calculateInterfaceCost(iface *interfaces.Interface) uint16 {
	// 简化实现，基于接口MTU计算开销
	// 实际应该基于带宽：cost = 10^8 / bandwidth
	if iface.MTU >= 1500 {
		return 1
	}
	return 10
}

// intToIP 将uint32转换为IP地址
func intToIP(i uint32) net.IP {
	return net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
}

// GetRouterID 获取路由器ID
func (om *OSPFManager) GetRouterID() uint32 {
	om.mu.RLock()
	defer om.mu.RUnlock()
	return om.routerID
}

// GetAreas 获取所有区域
func (om *OSPFManager) GetAreas() map[uint32]*OSPFArea {
	om.mu.RLock()
	defer om.mu.RUnlock()

	areas := make(map[uint32]*OSPFArea)
	for id, area := range om.areas {
		areas[id] = area
	}
	return areas
}

// GetNeighbors 获取所有邻居
func (om *OSPFManager) GetNeighbors() map[string]*OSPFNeighbor {
	om.mu.RLock()
	defer om.mu.RUnlock()

	neighbors := make(map[string]*OSPFNeighbor)
	for _, area := range om.areas {
		for _, iface := range area.Interfaces {
			for key, neighbor := range iface.Neighbors {
				neighbors[key] = neighbor
			}
		}
	}
	return neighbors
}
