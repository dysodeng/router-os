// Package protocols 实现BGP（Border Gateway Protocol）协议
// BGP是一种基于路径向量算法的外部网关协议（EGP）
// 本实现遵循RFC 4271标准，支持BGP-4协议的核心功能
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

// BGP协议相关常量定义
const (
	// BGPPort BGP协议使用的TCP端口号
	BGPPort = 179

	// BGPVersion BGP协议版本号
	BGPVersion = 4

	// BGPKeepaliveTime BGP Keepalive时间
	BGPKeepaliveTime = 60 * time.Second

	// BGPHoldTime BGP Hold时间
	BGPHoldTime = 180 * time.Second

	// BGPConnectRetryTime BGP连接重试时间
	BGPConnectRetryTime = 120 * time.Second

	// BGPMaxMessageSize BGP最大消息大小
	BGPMaxMessageSize = 4096
)

// BGPMessageType BGP消息类型
type BGPMessageType uint8

const (
	BGPOpen         BGPMessageType = 1
	BGPUpdate       BGPMessageType = 2
	BGPNotification BGPMessageType = 3
	BGPKeepalive    BGPMessageType = 4
)

// BGPPeerState BGP邻居状态
type BGPPeerState uint8

const (
	BGPIdle        BGPPeerState = 0
	BGPConnect     BGPPeerState = 1
	BGPActive      BGPPeerState = 2
	BGPOpenSent    BGPPeerState = 3
	BGPOpenConfirm BGPPeerState = 4
	BGPEstablished BGPPeerState = 5
)

// BGPOrigin BGP Origin属性
type BGPOrigin uint8

const (
	OriginIGP        BGPOrigin = 0
	OriginEGP        BGPOrigin = 1
	OriginIncomplete BGPOrigin = 2
)

// BGPPathAttributeType BGP路径属性类型
type BGPPathAttributeType uint8

const (
	BGPAttrOrigin    BGPPathAttributeType = 1
	BGPAttrASPath    BGPPathAttributeType = 2
	BGPAttrNextHop   BGPPathAttributeType = 3
	BGPAttrMED       BGPPathAttributeType = 4
	BGPAttrLocalPref BGPPathAttributeType = 5
	BGPAttrCommunity BGPPathAttributeType = 8
)

// BGPHeader BGP消息头部
type BGPHeader struct {
	Marker [16]byte       // 标记字段
	Length uint16         // 消息长度
	Type   BGPMessageType // 消息类型
}

// BGPOpenMessage BGP Open消息
type BGPOpenMessage struct {
	Header         BGPHeader
	Version        uint8  // BGP版本
	MyAS           uint16 // 本地AS号
	HoldTime       uint16 // Hold时间
	BGPIdentifier  uint32 // BGP标识符
	OptParamLength uint8  // 可选参数长度
	OptionalParams []byte // 可选参数
}

// BGPUpdateMessage BGP Update消息
type BGPUpdateMessage struct {
	Header                BGPHeader
	WithdrawnRoutesLength uint16             // 撤销路由长度
	WithdrawnRoutes       []*net.IPNet       // 撤销路由列表
	PathAttributesLength  uint16             // 路径属性长度
	PathAttributes        []BGPPathAttribute // 路径属性列表
	NLRI                  []*net.IPNet       // 网络层可达性信息
}

// BGPPathAttribute BGP路径属性
type BGPPathAttribute struct {
	Flags  uint8                // 属性标志
	Type   BGPPathAttributeType // 属性类型
	Length uint16               // 属性长度
	Value  []byte               // 属性值
}

// BGPNotificationMessage BGP Notification消息
type BGPNotificationMessage struct {
	Header       BGPHeader
	ErrorCode    uint8  // 错误代码
	ErrorSubcode uint8  // 错误子代码
	Data         []byte // 错误数据
}

// BGPKeepaliveMessage BGP Keepalive消息
type BGPKeepaliveMessage struct {
	Header BGPHeader
}

// BGPRoute BGP路由条目
type BGPRoute struct {
	Prefix     *net.IPNet         // 路由前缀
	NextHop    net.IP             // 下一跳
	ASPath     []uint16           // AS路径
	Origin     BGPOrigin          // 起源
	MED        uint32             // 多出口判别符
	LocalPref  uint32             // 本地优先级
	Community  []uint32           // 团体属性
	Attributes []BGPPathAttribute // 其他路径属性
	Age        time.Time          // 路由年龄
	Source     string             // 路由来源
}

// BGPPeer BGP邻居
type BGPPeer struct {
	Address          net.IP               // 邻居IP地址
	AS               uint16               // 邻居AS号
	State            BGPPeerState         // 邻居状态
	HoldTime         time.Duration        // Hold时间
	KeepaliveTime    time.Duration        // Keepalive时间
	ConnectRetryTime time.Duration        // 连接重试时间
	LastKeepalive    time.Time            // 最后Keepalive时间
	LastUpdate       time.Time            // 最后更新时间
	EstablishedTime  time.Time            // 建立连接时间
	Routes           map[string]*BGPRoute // 从该邻居学到的路由
	mu               sync.RWMutex         // 读写锁
}

// BGPRIBEntry RIB条目
type BGPRIBEntry struct {
	Prefix    *net.IPNet
	Routes    []*BGPRoute // 到达该前缀的所有路由
	BestRoute *BGPRoute   // 最优路由
	mu        sync.RWMutex
}

// BGPManager BGP协议管理器
type BGPManager struct {
	localAS          uint16                        // 本地AS号
	routerID         uint32                        // 路由器ID
	peers            map[string]*BGPPeer           // BGP邻居列表
	ribIn            map[string]*BGPRIBEntry       // Adj-RIB-In
	ribOut           map[string]*BGPRIBEntry       // Adj-RIB-Out
	locRIB           map[string]*BGPRIBEntry       // Loc-RIB
	routingTable     routing.RoutingTableInterface // 路由表
	interfaceManager *interfaces.Manager           // 接口管理器
	running          bool                          // 运行状态
	mu               sync.RWMutex                  // 读写锁
	logger           *logging.Logger               // 日志记录器
}

// NewBGPManager 创建BGP管理器
func NewBGPManager(localAS uint16, routingTable routing.RoutingTableInterface, interfaceManager *interfaces.Manager) *BGPManager {
	return &BGPManager{
		localAS:          localAS,
		routerID:         generateBGPRouterID(),
		peers:            make(map[string]*BGPPeer),
		ribIn:            make(map[string]*BGPRIBEntry),
		ribOut:           make(map[string]*BGPRIBEntry),
		locRIB:           make(map[string]*BGPRIBEntry),
		routingTable:     routingTable,
		interfaceManager: interfaceManager,
		running:          false,
		logger:           logging.GetLogger(),
	}
}

// Start 启动BGP协议
func (bm *BGPManager) Start() error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if bm.running {
		return fmt.Errorf("BGP协议已经在运行")
	}

	bm.logger.Info("启动BGP协议")
	bm.running = true

	// 启动定时器
	go bm.keepaliveTimer()
	go bm.holdTimer()
	go bm.connectRetryTimer()
	go bm.routeSelection()

	return nil
}

// Stop 停止BGP协议
func (bm *BGPManager) Stop() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if !bm.running {
		return
	}

	bm.logger.Info("停止BGP协议")
	bm.running = false

	// 关闭所有BGP会话
	for _, peer := range bm.peers {
		peer.State = BGPIdle
	}
}

// IsRunning 检查BGP是否运行
func (bm *BGPManager) IsRunning() bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.running
}

// AddPeer 添加BGP邻居
func (bm *BGPManager) AddPeer(address net.IP, as uint16) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	peerKey := address.String()
	if _, exists := bm.peers[peerKey]; exists {
		return fmt.Errorf("BGP邻居 %s 已存在", address)
	}

	peer := &BGPPeer{
		Address:          address,
		AS:               as,
		State:            BGPIdle,
		HoldTime:         BGPHoldTime,
		KeepaliveTime:    BGPKeepaliveTime,
		ConnectRetryTime: BGPConnectRetryTime,
		Routes:           make(map[string]*BGPRoute),
	}

	bm.peers[peerKey] = peer
	bm.logger.Info(fmt.Sprintf("添加BGP邻居: %s (AS %d)", address, as))

	// 启动连接
	go bm.connectToPeer(peer)

	return nil
}

// RemovePeer 删除BGP邻居
func (bm *BGPManager) RemovePeer(address net.IP) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	peerKey := address.String()
	peer, exists := bm.peers[peerKey]
	if !exists {
		return fmt.Errorf("BGP邻居 %s 不存在", address)
	}

	// 撤销从该邻居学到的所有路由
	bm.withdrawRoutesFromPeer(peer)

	delete(bm.peers, peerKey)
	bm.logger.Info(fmt.Sprintf("删除BGP邻居: %s", address))

	return nil
}

// connectToPeer 连接到BGP邻居
func (bm *BGPManager) connectToPeer(peer *BGPPeer) {
	peer.mu.Lock()
	defer peer.mu.Unlock()

	if peer.State != BGPIdle {
		return
	}

	bm.logger.Info(fmt.Sprintf("尝试连接BGP邻居: %s", peer.Address))
	peer.State = BGPConnect

	// 这里应该建立TCP连接，简化实现
	// 模拟连接成功
	time.Sleep(time.Second)

	if bm.sendOpenMessage(peer) {
		peer.State = BGPOpenSent
		bm.logger.Info(fmt.Sprintf("发送Open消息到邻居: %s", peer.Address))
	} else {
		peer.State = BGPIdle
		bm.logger.Warn(fmt.Sprintf("连接邻居失败: %s", peer.Address))
	}
}

// sendOpenMessage 发送Open消息
func (bm *BGPManager) sendOpenMessage(peer *BGPPeer) bool {
	open := &BGPOpenMessage{
		Header: BGPHeader{
			Type: BGPOpen,
		},
		Version:       BGPVersion,
		MyAS:          bm.localAS,
		HoldTime:      uint16(peer.HoldTime.Seconds()),
		BGPIdentifier: bm.routerID,
	}
	
	// 这里应该实际发送消息，简化实现
	bm.logger.Debug(fmt.Sprintf("发送BGP Open消息到 %s (AS: %d, Hold: %d)", 
		peer.Address, open.MyAS, open.HoldTime))
	return true
}

// ProcessOpenMessage 处理Open消息
func (bm *BGPManager) ProcessOpenMessage(message *BGPOpenMessage, peer *BGPPeer) error {
	peer.mu.Lock()
	defer peer.mu.Unlock()

	if peer.State != BGPOpenSent && peer.State != BGPConnect {
		return fmt.Errorf("BGP邻居 %s 状态错误: %d", peer.Address, peer.State)
	}

	// 验证BGP版本
	if message.Version != BGPVersion {
		bm.sendNotification(peer, 2, 1, nil) // Version Error
		return fmt.Errorf("BGP版本不匹配: %d", message.Version)
	}

	// 验证AS号
	if message.MyAS != peer.AS {
		bm.sendNotification(peer, 2, 2, nil) // Bad Peer AS
		return fmt.Errorf("AS号不匹配: %d", message.MyAS)
	}

	// 更新Hold时间
	if message.HoldTime < uint16(peer.HoldTime.Seconds()) {
		peer.HoldTime = time.Duration(message.HoldTime) * time.Second
	}

	// 发送Keepalive消息
	bm.sendKeepalive(peer)

	if peer.State == BGPOpenSent {
		peer.State = BGPOpenConfirm
	} else {
		peer.State = BGPEstablished
		peer.EstablishedTime = time.Now()
		bm.logger.Info(fmt.Sprintf("BGP会话建立: %s", peer.Address))
	}

	return nil
}

// ProcessUpdateMessage 处理Update消息
func (bm *BGPManager) ProcessUpdateMessage(message *BGPUpdateMessage, peer *BGPPeer) error {
	peer.mu.Lock()
	defer peer.mu.Unlock()

	if peer.State != BGPEstablished {
		return fmt.Errorf("BGP邻居 %s 未建立连接", peer.Address)
	}

	// 处理撤销路由
	for _, prefix := range message.WithdrawnRoutes {
		bm.withdrawRoute(prefix, peer)
	}

	// 处理新路由
	if len(message.NLRI) > 0 {
		route := bm.parsePathAttributes(message.PathAttributes)
		route.Source = peer.Address.String()
		route.Age = time.Now()

		for _, prefix := range message.NLRI {
			route.Prefix = prefix
			bm.installRoute(route, peer)
		}
	}

	peer.LastUpdate = time.Now()
	return nil
}

// parsePathAttributes 解析路径属性
func (bm *BGPManager) parsePathAttributes(attributes []BGPPathAttribute) *BGPRoute {
	route := &BGPRoute{
		ASPath:    []uint16{},
		Community: []uint32{},
	}

	for _, attr := range attributes {
		switch attr.Type {
		case BGPAttrOrigin:
			if len(attr.Value) > 0 {
				route.Origin = BGPOrigin(attr.Value[0])
			}
		case BGPAttrASPath:
			route.ASPath = bm.parseASPath(attr.Value)
		case BGPAttrNextHop:
			if len(attr.Value) >= 4 {
				route.NextHop = net.IPv4(attr.Value[0], attr.Value[1], attr.Value[2], attr.Value[3])
			}
		case BGPAttrMED:
			if len(attr.Value) >= 4 {
				route.MED = uint32(attr.Value[0])<<24 | uint32(attr.Value[1])<<16 |
					uint32(attr.Value[2])<<8 | uint32(attr.Value[3])
			}
		case BGPAttrLocalPref:
			if len(attr.Value) >= 4 {
				route.LocalPref = uint32(attr.Value[0])<<24 | uint32(attr.Value[1])<<16 |
					uint32(attr.Value[2])<<8 | uint32(attr.Value[3])
			}
		}
	}

	return route
}

// parseASPath 解析AS路径
func (bm *BGPManager) parseASPath(data []byte) []uint16 {
	var asPath []uint16

	// 简化实现，实际应该解析AS_SEQUENCE和AS_SET
	for i := 0; i < len(data)-1; i += 2 {
		as := uint16(data[i])<<8 | uint16(data[i+1])
		asPath = append(asPath, as)
	}

	return asPath
}

// installRoute 安装路由
func (bm *BGPManager) installRoute(route *BGPRoute, peer *BGPPeer) {
	prefixKey := route.Prefix.String()

	// 添加到Adj-RIB-In
	if entry, exists := bm.ribIn[prefixKey]; exists {
		entry.mu.Lock()
		entry.Routes = append(entry.Routes, route)
		entry.mu.Unlock()
	} else {
		bm.ribIn[prefixKey] = &BGPRIBEntry{
			Prefix: route.Prefix,
			Routes: []*BGPRoute{route},
		}
	}

	// 添加到邻居的路由表
	peer.Routes[prefixKey] = route

	// 触发路由选择
	bm.selectBestRoute(prefixKey)

	bm.logger.Debug(fmt.Sprintf("安装BGP路由: %s via %s", route.Prefix, route.NextHop))
}

// withdrawRoute 撤销路由
func (bm *BGPManager) withdrawRoute(prefix *net.IPNet, peer *BGPPeer) {
	prefixKey := prefix.String()

	// 从邻居路由表中删除
	delete(peer.Routes, prefixKey)

	// 从Adj-RIB-In中删除
	if entry, exists := bm.ribIn[prefixKey]; exists {
		entry.mu.Lock()
		newRoutes := []*BGPRoute{}
		for _, route := range entry.Routes {
			if route.Source != peer.Address.String() {
				newRoutes = append(newRoutes, route)
			}
		}
		entry.Routes = newRoutes
		entry.mu.Unlock()

		// 重新选择最优路由
		bm.selectBestRoute(prefixKey)
	}

	bm.logger.Debug(fmt.Sprintf("撤销BGP路由: %s", prefix))
}

// selectBestRoute 选择最优路由
func (bm *BGPManager) selectBestRoute(prefixKey string) {
	entry, exists := bm.ribIn[prefixKey]
	if !exists || len(entry.Routes) == 0 {
		// 删除Loc-RIB中的条目
		delete(bm.locRIB, prefixKey)
		return
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	// BGP路由选择算法
	var bestRoute *BGPRoute
	for _, route := range entry.Routes {
		if bestRoute == nil || bm.compareBGPRoutes(route, bestRoute) {
			bestRoute = route
		}
	}

	entry.BestRoute = bestRoute

	// 更新Loc-RIB
	bm.locRIB[prefixKey] = &BGPRIBEntry{
		Prefix:    entry.Prefix,
		Routes:    []*BGPRoute{bestRoute},
		BestRoute: bestRoute,
	}

	// 安装到路由表
	bm.installToRoutingTable(bestRoute)
}

// compareBGPRoutes BGP路由比较
func (bm *BGPManager) compareBGPRoutes(route1, route2 *BGPRoute) bool {
	// 1. 本地优先级（越大越优）
	if route1.LocalPref != route2.LocalPref {
		return route1.LocalPref > route2.LocalPref
	}

	// 2. AS路径长度（越短越优）
	if len(route1.ASPath) != len(route2.ASPath) {
		return len(route1.ASPath) < len(route2.ASPath)
	}

	// 3. Origin（IGP > EGP > Incomplete）
	if route1.Origin != route2.Origin {
		return route1.Origin < route2.Origin
	}

	// 4. MED（越小越优）
	if route1.MED != route2.MED {
		return route1.MED < route2.MED
	}

	// 5. 路由年龄（越新越优）
	return route1.Age.After(route2.Age)
}

// installToRoutingTable 安装到路由表
func (bm *BGPManager) installToRoutingTable(route *BGPRoute) {
	routeEntry := routing.Route{
		Destination: route.Prefix,
		Gateway:     route.NextHop,
		Interface:   bm.findOutputInterface(route.NextHop),
		Metric:      int(route.MED),
		Type:        4, // BGP路由类型
		Age:         route.Age,
	}

	bm.routingTable.AddRoute(routeEntry)
}

// findOutputInterface 查找输出接口
func (bm *BGPManager) findOutputInterface(nextHop net.IP) string {
	interfaces := bm.interfaceManager.GetAllInterfaces()

	for _, iface := range interfaces {
		if iface.IPAddress != nil && iface.Netmask != nil {
			network := &net.IPNet{IP: iface.IPAddress.Mask(iface.Netmask), Mask: iface.Netmask}
			if network.Contains(nextHop) {
				return iface.Name
			}
		}
	}

	return "unknown"
}

// withdrawRoutesFromPeer 撤销来自指定邻居的所有路由
func (bm *BGPManager) withdrawRoutesFromPeer(peer *BGPPeer) {
	peer.mu.RLock()
	defer peer.mu.RUnlock()

	for prefixKey := range peer.Routes {
		if prefix, err := parsePrefix(prefixKey); err == nil {
			bm.withdrawRoute(prefix, peer)
		}
	}
}

// parsePrefix 解析前缀字符串
func parsePrefix(prefixStr string) (*net.IPNet, error) {
	_, network, err := net.ParseCIDR(prefixStr)
	return network, err
}

// 定时器相关方法

// keepaliveTimer Keepalive定时器
func (bm *BGPManager) keepaliveTimer() {
	ticker := time.NewTicker(BGPKeepaliveTime)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !bm.IsRunning() {
				return
			}
			bm.sendKeepaliveToAllPeers()
		}
	}
}

// sendKeepaliveToAllPeers 向所有邻居发送Keepalive
func (bm *BGPManager) sendKeepaliveToAllPeers() {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	for _, peer := range bm.peers {
		if peer.State == BGPEstablished {
			bm.sendKeepalive(peer)
		}
	}
}

// sendKeepalive 发送Keepalive消息
func (bm *BGPManager) sendKeepalive(peer *BGPPeer) {
	keepalive := &BGPKeepaliveMessage{
		Header: BGPHeader{
			Type: BGPKeepalive,
		},
	}
	
	// 这里应该实际发送消息，简化实现
	bm.logger.Debug(fmt.Sprintf("发送BGP Keepalive到 %s (Type: %d)", peer.Address, keepalive.Header.Type))
	peer.LastKeepalive = time.Now()
}

// holdTimer Hold定时器
func (bm *BGPManager) holdTimer() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !bm.IsRunning() {
				return
			}
			bm.checkHoldTimers()
		}
	}
}

// checkHoldTimers 检查Hold定时器
func (bm *BGPManager) checkHoldTimers() {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	now := time.Now()
	for _, peer := range bm.peers {
		if peer.State == BGPEstablished {
			if now.Sub(peer.LastKeepalive) > peer.HoldTime {
				bm.logger.Warn(fmt.Sprintf("BGP邻居 %s Hold定时器超时", peer.Address))
				peer.State = BGPIdle
				bm.withdrawRoutesFromPeer(peer)
			}
		}
	}
}

// connectRetryTimer 连接重试定时器
func (bm *BGPManager) connectRetryTimer() {
	ticker := time.NewTicker(BGPConnectRetryTime)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !bm.IsRunning() {
				return
			}
			bm.retryConnections()
		}
	}
}

// retryConnections 重试连接
func (bm *BGPManager) retryConnections() {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	for _, peer := range bm.peers {
		if peer.State == BGPIdle {
			go bm.connectToPeer(peer)
		}
	}
}

// routeSelection 路由选择定时器
func (bm *BGPManager) routeSelection() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !bm.IsRunning() {
				return
			}
			bm.runRouteSelection()
		}
	}
}

// runRouteSelection 运行路由选择
func (bm *BGPManager) runRouteSelection() {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	for prefixKey := range bm.ribIn {
		bm.selectBestRoute(prefixKey)
	}
}

// sendNotification 发送Notification消息
func (bm *BGPManager) sendNotification(peer *BGPPeer, errorCode, errorSubcode uint8, data []byte) {
	notification := &BGPNotificationMessage{
		Header: BGPHeader{
			Type: BGPNotification,
		},
		ErrorCode:    errorCode,
		ErrorSubcode: errorSubcode,
		Data:         data,
	}
	
	// 这里应该实际发送消息，简化实现
	bm.logger.Warn(fmt.Sprintf("发送BGP Notification到 %s (错误: %d.%d, 数据长度: %d)", 
		peer.Address, notification.ErrorCode, notification.ErrorSubcode, len(notification.Data)))
	peer.State = BGPIdle
}

// 辅助函数

// generateBGPRouterID 生成BGP路由器ID
func generateBGPRouterID() uint32 {
	// 简化实现，实际应该基于接口IP地址
	return 0x01010101 // 1.1.1.1
}

// GetLocalAS 获取本地AS号
func (bm *BGPManager) GetLocalAS() uint16 {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.localAS
}

// GetRouterID 获取路由器ID
func (bm *BGPManager) GetRouterID() uint32 {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.routerID
}

// GetPeers 获取所有BGP邻居
func (bm *BGPManager) GetPeers() map[string]*BGPPeer {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	peers := make(map[string]*BGPPeer)
	for key, peer := range bm.peers {
		peers[key] = peer
	}
	return peers
}

// GetRIB 获取RIB信息
func (bm *BGPManager) GetRIB() (map[string]*BGPRIBEntry, map[string]*BGPRIBEntry, map[string]*BGPRIBEntry) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	ribIn := make(map[string]*BGPRIBEntry)
	ribOut := make(map[string]*BGPRIBEntry)
	locRIB := make(map[string]*BGPRIBEntry)

	for key, entry := range bm.ribIn {
		ribIn[key] = entry
	}
	for key, entry := range bm.ribOut {
		ribOut[key] = entry
	}
	for key, entry := range bm.locRIB {
		locRIB[key] = entry
	}

	return ribIn, ribOut, locRIB
}
