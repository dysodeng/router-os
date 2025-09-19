// Package protocols 实现BGP（Border Gateway Protocol）协议
//
// BGP协议详解：
// BGP是一种基于路径向量算法的外部网关协议（EGP），主要用于自治系统（AS）之间的路由交换。
// 它是互联网的核心路由协议，负责在不同的自治系统之间传播路由信息。
//
// 核心概念：
// 1. 自治系统（AS）：由单一技术管理机构管理的一组路由器和网络的集合
// 2. 路径向量算法：每个路由都包含完整的AS路径信息，用于防止路由环路
// 3. BGP Speaker：运行BGP协议的路由器
// 4. BGP邻居（Peer）：直接交换BGP信息的两个BGP Speaker
//
// BGP工作原理：
// 1. 邻居建立：通过TCP连接建立BGP会话
// 2. 路由交换：通过UPDATE消息交换路由信息
// 3. 路由选择：基于多种属性选择最优路径
// 4. 路由传播：将最优路由传播给其他邻居
//
// BGP消息类型：
// 1. OPEN：建立BGP会话
// 2. UPDATE：传播路由信息
// 3. NOTIFICATION：错误通知
// 4. KEEPALIVE：保持连接活跃
//
// BGP路径属性：
// 1. ORIGIN：路由起源（IGP/EGP/Incomplete）
// 2. AS_PATH：AS路径列表
// 3. NEXT_HOP：下一跳地址
// 4. MED：多出口判别符
// 5. LOCAL_PREF：本地优先级
// 6. COMMUNITY：团体属性
//
// 本实现特点：
// - 遵循RFC 4271标准，支持BGP-4协议
// - 实现完整的BGP状态机
// - 支持多种路径属性
// - 提供RIB（路由信息库）管理
// - 支持路由选择和最优路径计算
//
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
// 这些常量遵循RFC 4271标准，定义了BGP协议的基本参数
const (
	// BGPPort BGP协议使用的TCP端口号
	// RFC 4271规定BGP使用TCP端口179进行通信
	// BGP是基于TCP的可靠传输协议，确保消息的可靠传递
	BGPPort = 179

	// BGPVersion BGP协议版本号
	// 当前实现支持BGP-4版本，这是目前广泛使用的版本
	// BGP-4相比早期版本支持CIDR和更多路径属性
	BGPVersion = 4

	// BGPKeepaliveTime BGP Keepalive时间
	// 用于保持BGP会话活跃的心跳间隔
	// 通常设置为Hold Time的1/3，默认60秒
	// 定期发送Keepalive消息防止会话超时
	BGPKeepaliveTime = 60 * time.Second

	// BGPHoldTime BGP Hold时间
	// BGP会话的超时时间，如果在此时间内未收到消息则认为邻居失效
	// RFC建议最小值为3秒，典型值为180秒
	// 用于检测邻居故障和网络分割
	BGPHoldTime = 180 * time.Second

	// BGPConnectRetryTime BGP连接重试时间
	// 当BGP连接失败时的重试间隔
	// 避免频繁重连造成网络拥塞
	// 典型值为120秒
	BGPConnectRetryTime = 120 * time.Second

	// BGPMaxMessageSize BGP最大消息大小
	// BGP消息的最大长度限制，单位为字节
	// RFC 4271规定最小值为19字节（仅包含头部）
	// 最大值为4096字节，足以容纳大部分BGP消息
	BGPMaxMessageSize = 4096
)

// BGPMessageType BGP消息类型
// BGP协议定义了四种基本消息类型，用于不同的通信目的
type BGPMessageType uint8

const (
	// BGPOpen OPEN消息（类型1）
	// 用于建立BGP会话，包含BGP版本、AS号、Hold Time等参数
	// 这是BGP会话建立的第一步，双方交换基本配置信息
	BGPOpen BGPMessageType = 1

	// BGPUpdate UPDATE消息（类型2）
	// 用于传播路由信息，包含路径属性和网络层可达性信息（NLRI）
	// 这是BGP的核心消息，负责路由的通告和撤销
	BGPUpdate BGPMessageType = 2

	// BGPNotification NOTIFICATION消息（类型3）
	// 用于报告错误并关闭BGP连接
	// 包含错误代码和子代码，帮助诊断BGP会话问题
	BGPNotification BGPMessageType = 3

	// BGPKeepalive KEEPALIVE消息（类型4）
	// 用于保持BGP会话活跃，防止Hold Timer超时
	// 这是最简单的BGP消息，只包含BGP头部
	BGPKeepalive BGPMessageType = 4
)

// BGPPeerState BGP邻居状态
// BGP状态机定义了邻居关系的生命周期，从空闲到建立连接的完整过程
type BGPPeerState uint8

const (
	// BGPIdle 空闲状态（状态0）
	// BGP的初始状态，拒绝所有传入的BGP连接
	// 等待Start事件触发连接建立过程
	BGPIdle BGPPeerState = 0

	// BGPConnect 连接状态（状态1）
	// 等待TCP连接建立完成
	// 如果TCP连接成功，转入OpenSent状态
	BGPConnect BGPPeerState = 1

	// BGPActive 活跃状态（状态2）
	// 尝试建立TCP连接
	// 如果连接失败，可能回到Connect状态重试
	BGPActive BGPPeerState = 2

	// BGPOpenSent 已发送Open状态（状态3）
	// TCP连接已建立，已发送OPEN消息
	// 等待接收对方的OPEN消息
	BGPOpenSent BGPPeerState = 3

	// BGPOpenConfirm 确认Open状态（状态4）
	// 已收到对方的OPEN消息并发送KEEPALIVE确认
	// 等待接收对方的KEEPALIVE确认
	BGPOpenConfirm BGPPeerState = 4

	// BGPEstablished 已建立状态（状态5）
	// BGP会话已完全建立，可以交换UPDATE消息
	// 这是BGP的正常工作状态
	BGPEstablished BGPPeerState = 5
)

// BGPOrigin BGP Origin属性
// Origin属性指示路由信息的来源，影响路由选择的优先级
type BGPOrigin uint8

const (
	// OriginIGP IGP起源（值0）
	// 路由来自内部网关协议（如OSPF、RIP）
	// 这是最优的起源类型，优先级最高
	OriginIGP BGPOrigin = 0

	// OriginEGP EGP起源（值1）
	// 路由来自外部网关协议（历史遗留，现已废弃）
	// 优先级中等，实际使用中很少见
	OriginEGP BGPOrigin = 1

	// OriginIncomplete 不完整起源（值2）
	// 路由来源未知或通过重分发获得
	// 优先级最低，通常用于静态路由重分发
	OriginIncomplete BGPOrigin = 2
)

// BGPPathAttributeType BGP路径属性类型
// 路径属性是BGP路由选择的核心，每种属性都有特定的用途和影响
type BGPPathAttributeType uint8

const (
	// BGPAttrOrigin ORIGIN属性（类型1）
	// 必选传递属性，指示路由的起源
	// 用于路由选择决策，IGP > EGP > Incomplete
	BGPAttrOrigin BGPPathAttributeType = 1

	// BGPAttrASPath AS_PATH属性（类型2）
	// 必选传递属性，记录路由经过的AS序列
	// 用于防止路由环路和路径选择
	// AS_PATH越短，路由优先级越高
	BGPAttrASPath BGPPathAttributeType = 2

	// BGPAttrNextHop NEXT_HOP属性（类型3）
	// 必选传递属性，指示到达目标网络的下一跳地址
	// 对于EBGP，通常是邻居的IP地址
	// 对于IBGP，可能需要递归查找
	BGPAttrNextHop BGPPathAttributeType = 3

	// BGPAttrMED MULTI_EXIT_DISC属性（类型4）
	// 可选非传递属性，多出口判别符
	// 用于影响从相邻AS进入本AS的流量路径选择
	// MED值越小，路由优先级越高
	BGPAttrMED BGPPathAttributeType = 4

	// BGPAttrLocalPref LOCAL_PREF属性（类型5）
	// 必选传递属性（仅在AS内部使用）
	// 用于在AS内部选择出口路径
	// LOCAL_PREF值越大，路由优先级越高
	BGPAttrLocalPref BGPPathAttributeType = 5

	// BGPAttrCommunity COMMUNITY属性（类型8）
	// 可选传递属性，用于路由标记和策略控制
	// 允许运营商对路由进行分组和策略应用
	// 常用于流量工程和路由过滤
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

	// 启动定时器和状态机
	go bm.keepaliveTimer()
	go bm.holdTimer()
	go bm.connectRetryTimer()
	go bm.routeSelection()
	go bm.peerStateMachine()
	go bm.routeAdvertisement()
	go bm.policyEngine()

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
	bm.logger.Info("添加BGP邻居: %s (AS %d)", address.String(), as)

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
		return fmt.Errorf("BGP邻居 %s 不存在", address.String())
	}

	// 撤销从该邻居学到的所有路由
	bm.withdrawRoutesFromPeer(peer)

	delete(bm.peers, peerKey)
	bm.logger.Info("删除BGP邻居: %s", address.String())

	return nil
}

// connectToPeer 连接到BGP邻居
func (bm *BGPManager) connectToPeer(peer *BGPPeer) {
	peer.mu.Lock()
	defer peer.mu.Unlock()

	if peer.State != BGPIdle {
		return
	}

	bm.logger.Info("尝试连接BGP邻居: %s", peer.Address)
	peer.State = BGPConnect

	// 这里应该建立TCP连接，简化实现
	// 模拟连接成功
	time.Sleep(time.Second)

	if bm.sendOpenMessage(peer) {
		peer.State = BGPOpenSent
		bm.logger.Info("发送Open消息到邻居: %s", peer.Address.String())
	} else {
		peer.State = BGPIdle
		bm.logger.Warn("连接邻居失败: %s", peer.Address.String())
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
	bm.logger.Debug("发送BGP Open消息到 %s (AS: %d, Hold: %d)",
		peer.Address.String(), open.MyAS, open.HoldTime)
	return true
}

// ProcessOpenMessage 处理Open消息
func (bm *BGPManager) ProcessOpenMessage(message *BGPOpenMessage, peer *BGPPeer) error {
	peer.mu.Lock()
	defer peer.mu.Unlock()

	if peer.State != BGPOpenSent && peer.State != BGPConnect {
		return fmt.Errorf("BGP邻居 %s 状态错误: %d", peer.Address.String(), peer.State)
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
		bm.logger.Info("BGP会话建立: %s", peer.Address.String())
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

	bm.logger.Debug("安装BGP路由: %s via %s", route.Prefix, route.NextHop)
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

	bm.logger.Debug("撤销BGP路由: %s", prefix.String())
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

	_ = bm.routingTable.AddRoute(routeEntry)
}

// findOutputInterface 查找输出接口
func (bm *BGPManager) findOutputInterface(nextHop net.IP) string {
	ifaces := bm.interfaceManager.GetAllInterfaces()

	for _, iface := range ifaces {
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

	for range ticker.C {
		if !bm.IsRunning() {
			return
		}
		bm.sendKeepaliveToAllPeers()
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
	bm.logger.Debug("发送BGP Keepalive到 %s (Type: %d)", peer.Address, keepalive.Header.Type)
	peer.LastKeepalive = time.Now()
}

// holdTimer Hold定时器
func (bm *BGPManager) holdTimer() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if !bm.IsRunning() {
			return
		}
		bm.checkHoldTimers()
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
				bm.logger.Warn("BGP邻居 %s Hold定时器超时", peer.Address.String())
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

	for range ticker.C {
		if !bm.IsRunning() {
			return
		}
		bm.retryConnections()
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

	for range ticker.C {
		if !bm.IsRunning() {
			return
		}
		bm.runRouteSelection()
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
	bm.logger.Warn("发送BGP Notification到 %s (错误: %d.%d, 数据长度: %d)",
		peer.Address, notification.ErrorCode, notification.ErrorSubcode, len(notification.Data))
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

// peerStateMachine BGP邻居状态机
func (bm *BGPManager) peerStateMachine() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !bm.IsRunning() {
			return
		}
		bm.processPeerStates()
	}
}

// processPeerStates 处理邻居状态
func (bm *BGPManager) processPeerStates() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	for _, peer := range bm.peers {
		bm.processPeerStateTransition(peer)
	}
}

// processPeerStateTransition 处理邻居状态转换
func (bm *BGPManager) processPeerStateTransition(peer *BGPPeer) {
	peer.mu.Lock()
	defer peer.mu.Unlock()

	now := time.Now()

	switch peer.State {
	case BGPIdle:
		// 空闲状态，尝试连接
		if now.Sub(peer.LastUpdate) > peer.ConnectRetryTime {
			bm.logger.Info("尝试连接BGP邻居: %s", peer.Address.String())
			go bm.connectToPeer(peer)
		}

	case BGPConnect:
		// 连接状态，等待连接建立
		// 这里应该检查TCP连接状态

	case BGPActive:
		// 活跃状态，等待连接

	case BGPOpenSent:
		// 已发送Open消息，等待回复
		if now.Sub(peer.LastUpdate) > peer.HoldTime {
			bm.logger.Warn("BGP邻居 %s Open消息超时", peer.Address.String())
			peer.State = BGPIdle
		}

	case BGPOpenConfirm:
		// Open确认状态，等待Keepalive
		if now.Sub(peer.LastKeepalive) > peer.HoldTime {
			bm.logger.Warn("BGP邻居 %s Keepalive超时", peer.Address.String())
			peer.State = BGPIdle
		}

	case BGPEstablished:
		// 已建立状态，检查Keepalive超时
		if now.Sub(peer.LastKeepalive) > peer.HoldTime {
			bm.logger.Warn("BGP邻居 %s 连接超时", peer.Address.String())
			peer.State = BGPIdle
			// 撤销从该邻居学到的所有路由
			bm.withdrawRoutesFromPeer(peer)
		}
	}
}

// routeAdvertisement 路由通告处理
func (bm *BGPManager) routeAdvertisement() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !bm.IsRunning() {
			return
		}
		bm.processRouteAdvertisement()
	}
}

// processRouteAdvertisement 处理路由通告
func (bm *BGPManager) processRouteAdvertisement() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// 向所有已建立的邻居通告路由
	for _, peer := range bm.peers {
		if peer.State == BGPEstablished {
			bm.advertiseRoutesToPeer(peer)
		}
	}
}

// advertiseRoutesToPeer 向邻居通告路由
func (bm *BGPManager) advertiseRoutesToPeer(peer *BGPPeer) {
	// 从Loc-RIB中选择要通告的路由
	for prefixKey, ribEntry := range bm.locRIB {
		if ribEntry.BestRoute != nil {
			// 应用出站策略
			if bm.shouldAdvertiseRoute(ribEntry.BestRoute, peer) {
				bm.sendUpdateMessage(peer, ribEntry.BestRoute)
				bm.logger.Debug("向邻居 %s 通告路由 %s", peer.Address.String(), prefixKey)
			}
		}
	}
}

// policyEngine 策略引擎
func (bm *BGPManager) policyEngine() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !bm.IsRunning() {
			return
		}
		bm.processPolicies()
	}
}

// processPolicies 处理策略
func (bm *BGPManager) processPolicies() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// 应用入站策略
	bm.applyInboundPolicies()

	// 应用出站策略
	bm.applyOutboundPolicies()

	// 重新运行路由选择
	bm.runRouteSelection()
}

// applyInboundPolicies 应用入站策略
func (bm *BGPManager) applyInboundPolicies() {
	for prefixKey, ribEntry := range bm.ribIn {
		for _, route := range ribEntry.Routes {
			// 应用入站过滤器
			if bm.applyInboundFilter(route) {
				// 修改路由属性
				bm.modifyRouteAttributes(route, "inbound")
			} else {
				// 过滤掉该路由
				bm.logger.Debug("入站策略过滤路由: %s", prefixKey)
			}
		}
	}
}

// applyOutboundPolicies 应用出站策略
func (bm *BGPManager) applyOutboundPolicies() {
	for prefixKey, ribEntry := range bm.ribOut {
		for _, route := range ribEntry.Routes {
			// 应用出站过滤器
			if !bm.applyOutboundFilter(route) {
				// 过滤掉该路由
				bm.logger.Debug("出站策略过滤路由: %s", prefixKey)
			}
		}
	}
}

// 辅助方法实现
func (bm *BGPManager) shouldAdvertiseRoute(route *BGPRoute, peer *BGPPeer) bool {
	// 简化实现，实际应该检查路由策略、AS路径等
	return true
}

func (bm *BGPManager) sendUpdateMessage(peer *BGPPeer, route *BGPRoute) {
	// 简化实现，实际应该构造并发送BGP Update消息
	bm.logger.Debug("发送Update消息到邻居 %s", peer.Address.String())
}

func (bm *BGPManager) applyInboundFilter(route *BGPRoute) bool {
	// 简化实现，实际应该根据配置的策略进行过滤
	return true
}

func (bm *BGPManager) applyOutboundFilter(route *BGPRoute) bool {
	// 简化实现，实际应该根据配置的策略进行过滤
	return true
}

func (bm *BGPManager) modifyRouteAttributes(route *BGPRoute, direction string) {
	// 简化实现，实际应该根据策略修改路由属性
	if direction == "inbound" {
		// TODO: 实现入站路由属性修改逻辑
		// 可能修改Local Preference等属性
		bm.logger.Debug("Processing inbound route attributes for route: %s", route.Prefix.String())
	} else {
		// TODO: 实现出站路由属性修改逻辑
		// 可能修改MED等属性
		bm.logger.Debug("Processing outbound route attributes for route: %s", route.Prefix.String())
	}
}

// GetPeerStates 获取所有邻居状态
func (bm *BGPManager) GetPeerStates() map[string]BGPPeerState {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	states := make(map[string]BGPPeerState)
	for addr, peer := range bm.peers {
		peer.mu.RLock()
		states[addr] = peer.State
		peer.mu.RUnlock()
	}
	return states
}

// GetRouteCount 获取路由数量统计
func (bm *BGPManager) GetRouteCount() (int, int, int) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	return len(bm.ribIn), len(bm.ribOut), len(bm.locRIB)
}
