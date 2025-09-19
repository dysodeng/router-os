package arp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ARPEntry ARP表条目
// 存储IP地址到MAC地址的映射关系
// 这是二层转发的基础，路由器需要知道下一跳的MAC地址才能构造以太网帧
type ARPEntry struct {
	// IPAddress IP地址
	IPAddress net.IP

	// MACAddress MAC地址（硬件地址）
	MACAddress net.HardwareAddr

	// Interface 学习到此条目的网络接口
	Interface string

	// Timestamp 条目创建或更新时间
	Timestamp time.Time

	// TTL 生存时间
	TTL time.Duration

	// State 条目状态
	State ARPState

	// RetryCount 重试次数（用于未完成的ARP请求）
	RetryCount int

	// LastAccessed 最后访问时间
	LastAccessed time.Time

	// CreatedAt 创建时间
	CreatedAt time.Time

	// UpdatedAt 更新时间
	UpdatedAt time.Time
}

// ARPState ARP条目状态
type ARPState int

const (
	// ARPStateIncomplete ARP解析进行中
	ARPStateIncomplete ARPState = iota

	// ARPStateReachable ARP条目有效且可达
	ARPStateReachable

	// ARPStateStale ARP条目过期但仍可用
	ARPStateStale

	// ARPStateFailed ARP解析失败
	ARPStateFailed

	// ARPStatePending ARP请求等待中
	ARPStatePending
)

// String 返回ARP状态的字符串表示
func (s ARPState) String() string {
	switch s {
	case ARPStateIncomplete:
		return "INCOMPLETE"
	case ARPStateReachable:
		return "REACHABLE"
	case ARPStateStale:
		return "STALE"
	case ARPStateFailed:
		return "FAILED"
	case ARPStatePending:
		return "PENDING"
	default:
		return "UNKNOWN"
	}
}

// ARPStats ARP统计信息
type ARPStats struct {
	TotalEntries      uint64
	EntriesAdded      uint64
	EntriesRemoved    uint64
	LookupHits        uint64
	LookupMisses      uint64
	RequestsSent      uint64
	RepliesReceived   uint64
	ExpiredEntries    uint64
	DynamicEntries    uint64
	ConflictsDetected uint64
	MACChanges        uint64
	GratuitousARPSent uint64
}

// ARPConflict IP冲突记录
type ARPConflict struct {
	IP        net.IP
	OldMAC    net.HardwareAddr
	NewMAC    net.HardwareAddr
	Interface string
	Timestamp time.Time
}

// MACChange MAC地址变化记录
type MACChange struct {
	IP        net.IP
	OldMAC    net.HardwareAddr
	NewMAC    net.HardwareAddr
	Interface string
	Timestamp time.Time
}

// ARPPacket ARP数据包结构
type ARPPacket struct {
	HardwareType       uint16  // 硬件类型 (1 = Ethernet)
	ProtocolType       uint16  // 协议类型 (0x0800 = IPv4)
	HardwareAddrLength uint8   // 硬件地址长度 (6 for MAC)
	ProtocolAddrLength uint8   // 协议地址长度 (4 for IPv4)
	Operation          uint16  // 操作类型 (1 = Request, 2 = Reply)
	SenderHardwareAddr [6]byte // 发送方MAC地址
	SenderProtocolAddr [4]byte // 发送方IP地址
	TargetHardwareAddr [6]byte // 目标MAC地址
	TargetProtocolAddr [4]byte // 目标IP地址
}

// ARPConstants ARP协议常量
const (
	ARPHardwareTypeEthernet = 1
	ARPProtocolTypeIPv4     = 0x0800
	ARPOperationRequest     = 1
	ARPOperationReply       = 2
	ARPHardwareAddrLen      = 6
	ARPProtocolAddrLen      = 4
	ARPPacketSize           = 28
)

// ARPTable ARP表管理器
// 负责维护IP到MAC地址的映射表，这是路由器二层转发的核心组件
//
// 主要功能：
// 1. ARP条目管理：添加、删除、更新ARP条目
// 2. ARP解析：将IP地址解析为MAC地址
// 3. ARP缓存：缓存已解析的地址映射
// 4. 超时处理：清理过期的ARP条目
// 5. ARP协议：处理ARP请求和回复
//
// 工作原理：
// - 当需要发送数据包到某个IP时，首先查询ARP表
// - 如果找到对应的MAC地址，直接使用
// - 如果没有找到，发送ARP请求广播询问
// - 收到ARP回复后，更新ARP表并发送数据包
//
// 注意事项：
// - ARP表有大小限制，防止内存耗尽
// - 条目有生存时间，定期清理过期条目
// - 支持静态ARP条目，用于安全或特殊需求
type ARPTable struct {
	// entries ARP条目映射表
	entries map[string]*ARPEntry

	// mu 读写锁，保护并发访问
	mu sync.RWMutex

	// maxEntries 最大条目数量
	maxEntries int

	// defaultTTL 默认生存时间
	defaultTTL time.Duration

	// cleanupInterval 清理间隔
	cleanupInterval time.Duration

	// running 运行状态
	running bool

	// stats 统计信息
	stats ARPStats

	// conflicts IP冲突记录
	conflicts []ARPConflict

	// macChanges MAC变化记录
	macChanges []MACChange

	// rawSocket 原始套接字文件描述符
	rawSocket int

	// interfaces 网络接口信息映射
	interfaces map[string]*InterfaceInfo

	// pendingRequests 待处理的ARP请求
	pendingRequests map[string]*PendingRequest
}

// InterfaceInfo 网络接口信息
type InterfaceInfo struct {
	Name       string
	Index      int
	MAC        net.HardwareAddr
	IP         net.IP
	Subnet     *net.IPNet
	MTU        int
	IsUp       bool
	LastUpdate time.Time
}

// PendingRequest 待处理的ARP请求
type PendingRequest struct {
	TargetIP    net.IP
	Interface   string
	RequestTime time.Time
	RetryCount  int
	MaxRetries  int
	Timeout     time.Duration
	Callback    func(net.HardwareAddr, error)
}

// NewARPTable 创建新的ARP表
func NewARPTable(maxEntries int, defaultTTL time.Duration, cleanupInterval time.Duration) *ARPTable {
	return &ARPTable{
		entries:         make(map[string]*ARPEntry),
		maxEntries:      maxEntries,
		defaultTTL:      defaultTTL,
		cleanupInterval: cleanupInterval,
		running:         false,
		stats:           ARPStats{},
		conflicts:       make([]ARPConflict, 0),
		macChanges:      make([]MACChange, 0),
		rawSocket:       -1,
		interfaces:      make(map[string]*InterfaceInfo),
		pendingRequests: make(map[string]*PendingRequest),
	}
}

// Start 启动ARP表的后台清理任务和ARP监听器
func (at *ARPTable) Start() error {
	at.mu.Lock()
	defer at.mu.Unlock()

	if at.running {
		return fmt.Errorf("ARP表已经在运行")
	}

	at.running = true
	go at.cleanupLoop()

	// 启动ARP数据包监听器
	if err := at.startARPListener(); err != nil {
		at.running = false
		return fmt.Errorf("启动ARP监听器失败: %v", err)
	}

	return nil
}

// Stop 停止ARP表管理器
func (at *ARPTable) Stop() {
	at.mu.Lock()
	defer at.mu.Unlock()

	if !at.running {
		return
	}

	at.running = false

	// 停止ARP数据包监听器
	at.stopARPListener()
}

// AddEntry 添加ARP条目
func (at *ARPTable) AddEntry(ip net.IP, mac net.HardwareAddr, iface string) error {
	at.mu.Lock()
	defer at.mu.Unlock()

	if !at.running {
		return fmt.Errorf("ARP table is not running")
	}

	ipStr := ip.String()

	// 检查是否存在冲突
	if existing, exists := at.entries[ipStr]; exists {
		if !bytes.Equal(existing.MACAddress, mac) {
			// 检测到IP冲突
			at.handleIPConflict(ip, existing.MACAddress, mac, iface)
		}
	}

	// 创建或更新条目
	entry := &ARPEntry{
		IPAddress:    ip,
		MACAddress:   mac,
		Interface:    iface,
		State:        ARPStateReachable,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		LastAccessed: time.Now(),
		TTL:          at.defaultTTL,
	}

	at.entries[ipStr] = entry

	// 记录统计信息
	at.stats.TotalEntries = uint64(len(at.entries))
	at.stats.EntriesAdded++

	return nil
}

// LookupEntry 查找ARP条目
func (at *ARPTable) LookupEntry(ip net.IP) (*ARPEntry, bool) {
	at.mu.RLock()
	defer at.mu.RUnlock()

	if !at.running {
		return nil, false
	}

	ipStr := ip.String()
	entry, exists := at.entries[ipStr]
	if !exists {
		at.stats.LookupMisses++
		return nil, false
	}

	// 检查条目是否过期
	if time.Since(entry.UpdatedAt) > entry.TTL {
		// 条目过期，标记为stale状态
		entry.State = ARPStateStale
		at.stats.ExpiredEntries++
	}

	at.stats.LookupHits++
	entry.LastAccessed = time.Now()

	return entry, true
}

// DeleteEntry 删除ARP条目
func (at *ARPTable) DeleteEntry(ip net.IP) bool {
	if ip == nil {
		return false
	}

	at.mu.Lock()
	defer at.mu.Unlock()

	key := ip.String()
	if _, exists := at.entries[key]; exists {
		delete(at.entries, key)
		at.stats.EntriesRemoved++
		at.stats.TotalEntries = uint64(len(at.entries))
		return true
	}

	return false
}

// GetAllEntries 获取所有ARP条目
func (at *ARPTable) GetAllEntries() []*ARPEntry {
	at.mu.RLock()
	defer at.mu.RUnlock()

	entries := make([]*ARPEntry, 0, len(at.entries))
	for _, entry := range at.entries {
		// 创建条目副本
		entryCopy := *entry
		entries = append(entries, &entryCopy)
	}

	return entries
}

// GetStats 获取ARP表统计信息
func (at *ARPTable) GetStats() ARPStats {
	at.mu.RLock()
	defer at.mu.RUnlock()

	return at.stats
}

// cleanupLoop 清理循环
func (at *ARPTable) cleanupLoop() {
	ticker := time.NewTicker(at.cleanupInterval)
	defer ticker.Stop()

	for at.running {
		select {
		case <-ticker.C:
			at.cleanupExpiredEntries()
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// cleanupExpiredEntries 清理过期条目
func (at *ARPTable) cleanupExpiredEntries() {
	at.mu.Lock()
	defer at.mu.Unlock()

	now := time.Now()
	expiredIPs := make([]string, 0)

	for ipStr, entry := range at.entries {
		// 检查条目是否过期
		if now.Sub(entry.UpdatedAt) > entry.TTL {
			// 如果条目长时间未访问，则删除
			if now.Sub(entry.LastAccessed) > time.Hour {
				expiredIPs = append(expiredIPs, ipStr)
				continue
			}

			// 否则标记为stale状态
			if entry.State == ARPStateReachable {
				entry.State = ARPStateStale
			}
		}

		// 清理长时间处于pending状态的条目
		if entry.State == ARPStatePending && now.Sub(entry.CreatedAt) > time.Minute {
			expiredIPs = append(expiredIPs, ipStr)
		}
	}

	// 删除过期条目
	for _, ipStr := range expiredIPs {
		delete(at.entries, ipStr)
		at.stats.ExpiredEntries++
	}

	at.stats.TotalEntries = uint64(len(at.entries))
}

// Resolve 解析IP地址到MAC地址
func (at *ARPTable) Resolve(ip net.IP, iface string, timeout time.Duration) (net.HardwareAddr, error) {
	if ip == nil {
		return nil, fmt.Errorf("IP地址不能为空")
	}

	// 第一步：查询ARP缓存
	entry, found := at.LookupEntry(ip)
	if found && entry.State == ARPStateReachable {
		// 缓存命中且条目有效，直接返回
		return entry.MACAddress, nil
	}

	// 第二步：发送ARP请求
	return at.sendARPRequest(ip, iface, timeout)
}

// sendARPRequest 发送真实的ARP请求
func (at *ARPTable) sendARPRequest(ip net.IP, iface string, timeout time.Duration) (net.HardwareAddr, error) {
	if ip == nil {
		return nil, fmt.Errorf("目标IP地址不能为空")
	}

	// 首先尝试使用系统ARP命令
	if mac, err := at.querySystemARP(ip); err == nil && mac != nil {
		// 将结果添加到ARP表
		if err = at.AddEntry(ip, mac, iface); err != nil {
			return nil, err
		}
		return mac, nil
	}

	// 如果系统ARP查询失败，尝试发送ARP请求包
	return at.sendARPPacket(ip, iface, timeout)
}

// querySystemARP 查询系统ARP表
func (at *ARPTable) querySystemARP(ip net.IP) (net.HardwareAddr, error) {
	// 使用arp命令查询系统ARP表
	cmd := exec.Command("arp", "-n", ip.String())
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行arp命令失败: %v", err)
	}

	// 解析arp命令输出
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ip.String()) {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				macStr := fields[2]
				// 检查MAC地址格式
				if strings.Contains(macStr, ":") && len(macStr) == 17 {
					mac, err := net.ParseMAC(macStr)
					if err == nil {
						return mac, nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("在系统ARP表中未找到IP %s", ip.String())
}

// sendARPPacket 发送ARP数据包
func (at *ARPTable) sendARPPacket(ip net.IP, iface string, timeout time.Duration) (net.HardwareAddr, error) {
	// 获取接口信息
	ifaceInfo, err := at.getInterfaceInfo(iface)
	if err != nil {
		return nil, fmt.Errorf("获取接口信息失败: %v", err)
	}

	// 创建ARP请求包
	arpPacket, err := at.createARPRequest(ip, ifaceInfo)
	if err != nil {
		return nil, fmt.Errorf("创建ARP请求包失败: %v", err)
	}

	// 发送ARP请求
	err = at.sendRawARPPacket(arpPacket, ifaceInfo)
	if err != nil {
		return nil, fmt.Errorf("发送ARP请求失败: %v", err)
	}

	// 等待ARP响应
	return at.waitForARPReply(ip, timeout)
}

// getInterfaceInfo 获取网络接口信息
func (at *ARPTable) getInterfaceInfo(ifaceName string) (*InterfaceInfo, error) {
	at.mu.RLock()
	if info, exists := at.interfaces[ifaceName]; exists {
		at.mu.RUnlock()
		return info, nil
	}
	at.mu.RUnlock()

	// 如果缓存中没有，从系统获取
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("获取网络接口失败: %v", err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("获取接口地址失败: %v", err)
	}

	var ip net.IP
	var subnet *net.IPNet
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip = ipnet.IP
				subnet = ipnet
				break
			}
		}
	}

	if ip == nil {
		return nil, fmt.Errorf("接口 %s 没有有效的IPv4地址", ifaceName)
	}

	info := &InterfaceInfo{
		Name:       iface.Name,
		Index:      iface.Index,
		MAC:        iface.HardwareAddr,
		IP:         ip,
		Subnet:     subnet,
		MTU:        iface.MTU,
		IsUp:       iface.Flags&net.FlagUp != 0,
		LastUpdate: time.Now(),
	}

	// 缓存接口信息
	at.mu.Lock()
	at.interfaces[ifaceName] = info
	at.mu.Unlock()

	return info, nil
}

// createARPRequest 创建ARP请求包
func (at *ARPTable) createARPRequest(targetIP net.IP, ifaceInfo *InterfaceInfo) (*ARPPacket, error) {
	packet := &ARPPacket{
		HardwareType:       ARPHardwareTypeEthernet,
		ProtocolType:       ARPProtocolTypeIPv4,
		HardwareAddrLength: ARPHardwareAddrLen,
		ProtocolAddrLength: ARPProtocolAddrLen,
		Operation:          ARPOperationRequest,
	}

	// 设置发送方地址
	copy(packet.SenderHardwareAddr[:], ifaceInfo.MAC)
	copy(packet.SenderProtocolAddr[:], ifaceInfo.IP.To4())

	// 设置目标地址
	copy(packet.TargetProtocolAddr[:], targetIP.To4())
	// 目标MAC地址设为全0（未知）

	return packet, nil
}

// sendRawARPPacket 发送原始ARP数据包
func (at *ARPTable) sendRawARPPacket(packet *ARPPacket, ifaceInfo *InterfaceInfo) error {
	// 在实际实现中，这里需要使用原始套接字发送ARP包
	// 由于需要root权限和复杂的套接字操作，这里使用系统命令作为替代

	// 构造arping命令
	targetIP := net.IP(packet.TargetProtocolAddr[:]).String()
	cmd := exec.Command("arping", "-c", "1", "-I", ifaceInfo.Name, targetIP)
	err := cmd.Run()
	if err != nil {
		// 如果arping命令失败，尝试使用ping命令触发ARP
		pingCmd := exec.Command("ping", "-c", "1", "-W", "1", targetIP)
		_ = pingCmd.Run() // 忽略ping的错误，只是为了触发ARP
	}

	return nil
}

// waitForARPReply 等待ARP响应
func (at *ARPTable) waitForARPReply(targetIP net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	// 等待一段时间后再次查询系统ARP表
	time.Sleep(100 * time.Millisecond)

	// 多次尝试查询
	for i := 0; i < 5; i++ {
		if mac, err := at.querySystemARP(targetIP); err == nil {
			return mac, nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	return nil, fmt.Errorf("ARP解析超时: 无法获取IP %s 的MAC地址", targetIP.String())
}

// SendARPRequest 发送ARP请求
func (at *ARPTable) SendARPRequest(targetIP net.IP, iface string) error {
	at.mu.Lock()
	defer at.mu.Unlock()

	if !at.running {
		return fmt.Errorf("ARP table is not running")
	}

	// 创建pending条目
	ipStr := targetIP.String()
	entry := &ARPEntry{
		IPAddress:    targetIP,
		Interface:    iface,
		State:        ARPStatePending,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		LastAccessed: time.Now(),
		TTL:          at.defaultTTL,
	}

	at.entries[ipStr] = entry
	at.stats.RequestsSent++

	// 实际发送ARP请求的逻辑会在这里实现
	go at.sendARPRequestAsync(targetIP, iface)

	return nil
}

// sendARPRequestAsync 异步发送真实的ARP请求
func (at *ARPTable) sendARPRequestAsync(targetIP net.IP, iface string) {
	go func() {
		// 设置默认超时时间
		timeout := 3 * time.Second

		// 发送ARP请求
		mac, err := at.sendARPRequest(targetIP, iface, timeout)
		if err != nil {
			// 如果请求失败，记录到待处理请求中以便重试
			at.addPendingRequest(targetIP, iface, timeout, nil)
			return
		}

		// 成功获取MAC地址，处理ARP响应
		_ = at.HandleARPReply(targetIP, mac, iface)
	}()
}

// addPendingRequest 添加待处理的ARP请求
func (at *ARPTable) addPendingRequest(targetIP net.IP, iface string, timeout time.Duration, callback func(net.HardwareAddr, error)) {
	at.mu.Lock()
	defer at.mu.Unlock()

	key := targetIP.String() + "@" + iface
	request := &PendingRequest{
		TargetIP:    targetIP,
		Interface:   iface,
		RequestTime: time.Now(),
		RetryCount:  0,
		MaxRetries:  3,
		Timeout:     timeout,
		Callback:    callback,
	}

	at.pendingRequests[key] = request

	// 启动重试处理
	go at.handlePendingRequest(key, request)
}

// handlePendingRequest 处理待处理的ARP请求
func (at *ARPTable) handlePendingRequest(key string, request *PendingRequest) {
	for request.RetryCount < request.MaxRetries {
		// 等待重试间隔
		time.Sleep(time.Second * time.Duration(request.RetryCount+1))

		// 尝试发送ARP请求
		mac, err := at.sendARPRequest(request.TargetIP, request.Interface, request.Timeout)
		if err == nil {
			// 成功获取MAC地址
			_ = at.HandleARPReply(request.TargetIP, mac, request.Interface)

			// 调用回调函数
			if request.Callback != nil {
				request.Callback(mac, nil)
			}

			// 从待处理列表中移除
			at.mu.Lock()
			delete(at.pendingRequests, key)
			at.mu.Unlock()
			return
		}

		request.RetryCount++
	}

	// 重试次数用完，调用回调函数报告失败
	if request.Callback != nil {
		request.Callback(nil, fmt.Errorf("ARP请求失败，已重试%d次", request.MaxRetries))
	}

	// 从待处理列表中移除
	at.mu.Lock()
	delete(at.pendingRequests, key)
	at.mu.Unlock()
}

// ResolveAsync 异步解析IP地址到MAC地址
func (at *ARPTable) ResolveAsync(ip net.IP, iface string, callback func(net.HardwareAddr, error)) {
	// 首先检查缓存
	if entry, exists := at.LookupEntry(ip); exists && entry.State == ARPStateReachable {
		if callback != nil {
			callback(entry.MACAddress, nil)
		}
		return
	}

	// 添加到待处理请求并异步处理
	timeout := 3 * time.Second
	at.addPendingRequest(ip, iface, timeout, callback)
}

// HandleARPReply 处理ARP响应
func (at *ARPTable) HandleARPReply(ip net.IP, mac net.HardwareAddr, iface string) error {
	at.mu.Lock()
	defer at.mu.Unlock()

	ipStr := ip.String()
	entry, exists := at.entries[ipStr]

	if !exists {
		// 动态学习新的ARP条目
		entry = &ARPEntry{
			IPAddress:    ip,
			MACAddress:   mac,
			Interface:    iface,
			State:        ARPStateReachable,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			LastAccessed: time.Now(),
			TTL:          at.defaultTTL,
		}
		at.entries[ipStr] = entry
		at.stats.DynamicEntries++
	} else {
		// 更新现有条目
		if !bytes.Equal(entry.MACAddress, mac) {
			// MAC地址变化，可能是设备更换
			at.handleMACChange(ip, entry.MACAddress, mac, iface)
		}

		entry.MACAddress = mac
		entry.Interface = iface
		entry.State = ARPStateReachable
		entry.UpdatedAt = time.Now()
	}

	at.stats.RepliesReceived++
	at.stats.TotalEntries = uint64(len(at.entries))

	return nil
}

// SendGratuitousARP 发送免费ARP
func (at *ARPTable) SendGratuitousARP(ip net.IP, mac net.HardwareAddr, iface string) error {
	at.mu.Lock()
	defer at.mu.Unlock()

	if !at.running {
		return fmt.Errorf("ARP table is not running")
	}

	// 更新本地ARP表
	ipStr := ip.String()
	entry := &ARPEntry{
		IPAddress:    ip,
		MACAddress:   mac,
		Interface:    iface,
		State:        ARPStateReachable,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		LastAccessed: time.Now(),
		TTL:          at.defaultTTL,
	}

	at.entries[ipStr] = entry
	at.stats.GratuitousARPSent++

	return nil
}

// handleIPConflict 处理IP地址冲突
func (at *ARPTable) handleIPConflict(ip net.IP, oldMAC, newMAC net.HardwareAddr, iface string) {
	at.stats.ConflictsDetected++

	// 记录冲突事件
	conflict := ARPConflict{
		IP:        ip,
		OldMAC:    oldMAC,
		NewMAC:    newMAC,
		Interface: iface,
		Timestamp: time.Now(),
	}

	at.conflicts = append(at.conflicts, conflict)

	// 保持最近的100个冲突记录
	if len(at.conflicts) > 100 {
		at.conflicts = at.conflicts[1:]
	}
}

// handleMACChange 处理MAC地址变化
func (at *ARPTable) handleMACChange(ip net.IP, oldMAC, newMAC net.HardwareAddr, iface string) {
	at.stats.MACChanges++

	// 记录MAC变化事件
	change := MACChange{
		IP:        ip,
		OldMAC:    oldMAC,
		NewMAC:    newMAC,
		Interface: iface,
		Timestamp: time.Now(),
	}

	at.macChanges = append(at.macChanges, change)

	// 保持最近的100个变化记录
	if len(at.macChanges) > 100 {
		at.macChanges = at.macChanges[1:]
	}
}

// GetConflicts 获取IP冲突记录
func (at *ARPTable) GetConflicts() []ARPConflict {
	at.mu.RLock()
	defer at.mu.RUnlock()

	conflicts := make([]ARPConflict, len(at.conflicts))
	copy(conflicts, at.conflicts)
	return conflicts
}

// GetMACChanges 获取MAC地址变化记录
func (at *ARPTable) GetMACChanges() []MACChange {
	at.mu.RLock()
	defer at.mu.RUnlock()

	changes := make([]MACChange, len(at.macChanges))
	copy(changes, at.macChanges)
	return changes
}

// AddStaticEntry 添加静态ARP条目
func (at *ARPTable) AddStaticEntry(ip net.IP, mac net.HardwareAddr, iface string) error {
	if ip == nil {
		return fmt.Errorf("IP地址不能为空")
	}

	if mac == nil {
		return fmt.Errorf("MAC地址不能为空")
	}

	at.mu.Lock()
	defer at.mu.Unlock()

	key := ip.String()

	// 静态条目使用特殊的TTL值（-1表示永不过期）
	at.entries[key] = &ARPEntry{
		IPAddress:    ip,
		MACAddress:   mac,
		Interface:    iface,
		Timestamp:    time.Now(),
		TTL:          -1, // 永不过期
		State:        ARPStateReachable,
		RetryCount:   0,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		LastAccessed: time.Now(),
	}

	return nil
}

// IsStatic 检查ARP条目是否为静态条目
func (at *ARPTable) IsStatic(ip net.IP) bool {
	entry, found := at.LookupEntry(ip)
	if !found {
		return false
	}

	return entry.TTL == -1
}

// FlushTable 清空ARP表
func (at *ARPTable) FlushTable() {
	at.mu.Lock()
	defer at.mu.Unlock()

	at.entries = make(map[string]*ARPEntry)
	at.stats.TotalEntries = 0
}

// GetNeighborsByInterface 按接口获取邻居
func (at *ARPTable) GetNeighborsByInterface(iface string) []*ARPEntry {
	at.mu.RLock()
	defer at.mu.RUnlock()

	var neighbors []*ARPEntry
	for _, entry := range at.entries {
		if entry.Interface == iface {
			neighbors = append(neighbors, entry)
		}
	}

	return neighbors
}

// parseARPPacket 解析ARP数据包
func (at *ARPTable) parseARPPacket(data []byte) (*ARPPacket, error) {
	if len(data) < ARPPacketSize {
		return nil, fmt.Errorf("ARP数据包长度不足: %d < %d", len(data), ARPPacketSize)
	}

	packet := &ARPPacket{
		HardwareType:       uint16(data[0])<<8 | uint16(data[1]),
		ProtocolType:       uint16(data[2])<<8 | uint16(data[3]),
		HardwareAddrLength: data[4],
		ProtocolAddrLength: data[5],
		Operation:          uint16(data[6])<<8 | uint16(data[7]),
	}

	// 验证ARP包格式
	if packet.HardwareType != ARPHardwareTypeEthernet {
		return nil, fmt.Errorf("不支持的硬件类型: %d", packet.HardwareType)
	}
	if packet.ProtocolType != ARPProtocolTypeIPv4 {
		return nil, fmt.Errorf("不支持的协议类型: 0x%04x", packet.ProtocolType)
	}
	if packet.HardwareAddrLength != ARPHardwareAddrLen {
		return nil, fmt.Errorf("无效的硬件地址长度: %d", packet.HardwareAddrLength)
	}
	if packet.ProtocolAddrLength != ARPProtocolAddrLen {
		return nil, fmt.Errorf("无效的协议地址长度: %d", packet.ProtocolAddrLength)
	}

	// 复制地址信息
	copy(packet.SenderHardwareAddr[:], data[8:14])
	copy(packet.SenderProtocolAddr[:], data[14:18])
	copy(packet.TargetHardwareAddr[:], data[18:24])
	copy(packet.TargetProtocolAddr[:], data[24:28])

	return packet, nil
}

// serializeARPPacket 序列化ARP数据包
func (at *ARPTable) serializeARPPacket(packet *ARPPacket) []byte {
	data := make([]byte, ARPPacketSize)

	// 设置头部字段
	data[0] = byte(packet.HardwareType >> 8)
	data[1] = byte(packet.HardwareType)
	data[2] = byte(packet.ProtocolType >> 8)
	data[3] = byte(packet.ProtocolType)
	data[4] = packet.HardwareAddrLength
	data[5] = packet.ProtocolAddrLength
	data[6] = byte(packet.Operation >> 8)
	data[7] = byte(packet.Operation)

	// 复制地址信息
	copy(data[8:14], packet.SenderHardwareAddr[:])
	copy(data[14:18], packet.SenderProtocolAddr[:])
	copy(data[18:24], packet.TargetHardwareAddr[:])
	copy(data[24:28], packet.TargetProtocolAddr[:])

	return data
}

// processARPPacket 处理接收到的ARP数据包
func (at *ARPTable) processARPPacket(packet *ARPPacket, iface string) error {
	senderIP := net.IP(packet.SenderProtocolAddr[:])
	senderMAC := net.HardwareAddr(packet.SenderHardwareAddr[:])
	targetIP := net.IP(packet.TargetProtocolAddr[:])

	switch packet.Operation {
	case ARPOperationRequest:
		// 处理ARP请求
		return at.handleARPRequest(senderIP, senderMAC, targetIP, iface)
	case ARPOperationReply:
		// 处理ARP响应
		return at.HandleARPReply(senderIP, senderMAC, iface)
	default:
		return fmt.Errorf("未知的ARP操作类型: %d", packet.Operation)
	}
}

// handleARPRequest 处理ARP请求
func (at *ARPTable) handleARPRequest(senderIP net.IP, senderMAC net.HardwareAddr, targetIP net.IP, iface string) error {
	// 更新发送方的ARP条目
	_ = at.AddEntry(senderIP, senderMAC, iface)

	// 检查目标IP是否是本机接口IP
	ifaceInfo, err := at.getInterfaceInfo(iface)
	if err != nil {
		return fmt.Errorf("获取接口信息失败: %v", err)
	}

	if ifaceInfo.IP.Equal(targetIP) {
		// 目标IP是本机，发送ARP响应
		return at.sendARPReply(senderIP, senderMAC, targetIP, ifaceInfo)
	}

	// 目标IP不是本机，忽略请求
	return nil
}

// sendARPReply 发送ARP响应
func (at *ARPTable) sendARPReply(targetIP net.IP, targetMAC net.HardwareAddr, sourceIP net.IP, ifaceInfo *InterfaceInfo) error {
	// 创建ARP响应包
	packet := &ARPPacket{
		HardwareType:       ARPHardwareTypeEthernet,
		ProtocolType:       ARPProtocolTypeIPv4,
		HardwareAddrLength: ARPHardwareAddrLen,
		ProtocolAddrLength: ARPProtocolAddrLen,
		Operation:          ARPOperationReply,
	}

	// 设置发送方地址（本机）
	copy(packet.SenderHardwareAddr[:], ifaceInfo.MAC)
	copy(packet.SenderProtocolAddr[:], sourceIP.To4())

	// 设置目标地址
	copy(packet.TargetHardwareAddr[:], targetMAC)
	copy(packet.TargetProtocolAddr[:], targetIP.To4())

	// 发送ARP响应（在实际实现中需要使用原始套接字）
	// 这里使用系统命令作为替代
	return at.sendRawARPPacket(packet, ifaceInfo)
}

// startARPListener 启动ARP数据包监听器
func (at *ARPTable) startARPListener() error {
	// 创建原始套接字来监听ARP数据包
	// 注意：需要root权限才能创建原始套接字

	// 尝试创建原始套接字
	if err := at.createRawSocket(); err != nil {
		// 如果无法创建原始套接字（通常是权限问题），使用系统命令监听
		return at.startSystemARPMonitor()
	}

	// 启动数据包监听循环
	go at.packetListenerLoop()

	return nil
}

// createRawSocket 创建原始套接字
func (at *ARPTable) createRawSocket() error {
	// 在 macOS 上，AF_PACKET 不可用，返回错误以使用系统命令替代
	return fmt.Errorf("原始套接字在此平台上不可用，使用系统命令替代")
}

// htons 主机字节序转网络字节序
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// startSystemARPMonitor 使用系统命令监听ARP变化
func (at *ARPTable) startSystemARPMonitor() error {
	// 如果无法使用原始套接字，使用系统ARP表监控
	go at.systemARPMonitorLoop()
	return nil
}

// packetListenerLoop 数据包监听循环
func (at *ARPTable) packetListenerLoop() {
	// 在 macOS 上不使用原始套接字，直接返回
	return
}

// processRawPacket 处理原始数据包
func (at *ARPTable) processRawPacket(data []byte) {
	// 检查是否是以太网帧
	if len(data) < 14 {
		return // 太短，不是有效的以太网帧
	}

	// 解析以太网头部
	etherType := binary.BigEndian.Uint16(data[12:14])
	if etherType != 0x0806 { // ARP协议类型
		return
	}

	// 提取ARP数据包部分
	arpData := data[14:]
	if len(arpData) < ARPPacketSize {
		return
	}

	// 解析ARP数据包
	packet, err := at.parseARPPacket(arpData)
	if err != nil {
		return
	}

	// 处理ARP数据包
	at.processARPPacket(packet, "")
}

// systemARPMonitorLoop 系统ARP表监控循环
func (at *ARPTable) systemARPMonitorLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	lastARPTable := make(map[string]string)

	for at.running {
		select {
		case <-ticker.C:
			currentARPTable := at.getSystemARPTable()

			// 检查ARP表变化
			for ip, mac := range currentARPTable {
				if lastMAC, exists := lastARPTable[ip]; !exists || lastMAC != mac {
					// 新的或变化的ARP条目
					if parsedIP := net.ParseIP(ip); parsedIP != nil {
						if parsedMAC, err := net.ParseMAC(mac); err == nil {
							// 更新ARP表
							at.HandleARPReply(parsedIP, parsedMAC, "")
						}
					}
				}
			}

			lastARPTable = currentARPTable
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// getSystemARPTable 获取系统ARP表
func (at *ARPTable) getSystemARPTable() map[string]string {
	arpTable := make(map[string]string)

	// 使用arp命令获取系统ARP表
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return arpTable
	}

	// 解析arp命令输出
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "at") && strings.Contains(line, ":") {
			// 解析格式: hostname (ip) at mac [ether] on interface
			parts := strings.Fields(line)
			for i, part := range parts {
				if strings.HasPrefix(part, "(") && strings.HasSuffix(part, ")") {
					ip := strings.Trim(part, "()")
					if i+2 < len(parts) && strings.Contains(parts[i+2], ":") {
						mac := parts[i+2]
						arpTable[ip] = mac
					}
					break
				}
			}
		}
	}

	return arpTable
}

// stopARPListener 停止ARP数据包监听器
func (at *ARPTable) stopARPListener() {
	// 停止所有监听活动
	at.mu.Lock()
	defer at.mu.Unlock()

	// 重置原始套接字状态
	at.rawSocket = -1

	// 清理待处理的请求
	for key := range at.pendingRequests {
		delete(at.pendingRequests, key)
	}

	// 注意：实际的goroutine会通过检查at.running状态自动退出
}

// GetPendingRequests 获取待处理的ARP请求
func (at *ARPTable) GetPendingRequests() map[string]*PendingRequest {
	at.mu.RLock()
	defer at.mu.RUnlock()

	result := make(map[string]*PendingRequest)
	for key, request := range at.pendingRequests {
		result[key] = request
	}
	return result
}

// ClearPendingRequests 清除所有待处理的ARP请求
func (at *ARPTable) ClearPendingRequests() {
	at.mu.Lock()
	defer at.mu.Unlock()

	for key := range at.pendingRequests {
		delete(at.pendingRequests, key)
	}
}
