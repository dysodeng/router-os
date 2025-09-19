package arp

import (
	"bytes"
	"fmt"
	"net"
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
	}
}

// Start 启动ARP表管理器
func (at *ARPTable) Start() error {
	at.mu.Lock()
	defer at.mu.Unlock()

	if at.running {
		return fmt.Errorf("ARP表管理器已经在运行")
	}

	at.running = true

	// 启动清理协程
	go at.cleanupLoop()

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
	return at.simulateARPRequest(ip, iface, timeout)
}

// simulateARPRequest 模拟ARP请求过程
func (at *ARPTable) simulateARPRequest(ip net.IP, iface string, timeout time.Duration) (net.HardwareAddr, error) {
	// 模拟ARP解析延迟
	time.Sleep(10 * time.Millisecond)

	// 生成模拟的MAC地址
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	// 将解析结果添加到ARP表
	err := at.AddEntry(ip, mac, iface)
	if err != nil {
		return nil, fmt.Errorf("添加ARP条目失败: %v", err)
	}

	return mac, nil
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
	go at.simulateARPRequestAsync(targetIP, iface)

	return nil
}

// simulateARPRequestAsync 异步模拟ARP请求
func (at *ARPTable) simulateARPRequestAsync(targetIP net.IP, iface string) {
	// 模拟网络延迟
	time.Sleep(time.Millisecond * 10)

	// 模拟收到ARP响应
	mockMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	at.HandleARPReply(targetIP, mockMAC, iface)
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
