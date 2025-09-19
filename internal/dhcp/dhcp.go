package dhcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

// DHCPServer DHCP服务器
// 提供动态主机配置协议服务，自动分配IP地址和网络配置
//
// 主要功能：
// 1. IP地址分配：动态分配可用的IP地址
// 2. 租约管理：管理IP地址租约的生命周期
// 3. 配置分发：分发网络配置信息（网关、DNS等）
// 4. 地址保留：为特定MAC地址保留固定IP
// 5. 租约续期：处理客户端的租约续期请求
//
// 支持的DHCP消息类型：
// - DHCPDISCOVER：客户端发现DHCP服务器
// - DHCPOFFER：服务器提供IP地址
// - DHCPREQUEST：客户端请求IP地址
// - DHCPACK：服务器确认分配
// - DHCPNAK：服务器拒绝请求
// - DHCPRELEASE：客户端释放IP地址
// - DHCPINFORM：客户端请求配置信息
//
// 地址池管理：
// - 动态地址池：可动态分配的IP地址范围
// - 静态保留：为特定设备保留的固定IP
// - 排除地址：不参与分配的IP地址
// - 租约时间：IP地址的使用期限
//
// 配置选项支持：
// - 子网掩码、网关、DNS服务器
// - 域名、NTP服务器、WINS服务器
// - 自定义DHCP选项
type DHCPServer struct {
	// mu 读写锁
	mu sync.RWMutex

	// running 运行状态
	running bool

	// config 服务器配置
	config DHCPConfig

	// pools 地址池
	pools map[string]*AddressPool

	// leases 租约表
	leases map[string]*Lease

	// reservations 地址保留
	reservations map[string]*Reservation

	// stats 统计信息
	stats DHCPStats

	// conn UDP连接
	conn *net.UDPConn

	// stopChan 停止信号
	stopChan chan struct{}
}

// DHCPConfig DHCP服务器配置
type DHCPConfig struct {
	// Enabled 是否启用DHCP服务
	Enabled bool

	// Interface 监听接口
	Interface string

	// ListenAddress 监听地址
	ListenAddress string

	// ListenPort 监听端口
	ListenPort int

	// DefaultLeaseTime 默认租约时间
	DefaultLeaseTime time.Duration

	// MaxLeaseTime 最大租约时间
	MaxLeaseTime time.Duration

	// MinLeaseTime 最小租约时间
	MinLeaseTime time.Duration

	// PingCheck 是否进行ping检查
	PingCheck bool

	// PingTimeout ping超时时间
	PingTimeout time.Duration

	// LogLevel 日志级别
	LogLevel string

	// DatabaseFile 数据库文件路径
	DatabaseFile string
}

// AddressPool 地址池
type AddressPool struct {
	// ID 地址池ID
	ID string

	// Name 地址池名称
	Name string

	// Network 网络地址
	Network *net.IPNet

	// StartIP 起始IP地址
	StartIP net.IP

	// EndIP 结束IP地址
	EndIP net.IP

	// Gateway 网关地址
	Gateway net.IP

	// DNSServers DNS服务器列表
	DNSServers []net.IP

	// DomainName 域名
	DomainName string

	// LeaseTime 租约时间
	LeaseTime time.Duration

	// Options DHCP选项
	Options map[byte][]byte

	// ExcludedIPs 排除的IP地址
	ExcludedIPs []net.IP

	// Enabled 是否启用
	Enabled bool

	// CreatedAt 创建时间
	CreatedAt time.Time

	// stats 地址池统计
	stats PoolStats
}

// Lease 租约信息
type Lease struct {
	// IP 分配的IP地址
	IP net.IP

	// MAC 客户端MAC地址
	MAC net.HardwareAddr

	// Hostname 主机名
	Hostname string

	// ClientID 客户端ID
	ClientID []byte

	// StartTime 租约开始时间
	StartTime time.Time

	// EndTime 租约结束时间
	EndTime time.Time

	// State 租约状态 (offered, bound, expired)
	State string

	// Pool 所属地址池
	Pool string

	// Options 客户端请求的选项
	Options map[byte][]byte

	// RenewTime 续约时间
	RenewTime time.Time

	// RebindTime 重新绑定时间
	RebindTime time.Time

	// LastSeen 最后活动时间
	LastSeen time.Time
}

// Reservation 地址保留
type Reservation struct {
	// ID 保留ID
	ID string

	// MAC 客户端MAC地址
	MAC net.HardwareAddr

	// IP 保留的IP地址
	IP net.IP

	// Hostname 主机名
	Hostname string

	// Pool 所属地址池
	Pool string

	// Options 特定选项
	Options map[byte][]byte

	// Enabled 是否启用
	Enabled bool

	// CreatedAt 创建时间
	CreatedAt time.Time
}

// DHCPMessage DHCP消息
type DHCPMessage struct {
	// Op 操作类型 (1=BOOTREQUEST, 2=BOOTREPLY)
	Op byte

	// Htype 硬件类型
	Htype byte

	// Hlen 硬件地址长度
	Hlen byte

	// Hops 跳数
	Hops byte

	// Xid 事务ID
	Xid uint32

	// Secs 秒数
	Secs uint16

	// Flags 标志
	Flags uint16

	// Ciaddr 客户端IP地址
	Ciaddr net.IP

	// Yiaddr 你的IP地址
	Yiaddr net.IP

	// Siaddr 服务器IP地址
	Siaddr net.IP

	// Giaddr 网关IP地址
	Giaddr net.IP

	// Chaddr 客户端硬件地址
	Chaddr net.HardwareAddr

	// Sname 服务器名称
	Sname [64]byte

	// File 启动文件名
	File [128]byte

	// Options DHCP选项
	Options map[byte][]byte
}

// DHCPStats DHCP统计信息
type DHCPStats struct {
	// StartTime 统计开始时间
	StartTime time.Time

	// MessagesReceived 接收的消息总数
	MessagesReceived uint64

	// MessagesSent 发送的消息总数
	MessagesSent uint64

	// DiscoverReceived 接收的DISCOVER消息数
	DiscoverReceived uint64

	// OffersSent 发送的OFFER消息数
	OffersSent uint64

	// RequestsReceived 接收的REQUEST消息数
	RequestsReceived uint64

	// AcksSent 发送的ACK消息数
	AcksSent uint64

	// NaksSent 发送的NAK消息数
	NaksSent uint64

	// ReleasesReceived 接收的RELEASE消息数
	ReleasesReceived uint64

	// InformsReceived 接收的INFORM消息数
	InformsReceived uint64

	// ActiveLeases 活跃租约数
	ActiveLeases uint64

	// ExpiredLeases 过期租约数
	ExpiredLeases uint64

	// TotalLeases 总租约数
	TotalLeases uint64

	// PoolStats 地址池统计
	PoolStats map[string]PoolStats
}

// PoolStats 地址池统计信息
type PoolStats struct {
	// TotalAddresses 总地址数
	TotalAddresses uint64

	// AllocatedAddresses 已分配地址数
	AllocatedAddresses uint64

	// AvailableAddresses 可用地址数
	AvailableAddresses uint64

	// UtilizationRate 利用率
	UtilizationRate float64

	// LeaseRequests 租约请求数
	LeaseRequests uint64

	// LeaseRenewals 租约续期数
	LeaseRenewals uint64
}

// DHCP消息类型常量
const (
	DHCPDiscover = 1
	DHCPOffer    = 2
	DHCPRequest  = 3
	DHCPDecline  = 4
	DHCPAck      = 5
	DHCPNak      = 6
	DHCPRelease  = 7
	DHCPInform   = 8
)

// DHCP选项常量
const (
	OptionSubnetMask       = 1
	OptionRouter           = 3
	OptionDNS              = 6
	OptionDomainName       = 15
	OptionBroadcastAddress = 28
	OptionRequestedIP      = 50
	OptionLeaseTime        = 51
	OptionMessageType      = 53
	OptionServerID         = 54
	OptionParameterList    = 55
	OptionRenewalTime      = 58
	OptionRebindingTime    = 59
	OptionClientID         = 61
)

// NewDHCPServer 创建新的DHCP服务器
//
// 返回值：
//   - *DHCPServer: DHCP服务器实例
//
// 使用示例：
//   dhcp := NewDHCPServer()
//
//   // 配置地址池
//   pool := &AddressPool{
//       ID: "lan-pool",
//       Network: &net.IPNet{
//           IP:   net.ParseIP("192.168.1.0"),
//           Mask: net.CIDRMask(24, 32),
//       },
//       StartIP: net.ParseIP("192.168.1.100"),
//       EndIP:   net.ParseIP("192.168.1.200"),
//       Gateway: net.ParseIP("192.168.1.1"),
//       DNSServers: []net.IP{
//           net.ParseIP("8.8.8.8"),
//           net.ParseIP("8.8.4.4"),
//       },
//       LeaseTime: 24 * time.Hour,
//   }
//   dhcp.AddPool(pool)
//
//   // 启动服务器
//   dhcp.Start()
//   defer dhcp.Stop()

// 在NewDHCPServer函数中添加更完整的初始化
func NewDHCPServer() *DHCPServer {
	ds := &DHCPServer{
		config: DHCPConfig{
			Enabled:          false,
			Interface:        "eth0",
			ListenAddress:    "0.0.0.0",
			ListenPort:       67,
			DefaultLeaseTime: 24 * time.Hour,
			MaxLeaseTime:     7 * 24 * time.Hour,
			MinLeaseTime:     1 * time.Hour,
			PingCheck:        true,
			PingTimeout:      1 * time.Second,
			LogLevel:         "info",
			DatabaseFile:     "/var/lib/dhcp/dhcp.leases",
		},
		pools:        make(map[string]*AddressPool),
		leases:       make(map[string]*Lease),
		reservations: make(map[string]*Reservation),
		stats: DHCPStats{
			StartTime: time.Now(),
			PoolStats: make(map[string]PoolStats),
		},
	}

	// 加载持久化数据
	ds.loadLeases()
	ds.loadReservations()

	return ds
}

// Start 启动DHCP服务器
func (ds *DHCPServer) Start() error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if ds.running {
		return fmt.Errorf("DHCP服务器已经在运行")
	}

	if !ds.config.Enabled {
		return fmt.Errorf("DHCP服务器未启用")
	}

	// 创建UDP监听
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ds.config.ListenAddress, ds.config.ListenPort))
	if err != nil {
		return fmt.Errorf("解析监听地址失败: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("创建UDP监听失败: %v", err)
	}

	ds.conn = conn
	ds.running = true
	ds.stats.StartTime = time.Now()

	// 启动消息处理协程
	go ds.messageHandler()

	// 启动租约清理协程
	go ds.leaseCleanup()

	// 启动统计更新协程
	go ds.statsUpdater()

	return nil
}

// Stop 停止DHCP服务器
func (ds *DHCPServer) Stop() {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if !ds.running {
		return
	}

	ds.running = false

	// 关闭连接
	if ds.conn != nil {
		ds.conn.Close()
	}

	// 发送停止信号
	close(ds.stopChan)
}

// messageHandler 消息处理器
func (ds *DHCPServer) messageHandler() {
	buffer := make([]byte, 1500) // 最大以太网帧大小

	for ds.IsRunning() {
		// 设置读取超时
		ds.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, clientAddr, err := ds.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // 超时继续
			}
			if ds.IsRunning() {
				fmt.Printf("读取UDP消息失败: %v\n", err)
			}
			continue
		}

		// 解析DHCP消息
		msg, err := ds.parseDHCPMessage(buffer[:n])
		if err != nil {
			fmt.Printf("解析DHCP消息失败: %v\n", err)
			continue
		}

		// 更新统计信息
		ds.mu.Lock()
		ds.stats.MessagesReceived++
		ds.mu.Unlock()

		// 处理消息
		go ds.handleMessage(msg, clientAddr)
	}
}

// handleMessage 处理DHCP消息
func (ds *DHCPServer) handleMessage(msg *DHCPMessage, clientAddr *net.UDPAddr) {
	// 获取消息类型
	msgTypeBytes, exists := msg.Options[OptionMessageType]
	if !exists || len(msgTypeBytes) == 0 {
		return
	}

	msgType := msgTypeBytes[0]

	// 根据消息类型处理
	switch msgType {
	case DHCPDiscover:
		ds.handleDiscover(msg, clientAddr)
	case DHCPRequest:
		ds.handleRequest(msg, clientAddr)
	case DHCPRelease:
		ds.handleRelease(msg, clientAddr)
	case DHCPInform:
		ds.handleInform(msg, clientAddr)
	default:
		fmt.Printf("未知的DHCP消息类型: %d\n", msgType)
	}
}

// handleDiscover 处理DISCOVER消息
func (ds *DHCPServer) handleDiscover(msg *DHCPMessage, clientAddr *net.UDPAddr) {
	ds.mu.Lock()
	ds.stats.DiscoverReceived++
	ds.mu.Unlock()

	// 查找可用的IP地址
	ip, pool := ds.findAvailableIP(msg.Chaddr)
	if ip == nil {
		fmt.Printf("没有可用的IP地址分配给 %s\n", msg.Chaddr.String())
		return
	}

	// 创建租约
	lease := &Lease{
		IP:        ip,
		MAC:       msg.Chaddr,
		StartTime: time.Now(),
		EndTime:   time.Now().Add(pool.LeaseTime),
		State:     "offered",
		Pool:      pool.ID,
		Options:   make(map[byte][]byte),
	}

	// 保存租约
	leaseKey := ds.generateLeaseKey(msg.Chaddr, ip)
	ds.mu.Lock()
	ds.leases[leaseKey] = lease
	ds.mu.Unlock()

	// 发送OFFER消息
	ds.sendOffer(msg, lease, pool, clientAddr)
}

// handleRequest 处理REQUEST消息
func (ds *DHCPServer) handleRequest(msg *DHCPMessage, clientAddr *net.UDPAddr) {
	ds.mu.Lock()
	ds.stats.RequestsReceived++
	ds.mu.Unlock()

	// 获取请求的IP地址
	requestedIPBytes, exists := msg.Options[OptionRequestedIP]
	if !exists || len(requestedIPBytes) != 4 {
		ds.sendNak(msg, clientAddr, "无效的请求IP地址")
		return
	}

	requestedIP := net.IP(requestedIPBytes)
	leaseKey := ds.generateLeaseKey(msg.Chaddr, requestedIP)

	// 查找租约
	ds.mu.RLock()
	lease, exists := ds.leases[leaseKey]
	ds.mu.RUnlock()

	if !exists {
		ds.sendNak(msg, clientAddr, "租约不存在")
		return
	}

	// 验证租约
	if lease.MAC.String() != msg.Chaddr.String() {
		ds.sendNak(msg, clientAddr, "MAC地址不匹配")
		return
	}

	// 更新租约状态
	ds.mu.Lock()
	lease.State = "bound"
	lease.StartTime = time.Now()
	lease.EndTime = time.Now().Add(ds.getPoolByID(lease.Pool).LeaseTime)
	lease.RenewTime = lease.StartTime.Add(lease.EndTime.Sub(lease.StartTime) / 2)
	lease.RebindTime = lease.StartTime.Add(lease.EndTime.Sub(lease.StartTime) * 7 / 8)
	lease.LastSeen = time.Now()
	ds.mu.Unlock()

	// 发送ACK消息
	pool := ds.getPoolByID(lease.Pool)
	ds.sendAck(msg, lease, pool, clientAddr)
}

// handleRelease 处理RELEASE消息
func (ds *DHCPServer) handleRelease(msg *DHCPMessage, clientAddr *net.UDPAddr) {
	ds.mu.Lock()
	ds.stats.ReleasesReceived++
	ds.mu.Unlock()

	// 查找并删除租约
	leaseKey := ds.generateLeaseKey(msg.Chaddr, msg.Ciaddr)

	ds.mu.Lock()
	if lease, exists := ds.leases[leaseKey]; exists {
		delete(ds.leases, leaseKey)
		fmt.Printf("释放租约: %s -> %s\n", lease.MAC.String(), lease.IP.String())
	}
	ds.mu.Unlock()
}

// handleInform 处理INFORM消息
func (ds *DHCPServer) handleInform(msg *DHCPMessage, clientAddr *net.UDPAddr) {
	ds.mu.Lock()
	ds.stats.InformsReceived++
	ds.mu.Unlock()

	// 查找客户端所在的网络池
	pool := ds.findPoolByIP(msg.Ciaddr)
	if pool == nil {
		return
	}

	// 发送配置信息
	ds.sendInformAck(msg, pool, clientAddr)
}

// findAvailableIP 查找可用的IP地址
func (ds *DHCPServer) findAvailableIP(mac net.HardwareAddr) (net.IP, *AddressPool) {
	// 首先检查是否有地址保留
	ds.mu.RLock()
	for _, reservation := range ds.reservations {
		if reservation.Enabled && reservation.MAC.String() == mac.String() {
			pool := ds.pools[reservation.Pool]
			ds.mu.RUnlock()
			return reservation.IP, pool
		}
	}
	ds.mu.RUnlock()

	// 查找可用的动态地址
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	for _, pool := range ds.pools {
		if !pool.Enabled {
			continue
		}

		ip := ds.findAvailableIPInPool(pool)
		if ip != nil {
			return ip, pool
		}
	}

	return nil, nil
}

// findAvailableIPInPool 在地址池中查找可用IP
func (ds *DHCPServer) findAvailableIPInPool(pool *AddressPool) net.IP {
	// 将IP地址转换为整数进行遍历
	start := ipToInt(pool.StartIP)
	end := ipToInt(pool.EndIP)

	for i := start; i <= end; i++ {
		ip := intToIP(i)

		// 检查是否在排除列表中
		if ds.isIPExcluded(ip, pool.ExcludedIPs) {
			continue
		}

		// 检查是否已被租用
		if ds.isIPLeased(ip) {
			continue
		}

		// 如果启用ping检查，验证IP是否可用
		if ds.config.PingCheck && ds.pingIP(ip) {
			continue
		}

		return ip
	}

	return nil
}

// isIPExcluded 检查IP是否在排除列表中
func (ds *DHCPServer) isIPExcluded(ip net.IP, excludedIPs []net.IP) bool {
	for _, excluded := range excludedIPs {
		if ip.Equal(excluded) {
			return true
		}
	}
	return false
}

// isIPLeased 检查IP是否已被租用
func (ds *DHCPServer) isIPLeased(ip net.IP) bool {
	for _, lease := range ds.leases {
		if lease.IP.Equal(ip) && lease.State != "expired" {
			return true
		}
	}
	return false
}

// pingIP 检查IP地址是否可达（真实实现）
func (ds *DHCPServer) pingIP(ip net.IP) bool {
	if !ds.config.PingCheck {
		return false // 如果禁用ping检查，认为IP可用
	}

	// 使用系统ping命令检查IP是否可达
	timeout := ds.config.PingTimeout
	if timeout == 0 {
		timeout = 1 * time.Second // 默认超时时间
	}

	// 构建ping命令
	var cmd *exec.Cmd
	switch {
	case ip.To4() != nil:
		// IPv4 ping
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%.0f", timeout.Seconds()*1000), ip.String())
	case ip.To16() != nil:
		// IPv6 ping
		cmd = exec.Command("ping6", "-c", "1", "-W", fmt.Sprintf("%.0f", timeout.Seconds()*1000), ip.String())
	default:
		return false // 无效IP地址
	}

	// 执行ping命令
	err := cmd.Run()
	if err != nil {
		// ping失败，表示IP不可达（可用）
		return false
	}

	// ping成功，表示IP已被占用（不可用）
	return true
}

// sendOffer 发送OFFER消息
func (ds *DHCPServer) sendOffer(request *DHCPMessage, lease *Lease, pool *AddressPool, clientAddr *net.UDPAddr) {
	offer := &DHCPMessage{
		Op:      2, // BOOTREPLY
		Htype:   request.Htype,
		Hlen:    request.Hlen,
		Xid:     request.Xid,
		Yiaddr:  lease.IP,
		Siaddr:  ds.getServerIP(),
		Chaddr:  request.Chaddr,
		Options: make(map[byte][]byte),
	}

	// 设置DHCP选项
	offer.Options[OptionMessageType] = []byte{DHCPOffer}
	offer.Options[OptionServerID] = ds.getServerIP().To4()
	offer.Options[OptionLeaseTime] = ds.durationToBytes(pool.LeaseTime)
	offer.Options[OptionSubnetMask] = pool.Network.Mask

	if pool.Gateway != nil {
		offer.Options[OptionRouter] = pool.Gateway.To4()
	}

	if len(pool.DNSServers) > 0 {
		dnsBytes := make([]byte, 0, len(pool.DNSServers)*4)
		for _, dns := range pool.DNSServers {
			dnsBytes = append(dnsBytes, dns.To4()...)
		}
		offer.Options[OptionDNS] = dnsBytes
	}

	if pool.DomainName != "" {
		offer.Options[OptionDomainName] = []byte(pool.DomainName)
	}

	// 发送消息
	ds.sendMessage(offer, clientAddr)

	ds.mu.Lock()
	ds.stats.OffersSent++
	ds.mu.Unlock()
}

// sendAck 发送ACK消息
func (ds *DHCPServer) sendAck(request *DHCPMessage, lease *Lease, pool *AddressPool, clientAddr *net.UDPAddr) {
	ack := &DHCPMessage{
		Op:      2, // BOOTREPLY
		Htype:   request.Htype,
		Hlen:    request.Hlen,
		Xid:     request.Xid,
		Yiaddr:  lease.IP,
		Siaddr:  ds.getServerIP(),
		Chaddr:  request.Chaddr,
		Options: make(map[byte][]byte),
	}

	// 设置DHCP选项
	ack.Options[OptionMessageType] = []byte{DHCPAck}
	ack.Options[OptionServerID] = ds.getServerIP().To4()
	ack.Options[OptionLeaseTime] = ds.durationToBytes(pool.LeaseTime)
	ack.Options[OptionRenewalTime] = ds.durationToBytes(pool.LeaseTime / 2)
	ack.Options[OptionRebindingTime] = ds.durationToBytes(pool.LeaseTime * 7 / 8)
	ack.Options[OptionSubnetMask] = pool.Network.Mask

	if pool.Gateway != nil {
		ack.Options[OptionRouter] = pool.Gateway.To4()
	}

	if len(pool.DNSServers) > 0 {
		dnsBytes := make([]byte, 0, len(pool.DNSServers)*4)
		for _, dns := range pool.DNSServers {
			dnsBytes = append(dnsBytes, dns.To4()...)
		}
		ack.Options[OptionDNS] = dnsBytes
	}

	if pool.DomainName != "" {
		ack.Options[OptionDomainName] = []byte(pool.DomainName)
	}

	// 发送消息
	ds.sendMessage(ack, clientAddr)

	ds.mu.Lock()
	ds.stats.AcksSent++
	ds.mu.Unlock()
}

// sendNak 发送NAK消息
func (ds *DHCPServer) sendNak(request *DHCPMessage, clientAddr *net.UDPAddr, reason string) {
	nak := &DHCPMessage{
		Op:      2, // BOOTREPLY
		Htype:   request.Htype,
		Hlen:    request.Hlen,
		Xid:     request.Xid,
		Chaddr:  request.Chaddr,
		Options: make(map[byte][]byte),
	}

	nak.Options[OptionMessageType] = []byte{DHCPNak}
	nak.Options[OptionServerID] = ds.getServerIP().To4()

	// 发送消息
	ds.sendMessage(nak, clientAddr)

	ds.mu.Lock()
	ds.stats.NaksSent++
	ds.mu.Unlock()

	fmt.Printf("发送NAK给 %s: %s\n", request.Chaddr.String(), reason)
}

// sendInformAck 发送INFORM ACK消息
func (ds *DHCPServer) sendInformAck(request *DHCPMessage, pool *AddressPool, clientAddr *net.UDPAddr) {
	ack := &DHCPMessage{
		Op:      2, // BOOTREPLY
		Htype:   request.Htype,
		Hlen:    request.Hlen,
		Xid:     request.Xid,
		Ciaddr:  request.Ciaddr,
		Chaddr:  request.Chaddr,
		Options: make(map[byte][]byte),
	}

	// 设置配置选项
	ack.Options[OptionMessageType] = []byte{DHCPAck}
	ack.Options[OptionServerID] = ds.getServerIP().To4()
	ack.Options[OptionSubnetMask] = pool.Network.Mask

	if pool.Gateway != nil {
		ack.Options[OptionRouter] = pool.Gateway.To4()
	}

	if len(pool.DNSServers) > 0 {
		dnsBytes := make([]byte, 0, len(pool.DNSServers)*4)
		for _, dns := range pool.DNSServers {
			dnsBytes = append(dnsBytes, dns.To4()...)
		}
		ack.Options[OptionDNS] = dnsBytes
	}

	if pool.DomainName != "" {
		ack.Options[OptionDomainName] = []byte(pool.DomainName)
	}

	// 发送消息
	ds.sendMessage(ack, clientAddr)
}

// sendMessage 发送DHCP消息
func (ds *DHCPServer) sendMessage(msg *DHCPMessage, clientAddr *net.UDPAddr) {
	// 序列化消息
	data, err := ds.serializeDHCPMessage(msg)
	if err != nil {
		fmt.Printf("序列化DHCP消息失败: %v\n", err)
		return
	}

	// 发送消息
	_, err = ds.conn.WriteToUDP(data, clientAddr)
	if err != nil {
		fmt.Printf("发送DHCP消息失败: %v\n", err)
		return
	}

	ds.mu.Lock()
	ds.stats.MessagesSent++
	ds.mu.Unlock()
}

// AddPool 添加地址池
//
// 参数：
//   - pool: 地址池配置
//
// 返回值：
//   - error: 添加成功返回nil，失败返回错误信息
func (ds *DHCPServer) AddPool(pool *AddressPool) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, exists := ds.pools[pool.ID]; exists {
		return fmt.Errorf("地址池已存在: %s", pool.ID)
	}

	pool.CreatedAt = time.Now()
	pool.stats = PoolStats{}

	// 计算地址池大小
	start := ipToInt(pool.StartIP)
	end := ipToInt(pool.EndIP)
	pool.stats.TotalAddresses = uint64(end - start + 1)
	pool.stats.AvailableAddresses = pool.stats.TotalAddresses

	ds.pools[pool.ID] = pool
	ds.stats.PoolStats[pool.ID] = pool.stats

	return nil
}

// RemovePool 删除地址池
//
// 参数：
//   - poolID: 地址池ID
//
// 返回值：
//   - error: 删除成功返回nil，失败返回错误信息
func (ds *DHCPServer) RemovePool(poolID string) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, exists := ds.pools[poolID]; !exists {
		return fmt.Errorf("地址池不存在: %s", poolID)
	}

	// 删除相关租约
	for key, lease := range ds.leases {
		if lease.Pool == poolID {
			delete(ds.leases, key)
		}
	}

	// 删除相关保留
	for key, reservation := range ds.reservations {
		if reservation.Pool == poolID {
			delete(ds.reservations, key)
		}
	}

	delete(ds.pools, poolID)
	delete(ds.stats.PoolStats, poolID)

	return nil
}

// AddReservation 添加地址保留
//
// 参数：
//   - reservation: 地址保留配置
//
// 返回值：
//   - error: 添加成功返回nil，失败返回错误信息
func (ds *DHCPServer) AddReservation(reservation *Reservation) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, exists := ds.reservations[reservation.ID]; exists {
		return fmt.Errorf("地址保留已存在: %s", reservation.ID)
	}

	reservation.CreatedAt = time.Now()
	ds.reservations[reservation.ID] = reservation

	return nil
}

// RemoveReservation 删除地址保留
//
// 参数：
//   - reservationID: 保留ID
//
// 返回值：
//   - error: 删除成功返回nil，失败返回错误信息
func (ds *DHCPServer) RemoveReservation(reservationID string) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, exists := ds.reservations[reservationID]; !exists {
		return fmt.Errorf("地址保留不存在: %s", reservationID)
	}

	delete(ds.reservations, reservationID)

	return nil
}

// GetLeases 获取所有租约
//
// 返回值：
//   - []*Lease: 租约列表
func (ds *DHCPServer) GetLeases() []*Lease {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	leases := make([]*Lease, 0, len(ds.leases))
	for _, lease := range ds.leases {
		leases = append(leases, lease)
	}

	return leases
}

// GetPools 获取所有地址池
//
// 返回值：
//   - []*AddressPool: 地址池列表
func (ds *DHCPServer) GetPools() []*AddressPool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	pools := make([]*AddressPool, 0, len(ds.pools))
	for _, pool := range ds.pools {
		pools = append(pools, pool)
	}

	return pools
}

// GetReservations 获取所有地址保留
//
// 返回值：
//   - []*Reservation: 保留列表
func (ds *DHCPServer) GetReservations() []*Reservation {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	reservations := make([]*Reservation, 0, len(ds.reservations))
	for _, reservation := range ds.reservations {
		reservations = append(reservations, reservation)
	}

	return reservations
}

// GetStats 获取DHCP统计信息
//
// 返回值：
//   - DHCPStats: 统计信息
func (ds *DHCPServer) GetStats() DHCPStats {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	// 更新活跃租约数
	activeLeases := uint64(0)
	for _, lease := range ds.leases {
		if lease.State == "bound" && time.Now().Before(lease.EndTime) {
			activeLeases++
		}
	}
	ds.stats.ActiveLeases = activeLeases

	return ds.stats
}

// IsRunning 检查DHCP服务器是否运行
//
// 返回值：
//   - bool: 运行状态
func (ds *DHCPServer) IsRunning() bool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	return ds.running
}

// SetConfig 设置DHCP配置
//
// 参数：
//   - config: DHCP配置
func (ds *DHCPServer) SetConfig(config DHCPConfig) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	ds.config = config
}

// GetConfig 获取DHCP配置
//
// 返回值：
//   - DHCPConfig: DHCP配置
func (ds *DHCPServer) GetConfig() DHCPConfig {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	return ds.config
}

// 内部辅助方法

// leaseCleanup 租约清理协程
func (ds *DHCPServer) leaseCleanup() {
	ticker := time.NewTicker(5 * time.Minute) // 每5分钟清理一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !ds.IsRunning() {
				return
			}
			ds.cleanupExpiredLeases()
		case <-ds.stopChan:
			return
		}
	}
}

// cleanupExpiredLeases 清理过期租约
func (ds *DHCPServer) cleanupExpiredLeases() {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	now := time.Now()
	expiredCount := uint64(0)

	for key, lease := range ds.leases {
		if now.After(lease.EndTime) {
			lease.State = "expired"
			delete(ds.leases, key)
			expiredCount++
		}
	}

	ds.stats.ExpiredLeases += expiredCount
}

// statsUpdater 统计更新协程
func (ds *DHCPServer) statsUpdater() {
	ticker := time.NewTicker(30 * time.Second) // 每30秒更新一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !ds.IsRunning() {
				return
			}
			ds.updatePoolStats()
		case <-ds.stopChan:
			return
		}
	}
}

// updatePoolStats 更新地址池统计
func (ds *DHCPServer) updatePoolStats() {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	for poolID, pool := range ds.pools {
		stats := ds.stats.PoolStats[poolID]

		// 计算已分配地址数
		allocatedCount := uint64(0)
		for _, lease := range ds.leases {
			if lease.Pool == poolID && lease.State == "bound" {
				allocatedCount++
			}
		}

		stats.AllocatedAddresses = allocatedCount
		stats.AvailableAddresses = stats.TotalAddresses - allocatedCount

		if stats.TotalAddresses > 0 {
			stats.UtilizationRate = float64(allocatedCount) / float64(stats.TotalAddresses)
		}

		ds.stats.PoolStats[poolID] = stats
		pool.stats = stats
	}
}

// 辅助函数

// generateLeaseKey 生成租约键
func (ds *DHCPServer) generateLeaseKey(mac net.HardwareAddr, ip net.IP) string {
	return fmt.Sprintf("%s-%s", mac.String(), ip.String())
}

// getPoolByID 根据ID获取地址池
func (ds *DHCPServer) getPoolByID(poolID string) *AddressPool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	return ds.pools[poolID]
}

// findPoolByIP 根据IP查找地址池
func (ds *DHCPServer) findPoolByIP(ip net.IP) *AddressPool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	for _, pool := range ds.pools {
		if pool.Network.Contains(ip) {
			return pool
		}
	}

	return nil
}

// getServerIP 获取服务器IP地址（真实实现）
func (ds *DHCPServer) getServerIP() net.IP {
	// 如果配置中指定了监听地址，使用该地址
	if ds.config.ListenAddress != "" && ds.config.ListenAddress != "0.0.0.0" {
		if ip := net.ParseIP(ds.config.ListenAddress); ip != nil {
			return ip
		}
	}

	// 如果指定了网络接口，获取该接口的IP地址
	if ds.config.Interface != "" {
		if ip := ds.getInterfaceIP(ds.config.Interface); ip != nil {
			return ip
		}
	}

	// 获取默认路由的本地IP地址
	if ip := ds.getDefaultRouteIP(); ip != nil {
		return ip
	}

	// 获取第一个非回环接口的IP地址
	if ip := ds.getFirstNonLoopbackIP(); ip != nil {
		return ip
	}

	// 最后的备选方案
	return net.ParseIP("127.0.0.1")
}

// getInterfaceIP 获取指定网络接口的IP地址
func (ds *DHCPServer) getInterfaceIP(interfaceName string) net.IP {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP
			}
		}
	}

	return nil
}

// getDefaultRouteIP 获取默认路由的本地IP地址
func (ds *DHCPServer) getDefaultRouteIP() net.IP {
	// 连接到一个远程地址来确定本地IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// getFirstNonLoopbackIP 获取第一个非回环接口的IP地址
func (ds *DHCPServer) getFirstNonLoopbackIP() net.IP {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return ipnet.IP
				}
			}
		}
	}

	return nil
}

// durationToBytes 将时间间隔转换为字节
func (ds *DHCPServer) durationToBytes(d time.Duration) []byte {
	seconds := uint32(d.Seconds())
	return []byte{
		byte(seconds >> 24),
		byte(seconds >> 16),
		byte(seconds >> 8),
		byte(seconds),
	}
}

// ipToInt 将IP地址转换为整数
func ipToInt(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3])
}

// intToIP 将整数转换为IP地址
func intToIP(i uint32) net.IP {
	return net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
}

// parseDHCPMessage 解析DHCP消息（完整实现）
func (ds *DHCPServer) parseDHCPMessage(data []byte) (*DHCPMessage, error) {
	if len(data) < 240 {
		return nil, fmt.Errorf("DHCP消息太短，至少需要240字节")
	}

	msg := &DHCPMessage{
		Op:      data[0],
		Htype:   data[1],
		Hlen:    data[2],
		Hops:    data[3],
		Xid:     uint32(data[4])<<24 + uint32(data[5])<<16 + uint32(data[6])<<8 + uint32(data[7]),
		Secs:    uint16(data[8])<<8 + uint16(data[9]),
		Flags:   uint16(data[10])<<8 + uint16(data[11]),
		Ciaddr:  net.IP(data[12:16]),
		Yiaddr:  net.IP(data[16:20]),
		Siaddr:  net.IP(data[20:24]),
		Giaddr:  net.IP(data[24:28]),
		Chaddr:  net.HardwareAddr(data[28 : 28+data[2]]),
		Options: make(map[byte][]byte),
	}

	copy(msg.Sname[:], data[44:108])
	copy(msg.File[:], data[108:236])

	// 解析DHCP选项（完整实现）
	if len(data) > 240 {
		err := ds.parseDHCPOptions(data[240:], msg.Options)
		if err != nil {
			return nil, fmt.Errorf("解析DHCP选项失败: %v", err)
		}
	}

	return msg, nil
}

// parseDHCPOptions 解析DHCP选项
func (ds *DHCPServer) parseDHCPOptions(data []byte, options map[byte][]byte) error {
	// 检查魔术cookie (0x63825363)
	if len(data) < 4 {
		return fmt.Errorf("选项数据太短")
	}

	if data[0] != 0x63 || data[1] != 0x82 || data[2] != 0x53 || data[3] != 0x63 {
		return fmt.Errorf("无效的DHCP魔术cookie")
	}

	offset := 4
	for offset < len(data) {
		if offset >= len(data) {
			break
		}

		optionCode := data[offset]
		offset++

		// 处理特殊选项
		if optionCode == 0 { // Pad选项
			continue
		}

		if optionCode == 255 { // End选项
			break
		}

		// 检查长度字段
		if offset >= len(data) {
			return fmt.Errorf("选项长度字段缺失")
		}

		optionLength := data[offset]
		offset++

		// 检查数据是否足够
		if offset+int(optionLength) > len(data) {
			return fmt.Errorf("选项数据不完整")
		}

		// 提取选项数据
		optionData := make([]byte, optionLength)
		copy(optionData, data[offset:offset+int(optionLength)])
		options[optionCode] = optionData

		offset += int(optionLength)
	}

	return nil
}

// serializeDHCPMessage 序列化DHCP消息（完整实现）
func (ds *DHCPServer) serializeDHCPMessage(msg *DHCPMessage) ([]byte, error) {
	// 创建基本的DHCP消息结构（240字节）
	data := make([]byte, 240)

	data[0] = msg.Op
	data[1] = msg.Htype
	data[2] = msg.Hlen
	data[3] = msg.Hops

	// 事务ID（大端序）
	data[4] = byte(msg.Xid >> 24)
	data[5] = byte(msg.Xid >> 16)
	data[6] = byte(msg.Xid >> 8)
	data[7] = byte(msg.Xid)

	// 秒数和标志（大端序）
	data[8] = byte(msg.Secs >> 8)
	data[9] = byte(msg.Secs)
	data[10] = byte(msg.Flags >> 8)
	data[11] = byte(msg.Flags)

	// IP地址字段
	copy(data[12:16], msg.Ciaddr.To4())
	copy(data[16:20], msg.Yiaddr.To4())
	copy(data[20:24], msg.Siaddr.To4())
	copy(data[24:28], msg.Giaddr.To4())

	// MAC地址
	if len(msg.Chaddr) > 0 {
		copy(data[28:28+len(msg.Chaddr)], msg.Chaddr)
	}

	// 服务器名称和文件名
	copy(data[44:108], msg.Sname[:])
	copy(data[108:236], msg.File[:])

	// 序列化DHCP选项
	optionsData, err := ds.serializeDHCPOptions(msg.Options)
	if err != nil {
		return nil, fmt.Errorf("序列化DHCP选项失败: %v", err)
	}

	// 合并基本消息和选项
	result := append(data, optionsData...)

	return result, nil
}

// serializeDHCPOptions 序列化DHCP选项
func (ds *DHCPServer) serializeDHCPOptions(options map[byte][]byte) ([]byte, error) {
	var buffer bytes.Buffer

	// 写入魔术cookie (0x63825363)
	buffer.Write([]byte{0x63, 0x82, 0x53, 0x63})

	// 序列化所有选项
	for optionCode, optionData := range options {
		// 跳过特殊选项
		if optionCode == 0 || optionCode == 255 {
			continue
		}

		// 检查选项数据长度
		if len(optionData) > 255 {
			return nil, fmt.Errorf("选项 %d 数据太长: %d 字节", optionCode, len(optionData))
		}

		// 写入选项代码
		buffer.WriteByte(optionCode)

		// 写入选项长度
		buffer.WriteByte(byte(len(optionData)))

		// 写入选项数据
		buffer.Write(optionData)
	}

	// 写入结束选项
	buffer.WriteByte(255)

	// 填充到4字节边界
	for buffer.Len()%4 != 0 {
		buffer.WriteByte(0) // Pad选项
	}

	return buffer.Bytes(), nil
}

// 添加租约管理功能
func (ds *DHCPServer) CreateLease(ip net.IP, mac net.HardwareAddr, hostname string, pool *AddressPool) *Lease {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	lease := &Lease{
		IP:         ip,
		MAC:        mac,
		Hostname:   hostname,
		ClientID:   nil,
		StartTime:  time.Now(),
		EndTime:    time.Now().Add(pool.LeaseTime),
		State:      "offered",
		Pool:       pool.ID,
		Options:    make(map[byte][]byte),
		RenewTime:  time.Now().Add(pool.LeaseTime / 2),
		RebindTime: time.Now().Add(pool.LeaseTime * 7 / 8),
		LastSeen:   time.Now(),
	}

	key := ds.generateLeaseKey(mac, ip)
	ds.leases[key] = lease

	// 更新统计信息
	ds.stats.ActiveLeases++

	// 持久化租约
	ds.saveLease(lease)

	return lease
}

func (ds *DHCPServer) RenewLease(lease *Lease, duration time.Duration) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if lease.State != "bound" {
		return fmt.Errorf("lease is not in bound state")
	}

	// 检查续约时间是否合理
	if duration > ds.config.MaxLeaseTime {
		duration = ds.config.MaxLeaseTime
	}
	if duration < ds.config.MinLeaseTime {
		duration = ds.config.MinLeaseTime
	}

	lease.EndTime = time.Now().Add(duration)
	lease.RenewTime = time.Now().Add(duration / 2)
	lease.RebindTime = time.Now().Add(duration * 7 / 8)
	lease.LastSeen = time.Now()

	// 持久化更新
	ds.saveLease(lease)

	return nil
}

func (ds *DHCPServer) ReleaseLease(mac net.HardwareAddr, ip net.IP) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	key := ds.generateLeaseKey(mac, ip)
	lease, exists := ds.leases[key]
	if !exists {
		return fmt.Errorf("lease not found")
	}

	lease.State = "released"
	lease.EndTime = time.Now()

	// 从活跃租约中移除
	delete(ds.leases, key)
	ds.stats.ActiveLeases--

	// 记录到历史
	ds.saveLeaseHistory(lease)

	return nil
}

func (ds *DHCPServer) ExpireLease(lease *Lease) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	lease.State = "expired"
	key := ds.generateLeaseKey(lease.MAC, lease.IP)

	// 从活跃租约中移除
	delete(ds.leases, key)
	ds.stats.ActiveLeases--
	ds.stats.ExpiredLeases++

	// 记录到历史
	ds.saveLeaseHistory(lease)
}

// 添加地址池管理功能
func (ds *DHCPServer) ValidatePool(pool *AddressPool) error {
	// 验证网络配置
	if pool.Network == nil {
		return fmt.Errorf("network is required")
	}

	// 验证IP范围
	if !pool.Network.Contains(pool.StartIP) {
		return fmt.Errorf("start IP is not in network range")
	}

	if !pool.Network.Contains(pool.EndIP) {
		return fmt.Errorf("end IP is not in network range")
	}

	// 验证IP范围顺序
	if bytes.Compare(pool.StartIP, pool.EndIP) > 0 {
		return fmt.Errorf("start IP must be less than or equal to end IP")
	}

	// 验证网关
	if pool.Gateway != nil && !pool.Network.Contains(pool.Gateway) {
		return fmt.Errorf("gateway is not in network range")
	}

	// 验证DNS服务器
	for _, dns := range pool.DNSServers {
		if dns == nil {
			return fmt.Errorf("invalid DNS server")
		}
	}

	// 验证租约时间
	if pool.LeaseTime <= 0 {
		pool.LeaseTime = ds.config.DefaultLeaseTime
	}

	return nil
}

func (ds *DHCPServer) CalculatePoolUtilization(pool *AddressPool) PoolStats {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	stats := PoolStats{}

	// 计算总地址数
	startInt := ipToInt(pool.StartIP)
	endInt := ipToInt(pool.EndIP)
	stats.TotalAddresses = uint64(endInt - startInt + 1)

	// 减去排除的地址
	stats.TotalAddresses -= uint64(len(pool.ExcludedIPs))

	// 计算已分配地址数
	for _, lease := range ds.leases {
		if lease.Pool == pool.ID && lease.State == "bound" {
			stats.AllocatedAddresses++
		}
	}

	// 计算可用地址数
	stats.AvailableAddresses = stats.TotalAddresses - stats.AllocatedAddresses

	// 计算利用率
	if stats.TotalAddresses > 0 {
		stats.UtilizationRate = float64(stats.AllocatedAddresses) / float64(stats.TotalAddresses)
	}

	return stats
}

// 添加选项配置功能
func (ds *DHCPServer) BuildDHCPOptions(pool *AddressPool, lease *Lease, msgType byte) map[byte][]byte {
	options := make(map[byte][]byte)

	// 消息类型
	options[OptionMessageType] = []byte{msgType}

	// 服务器标识
	serverIP := ds.getServerIP()
	if serverIP != nil {
		options[OptionServerID] = serverIP.To4()
	}

	// 子网掩码
	if pool.Network != nil {
		mask := pool.Network.Mask
		options[OptionSubnetMask] = mask
	}

	// 网关
	if pool.Gateway != nil {
		options[OptionRouter] = pool.Gateway.To4()
	}

	// DNS服务器
	if len(pool.DNSServers) > 0 {
		dnsBytes := make([]byte, 0, len(pool.DNSServers)*4)
		for _, dns := range pool.DNSServers {
			dnsBytes = append(dnsBytes, dns.To4()...)
		}
		options[OptionDNS] = dnsBytes
	}

	// 域名
	if pool.DomainName != "" {
		options[OptionDomainName] = []byte(pool.DomainName)
	}

	// 广播地址
	if pool.Network != nil {
		broadcast := make(net.IP, 4)
		copy(broadcast, pool.Network.IP.To4())
		for i := 0; i < 4; i++ {
			broadcast[i] |= ^pool.Network.Mask[i]
		}
		options[OptionBroadcastAddress] = broadcast
	}

	// 租约时间
	options[OptionLeaseTime] = ds.durationToBytes(pool.LeaseTime)

	// 续约时间 (T1)
	renewTime := pool.LeaseTime / 2
	options[OptionRenewalTime] = ds.durationToBytes(renewTime)

	// 重新绑定时间 (T2)
	rebindTime := pool.LeaseTime * 7 / 8
	options[OptionRebindingTime] = ds.durationToBytes(rebindTime)

	// 合并池特定选项
	for optCode, optValue := range pool.Options {
		options[optCode] = optValue
	}

	// 合并租约特定选项
	if lease != nil {
		for optCode, optValue := range lease.Options {
			options[optCode] = optValue
		}
	}

	return options
}

func (ds *DHCPServer) ParseClientOptions(msg *DHCPMessage) map[string]interface{} {
	clientInfo := make(map[string]interface{})

	// 解析客户端ID
	if clientID, exists := msg.Options[OptionClientID]; exists {
		clientInfo["client_id"] = clientID
	}

	// 解析请求的IP
	if requestedIP, exists := msg.Options[OptionRequestedIP]; exists && len(requestedIP) == 4 {
		clientInfo["requested_ip"] = net.IP(requestedIP)
	}

	// 解析参数请求列表
	if paramList, exists := msg.Options[OptionParameterList]; exists {
		clientInfo["parameter_list"] = paramList
	}

	// 解析主机名
	if hostname, exists := msg.Options[12]; exists { // Option 12 is hostname
		clientInfo["hostname"] = string(hostname)
	}

	// 解析厂商类别标识
	if vendorClass, exists := msg.Options[60]; exists { // Option 60 is vendor class identifier
		clientInfo["vendor_class"] = string(vendorClass)
	}

	return clientInfo
}

// 添加冲突检测功能
func (ds *DHCPServer) DetectIPConflict(ip net.IP) bool {
	// 使用ARP检测
	if ds.arpCheck(ip) {
		return true
	}

	// 使用ping检测
	if ds.config.PingCheck && ds.pingIP(ip) {
		return true
	}

	return false
}

func (ds *DHCPServer) arpCheck(ip net.IP) bool {
	// 发送ARP请求检测IP冲突
	cmd := exec.Command("arping", "-c", "1", "-w", "1", ip.String())
	err := cmd.Run()
	return err == nil // 如果arping成功，说明IP已被使用
}

// 添加负载均衡功能
func (ds *DHCPServer) SelectOptimalPool(clientMAC net.HardwareAddr) *AddressPool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	var bestPool *AddressPool
	var lowestUtilization float64 = 1.0

	for _, pool := range ds.pools {
		if !pool.Enabled {
			continue
		}

		stats := ds.CalculatePoolUtilization(pool)
		if stats.UtilizationRate < lowestUtilization && stats.AvailableAddresses > 0 {
			lowestUtilization = stats.UtilizationRate
			bestPool = pool
		}
	}

	return bestPool
}

// 添加持久化功能（完整实现）
func (ds *DHCPServer) saveLease(lease *Lease) error {
	if ds.config.DatabaseFile == "" {
		return nil // 如果没有配置数据库文件，跳过持久化
	}

	// 使用JSON格式保存租约信息
	leaseData := map[string]interface{}{
		"ip":          lease.IP.String(),
		"mac":         lease.MAC.String(),
		"hostname":    lease.Hostname,
		"client_id":   lease.ClientID,
		"start_time":  lease.StartTime.Unix(),
		"end_time":    lease.EndTime.Unix(),
		"state":       lease.State,
		"pool":        lease.Pool,
		"options":     lease.Options,
		"renew_time":  lease.RenewTime.Unix(),
		"rebind_time": lease.RebindTime.Unix(),
		"last_seen":   lease.LastSeen.Unix(),
	}

	return ds.saveToDatabase("leases", lease.IP.String(), leaseData)
}

func (ds *DHCPServer) saveLeaseHistory(lease *Lease) error {
	if ds.config.DatabaseFile == "" {
		return nil
	}

	// 保存租约历史记录
	historyData := map[string]interface{}{
		"ip":         lease.IP.String(),
		"mac":        lease.MAC.String(),
		"hostname":   lease.Hostname,
		"start_time": lease.StartTime.Unix(),
		"end_time":   lease.EndTime.Unix(),
		"state":      lease.State,
		"pool":       lease.Pool,
		"timestamp":  time.Now().Unix(),
	}

	historyKey := fmt.Sprintf("%s_%d", lease.IP.String(), time.Now().Unix())
	return ds.saveToDatabase("lease_history", historyKey, historyData)
}

func (ds *DHCPServer) loadLeases() error {
	if ds.config.DatabaseFile == "" {
		return nil
	}

	leases, err := ds.loadFromDatabase("leases")
	if err != nil {
		return err
	}

	for key, data := range leases {
		lease, err := ds.parseLeaseData(data)
		if err != nil {
			continue // 跳过无效的租约数据
		}

		// 检查租约是否过期
		if time.Now().After(lease.EndTime) {
			lease.State = "expired"
		}

		ds.leases[key] = lease
	}

	return nil
}

func (ds *DHCPServer) loadReservations() error {
	if ds.config.DatabaseFile == "" {
		return nil
	}

	reservations, err := ds.loadFromDatabase("reservations")
	if err != nil {
		return err
	}

	for key, data := range reservations {
		reservation, err := ds.parseReservationData(data)
		if err != nil {
			continue // 跳过无效的保留数据
		}

		ds.reservations[key] = reservation
	}

	return nil
}

// saveToDatabase 保存数据到数据库文件
func (ds *DHCPServer) saveToDatabase(table, key string, data interface{}) error {
	// 这里使用简单的JSON文件存储，实际生产环境应该使用专业数据库
	dbFile := ds.config.DatabaseFile

	// 读取现有数据
	database := make(map[string]map[string]interface{})
	if fileData, err := os.ReadFile(dbFile); err == nil {
		json.Unmarshal(fileData, &database)
	}

	// 确保表存在
	if database[table] == nil {
		database[table] = make(map[string]interface{})
	}

	// 保存数据
	database[table][key] = data

	// 写回文件
	jsonData, err := json.MarshalIndent(database, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(dbFile, jsonData, 0644)
}

// loadFromDatabase 从数据库文件加载数据
func (ds *DHCPServer) loadFromDatabase(table string) (map[string]interface{}, error) {
	dbFile := ds.config.DatabaseFile

	// 读取数据库文件
	fileData, err := os.ReadFile(dbFile)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]interface{}), nil // 文件不存在，返回空数据
		}
		return nil, err
	}

	// 解析JSON数据
	database := make(map[string]map[string]interface{})
	if err := json.Unmarshal(fileData, &database); err != nil {
		return nil, err
	}

	// 返回指定表的数据
	if database[table] == nil {
		return make(map[string]interface{}), nil
	}

	return database[table], nil
}

// parseLeaseData 解析租约数据
func (ds *DHCPServer) parseLeaseData(data interface{}) (*Lease, error) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("无效的租约数据格式")
	}

	lease := &Lease{}

	// 解析IP地址
	if ipStr, ok := dataMap["ip"].(string); ok {
		lease.IP = net.ParseIP(ipStr)
	}

	// 解析MAC地址
	if macStr, ok := dataMap["mac"].(string); ok {
		if mac, err := net.ParseMAC(macStr); err == nil {
			lease.MAC = mac
		}
	}

	// 解析其他字段
	if hostname, ok := dataMap["hostname"].(string); ok {
		lease.Hostname = hostname
	}

	if state, ok := dataMap["state"].(string); ok {
		lease.State = state
	}

	if pool, ok := dataMap["pool"].(string); ok {
		lease.Pool = pool
	}

	// 解析时间字段
	if startTime, ok := dataMap["start_time"].(float64); ok {
		lease.StartTime = time.Unix(int64(startTime), 0)
	}

	if endTime, ok := dataMap["end_time"].(float64); ok {
		lease.EndTime = time.Unix(int64(endTime), 0)
	}

	if renewTime, ok := dataMap["renew_time"].(float64); ok {
		lease.RenewTime = time.Unix(int64(renewTime), 0)
	}

	if rebindTime, ok := dataMap["rebind_time"].(float64); ok {
		lease.RebindTime = time.Unix(int64(rebindTime), 0)
	}

	if lastSeen, ok := dataMap["last_seen"].(float64); ok {
		lease.LastSeen = time.Unix(int64(lastSeen), 0)
	}

	return lease, nil
}

// parseReservationData 解析保留数据
func (ds *DHCPServer) parseReservationData(data interface{}) (*Reservation, error) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("无效的保留数据格式")
	}

	reservation := &Reservation{}

	// 解析字段
	if id, ok := dataMap["id"].(string); ok {
		reservation.ID = id
	}

	if ipStr, ok := dataMap["ip"].(string); ok {
		reservation.IP = net.ParseIP(ipStr)
	}

	if macStr, ok := dataMap["mac"].(string); ok {
		if mac, err := net.ParseMAC(macStr); err == nil {
			reservation.MAC = mac
		}
	}

	if hostname, ok := dataMap["hostname"].(string); ok {
		reservation.Hostname = hostname
	}

	if pool, ok := dataMap["pool"].(string); ok {
		reservation.Pool = pool
	}

	if enabled, ok := dataMap["enabled"].(bool); ok {
		reservation.Enabled = enabled
	}

	if createdAt, ok := dataMap["created_at"].(float64); ok {
		reservation.CreatedAt = time.Unix(int64(createdAt), 0)
	}

	return reservation, nil
}

// 添加高级查询功能
func (ds *DHCPServer) GetLeasesByPool(poolID string) []*Lease {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	var leases []*Lease
	for _, lease := range ds.leases {
		if lease.Pool == poolID {
			leases = append(leases, lease)
		}
	}

	return leases
}

func (ds *DHCPServer) GetLeasesByMAC(mac net.HardwareAddr) []*Lease {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	var leases []*Lease
	for _, lease := range ds.leases {
		if bytes.Equal(lease.MAC, mac) {
			leases = append(leases, lease)
		}
	}

	return leases
}

func (ds *DHCPServer) GetLeaseByIP(ip net.IP) *Lease {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	for _, lease := range ds.leases {
		if lease.IP.Equal(ip) {
			return lease
		}
	}

	return nil
}

// 添加动态配置更新功能
func (ds *DHCPServer) UpdatePoolConfig(poolID string, updates map[string]interface{}) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	pool, exists := ds.pools[poolID]
	if !exists {
		return fmt.Errorf("pool not found: %s", poolID)
	}

	// 更新配置
	for key, value := range updates {
		switch key {
		case "lease_time":
			if duration, ok := value.(time.Duration); ok {
				pool.LeaseTime = duration
			}
		case "gateway":
			if ip, ok := value.(net.IP); ok {
				pool.Gateway = ip
			}
		case "dns_servers":
			if servers, ok := value.([]net.IP); ok {
				pool.DNSServers = servers
			}
		case "domain_name":
			if domain, ok := value.(string); ok {
				pool.DomainName = domain
			}
		case "enabled":
			if enabled, ok := value.(bool); ok {
				pool.Enabled = enabled
			}
		}
	}

	// 验证更新后的配置
	return ds.ValidatePool(pool)
}

// 添加监控和告警功能
func (ds *DHCPServer) CheckPoolHealth() map[string]string {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	health := make(map[string]string)

	for poolID, pool := range ds.pools {
		if !pool.Enabled {
			health[poolID] = "disabled"
			continue
		}

		stats := ds.CalculatePoolUtilization(pool)

		if stats.UtilizationRate > 0.9 {
			health[poolID] = "critical"
		} else if stats.UtilizationRate > 0.8 {
			health[poolID] = "warning"
		} else {
			health[poolID] = "healthy"
		}
	}

	return health
}

func (ds *DHCPServer) GetDetailedStats() map[string]interface{} {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	stats := make(map[string]interface{})

	// 基本统计
	stats["uptime"] = time.Since(ds.stats.StartTime)
	stats["total_pools"] = len(ds.pools)
	stats["active_leases"] = ds.stats.ActiveLeases
	stats["expired_leases"] = ds.stats.ExpiredLeases

	// 消息统计
	stats["messages_received"] = ds.stats.MessagesReceived
	stats["messages_sent"] = ds.stats.MessagesSent
	stats["discover_received"] = ds.stats.DiscoverReceived
	stats["offers_sent"] = ds.stats.OffersSent
	stats["requests_received"] = ds.stats.RequestsReceived
	stats["acks_sent"] = ds.stats.AcksSent
	stats["naks_sent"] = ds.stats.NaksSent

	// 池统计
	poolStats := make(map[string]PoolStats)
	for poolID, pool := range ds.pools {
		poolStats[poolID] = ds.CalculatePoolUtilization(pool)
	}
	stats["pool_stats"] = poolStats

	// 健康状态
	stats["pool_health"] = ds.CheckPoolHealth()

	return stats
}
