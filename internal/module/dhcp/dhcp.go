package dhcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// RFC 2131 DHCP Message Types
const (
	DISCOVER = 1
	OFFER    = 2
	REQUEST  = 3
	DECLINE  = 4
	ACK      = 5
	NAK      = 6
	RELEASE  = 7
	INFORM   = 8
)

// RFC 2132 DHCP Options
const (
	OptionPad                                        = 0
	OptionSubnetMask                                 = 1
	OptionTimeOffset                                 = 2
	OptionRouter                                     = 3
	OptionTimeServer                                 = 4
	OptionNameServer                                 = 5
	OptionDomainNameServer                           = 6
	OptionLogServer                                  = 7
	OptionCookieServer                               = 8
	OptionLPRServer                                  = 9
	OptionImpressServer                              = 10
	OptionResourceLocation                           = 11
	OptionHostName                                   = 12
	OptionBootFileSize                               = 13
	OptionMeritDumpFile                              = 14
	OptionDomainName                                 = 15
	OptionSwapServer                                 = 16
	OptionRootPath                                   = 17
	OptionExtensionsPath                             = 18
	OptionIPForwarding                               = 19
	OptionNonLocalSourceRouting                      = 20
	OptionPolicyFilter                               = 21
	OptionMaximumDatagramReassemblySize              = 22
	OptionDefaultIPTTL                               = 23
	OptionPathMTUAgingTimeout                        = 24
	OptionPathMTUPlateauTable                        = 25
	OptionInterfaceMTU                               = 26
	OptionAllSubnetsLocal                            = 27
	OptionBroadcastAddress                           = 28
	OptionPerformMaskDiscovery                       = 29
	OptionMaskSupplier                               = 30
	OptionPerformRouterDiscovery                     = 31
	OptionRouterSolicitationAddress                  = 32
	OptionStaticRoute                                = 33
	OptionTrailerEncapsulation                       = 34
	OptionARPCacheTimeout                            = 35
	OptionEthernetEncapsulation                      = 36
	OptionTCPDefaultTTL                              = 37
	OptionTCPKeepaliveInterval                       = 38
	OptionTCPKeepaliveGarbage                        = 39
	OptionNetworkInformationServiceDomain            = 40
	OptionNetworkInformationServers                  = 41
	OptionNetworkTimeProtocolServers                 = 42
	OptionVendorSpecificInformation                  = 43
	OptionNetBIOSOverTCPIPNameServer                 = 44
	OptionNetBIOSOverTCPIPDatagramDistributionServer = 45
	OptionNetBIOSOverTCPIPNodeType                   = 46
	OptionNetBIOSOverTCPIPScope                      = 47
	OptionXWindowSystemFontServer                    = 48
	OptionXWindowSystemDisplayManager                = 49
	OptionRequestedIPAddress                         = 50
	OptionIPAddressLeaseTime                         = 51
	OptionOptionOverload                             = 52
	OptionDHCPMessageType                            = 53
	OptionServerIdentifier                           = 54
	OptionParameterRequestList                       = 55
	OptionMessage                                    = 56
	OptionMaximumDHCPMessageSize                     = 57
	OptionRenewalTimeValue                           = 58
	OptionRebindingTimeValue                         = 59
	OptionVendorClassIdentifier                      = 60
	OptionClientIdentifier                           = 61
	OptionEnd                                        = 255
)

// MagicCookie DHCP Magic Cookie (RFC 2131)
var MagicCookie = []byte{0x63, 0x82, 0x53, 0x63}

// Message represents a DHCP message according to RFC 2131
type Message struct {
	Op      uint8            // Message op code / message type
	Htype   uint8            // Hardware address type
	Hlen    uint8            // Hardware address length
	Hops    uint8            // Client sets to zero, optionally used by relay agents
	Xid     uint32           // Transaction ID
	Secs    uint16           // Filled in by client, seconds elapsed since client began address acquisition
	Flags   uint16           // Flags
	Ciaddr  net.IP           // Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state
	Yiaddr  net.IP           // 'your' (client) IP address
	Siaddr  net.IP           // IP address of next server to use in bootstrap
	Giaddr  net.IP           // Relay agent IP address
	Chaddr  net.HardwareAddr // Client hardware address
	Sname   [64]byte         // Optional server host name
	File    [128]byte        // Boot file name
	Options map[uint8][]byte // Optional parameters field
}

// Server represents a DHCP server
type Server struct {
	mu      sync.RWMutex
	conn    *net.UDPConn
	running bool
	enabled bool

	// Configuration
	serverIP      net.IP
	subnetMask    net.IPMask
	gateway       net.IP
	dnsServers    []net.IP
	domainName    string
	leaseTime     time.Duration
	interfaceName string

	// Address pool
	poolStart net.IP
	poolEnd   net.IP

	// Lease management
	leases       map[string]*Lease
	reservations map[string]net.IP // MAC -> IP reservations
}

// Lease represents a DHCP lease
type Lease struct {
	IP        net.IP
	MAC       net.HardwareAddr
	Hostname  string
	StartTime time.Time
	Duration  time.Duration
	State     string
}

// NewDHCPServer creates a new DHCP server
func NewDHCPServer() *Server {
	return &Server{
		enabled:      true, // Default enabled
		leases:       make(map[string]*Lease),
		reservations: make(map[string]net.IP),
		leaseTime:    24 * time.Hour, // Default 24 hours
	}
}

// Configure sets up the DHCP server configuration
func (s *Server) Configure(serverIP net.IP, subnet *net.IPNet, gateway net.IP, dnsServers []net.IP, domainName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Printf("DEBUG: Configure - ServerIP: %s, Subnet: %s, Gateway: %s\n",
		serverIP.String(), subnet.String(), gateway.String())

	s.serverIP = serverIP
	s.subnetMask = subnet.Mask
	s.gateway = gateway
	s.dnsServers = dnsServers
	s.domainName = domainName

	// Calculate pool range (skip first 10 and last 10 addresses)
	networkIP := subnet.IP.Mask(subnet.Mask)
	broadcast := make(net.IP, 4)
	copy(broadcast, networkIP)
	for i := 0; i < 4; i++ {
		broadcast[i] |= ^subnet.Mask[i]
	}

	fmt.Printf("DEBUG: Network: %s, Broadcast: %s\n", networkIP.String(), broadcast.String())

	// Pool start: network + 10
	poolStartInt := binary.BigEndian.Uint32(networkIP) + 10
	s.poolStart = make(net.IP, 4)
	binary.BigEndian.PutUint32(s.poolStart, poolStartInt)

	// Pool end: broadcast - 10
	poolEndInt := binary.BigEndian.Uint32(broadcast) - 10
	s.poolEnd = make(net.IP, 4)
	binary.BigEndian.PutUint32(s.poolEnd, poolEndInt)

	fmt.Printf("DEBUG: Initial pool - Start: %s, End: %s\n",
		s.poolStart.String(), s.poolEnd.String())

	return nil
}

// Start starts the DHCP server
func (s *Server) Start(listenAddr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("DHCP server is already running")
	}

	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %v", err)
	}

	// 设置广播权限，允许发送广播数据包
	file, err := conn.File()
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("failed to get socket file descriptor: %v", err)
	}
	defer func() {
		_ = file.Close()
	}()

	// 使用syscall设置SO_BROADCAST选项
	err = syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("failed to set SO_BROADCAST: %v", err)
	}

	fmt.Printf("DEBUG: Successfully set SO_BROADCAST option on UDP socket\n")

	s.conn = conn
	s.running = true

	go s.handleRequests()

	return nil
}

// StartWithDefaults starts the DHCP server with default settings
func (s *Server) StartWithDefaults() error {
	return s.Start("0.0.0.0:67")
}

// Stop stops the DHCP server
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	fmt.Println("正在关闭 DHCP 服务器...")
	s.running = false

	if s.conn != nil {
		// 设置读取超时，让阻塞的ReadFromUDP快速返回
		_ = s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_ = s.conn.Close()
	}

	fmt.Println("DHCP 服务器已关闭")
}

// handleRequests handles incoming DHCP requests
func (s *Server) handleRequests() {
	buffer := make([]byte, 1500) // Standard MTU size

	for s.running {
		n, clientAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if s.running {
				fmt.Printf("Error reading UDP packet: %v\n", err)
			}
			// 如果服务器正在关闭，直接退出循环
			if !s.running {
				break
			}
			continue
		}

		fmt.Printf("DEBUG: Received UDP packet from %s, size: %d bytes\n", clientAddr, n)

		// Parse DHCP message
		msg, err := s.parseDHCPMessage(buffer[:n])
		if err != nil {
			fmt.Printf("Error parsing DHCP message from %s: %v\n", clientAddr, err)
			continue
		}

		fmt.Printf("DEBUG: Successfully parsed DHCP message from %s, MAC: %s\n", clientAddr, msg.Chaddr)

		// Handle message based on type
		go s.handleDHCPMessage(msg, clientAddr)
	}
}

// parseDHCPMessage parses a DHCP message from raw bytes
func (s *Server) parseDHCPMessage(data []byte) (*Message, error) {
	if len(data) < 240 {
		return nil, fmt.Errorf("DHCP message too short: %d bytes", len(data))
	}

	msg := &Message{
		Options: make(map[uint8][]byte),
	}

	// Parse fixed fields
	msg.Op = data[0]
	msg.Htype = data[1]
	msg.Hlen = data[2]
	msg.Hops = data[3]
	msg.Xid = binary.BigEndian.Uint32(data[4:8])
	msg.Secs = binary.BigEndian.Uint16(data[8:10])
	msg.Flags = binary.BigEndian.Uint16(data[10:12])

	msg.Ciaddr = make(net.IP, 4)
	copy(msg.Ciaddr, data[12:16])

	msg.Yiaddr = make(net.IP, 4)
	copy(msg.Yiaddr, data[16:20])

	msg.Siaddr = make(net.IP, 4)
	copy(msg.Siaddr, data[20:24])

	msg.Giaddr = make(net.IP, 4)
	copy(msg.Giaddr, data[24:28])

	// Parse hardware address
	if msg.Hlen > 0 && msg.Hlen <= 16 {
		msg.Chaddr = make(net.HardwareAddr, msg.Hlen)
		copy(msg.Chaddr, data[28:28+msg.Hlen])
	}

	copy(msg.Sname[:], data[44:108])
	copy(msg.File[:], data[108:236])

	// Parse options (magic cookie starts at byte 236)
	if len(data) > 236 {
		err := s.parseOptions(data[236:], msg.Options)
		if err != nil {
			return nil, fmt.Errorf("error parsing options: %v", err)
		}
	}

	return msg, nil
}

// parseOptions parses DHCP options
func (s *Server) parseOptions(data []byte, options map[uint8][]byte) error {
	// Check magic cookie
	if len(data) < 4 || !bytes.Equal(data[:4], MagicCookie) {
		return fmt.Errorf("invalid magic cookie")
	}

	data = data[4:] // Skip magic cookie

	for len(data) > 0 {
		if data[0] == OptionPad {
			data = data[1:]
			continue
		}

		if data[0] == OptionEnd {
			break
		}

		if len(data) < 2 {
			return fmt.Errorf("incomplete option")
		}

		optionType := data[0]
		optionLen := data[1]

		if len(data) < int(2+optionLen) {
			return fmt.Errorf("option data too short")
		}

		optionData := make([]byte, optionLen)
		copy(optionData, data[2:2+optionLen])
		options[optionType] = optionData

		data = data[2+optionLen:]
	}

	return nil
}

// handleDHCPMessage handles a parsed DHCP message
func (s *Server) handleDHCPMessage(msg *Message, clientAddr *net.UDPAddr) {
	// Get message type
	msgTypeData, exists := msg.Options[OptionDHCPMessageType]
	if !exists || len(msgTypeData) != 1 {
		fmt.Printf("Invalid or missing DHCP message type\n")
		return
	}

	msgType := msgTypeData[0]

	// Debug: Print message type details
	msgTypeName := "UNKNOWN"
	switch msgType {
	case DISCOVER:
		msgTypeName = "DISCOVER"
	case OFFER:
		msgTypeName = "OFFER"
	case REQUEST:
		msgTypeName = "REQUEST"
	case DECLINE:
		msgTypeName = "DECLINE"
	case ACK:
		msgTypeName = "ACK"
	case NAK:
		msgTypeName = "NAK"
	case RELEASE:
		msgTypeName = "RELEASE"
	case INFORM:
		msgTypeName = "INFORM"
	}
	fmt.Printf("DEBUG: Received DHCP %s (type %d) from %s (MAC: %s, XID: 0x%x)\n",
		msgTypeName, msgType, clientAddr, msg.Chaddr, msg.Xid)

	switch msgType {
	case DISCOVER:
		s.handleDiscover(msg, clientAddr)
	case REQUEST:
		s.handleRequest(msg, clientAddr)
	case RELEASE:
		s.handleRelease(msg, clientAddr)
	case INFORM:
		s.handleInform(msg, clientAddr)
	default:
		fmt.Printf("Unsupported DHCP message type: %d\n", msgType)
	}
}

// handleDiscover handles DHCP DISCOVER messages
func (s *Server) handleDiscover(msg *Message, clientAddr *net.UDPAddr) {
	fmt.Printf("Handling DHCP DISCOVER from %s (MAC: %s)\n", clientAddr, msg.Chaddr)
	fmt.Printf("DISCOVER Flags: 0x%04x (Broadcast: %t)\n", msg.Flags, msg.Flags&0x8000 != 0)

	// Find or allocate IP address
	ip := s.findOrAllocateIP(msg.Chaddr)
	if ip == nil {
		fmt.Printf("No available IP addresses for %s\n", msg.Chaddr)
		return
	}

	// Create OFFER message
	offer := s.createOffer(msg, ip)

	// Send OFFER
	_ = s.sendDHCPMessage(offer, clientAddr)

	fmt.Printf("Sent DHCP OFFER: %s to %s (MAC: %s), Flags: 0x%04x\n", ip, clientAddr, msg.Chaddr, offer.Flags)
}

// handleRequest handles DHCP REQUEST messages
func (s *Server) handleRequest(msg *Message, clientAddr *net.UDPAddr) {
	fmt.Printf("Handling DHCP REQUEST from %s (MAC: %s)\n", clientAddr, msg.Chaddr)

	// Check if this is for us
	serverID, hasServerID := msg.Options[OptionServerIdentifier]
	if hasServerID {
		if !bytes.Equal(serverID, s.serverIP.To4()) {
			fmt.Printf("REQUEST not for us (server ID: %v, our ID: %v)\n", serverID, s.serverIP.To4())
			return
		}
		fmt.Printf("REQUEST is for us (server ID matches)\n")
	} else {
		fmt.Printf("REQUEST has no server ID, processing anyway\n")
	}

	// Get requested IP
	var requestedIP net.IP
	if reqIPData, exists := msg.Options[OptionRequestedIPAddress]; exists && len(reqIPData) == 4 {
		requestedIP = net.IP(reqIPData)
		fmt.Printf("Requested IP from option 50: %s\n", requestedIP)
	} else if !msg.Ciaddr.IsUnspecified() {
		requestedIP = msg.Ciaddr
		fmt.Printf("Requested IP from Ciaddr: %s\n", requestedIP)
	}

	if requestedIP == nil || requestedIP.IsUnspecified() {
		fmt.Printf("No valid requested IP address found\n")
		s.sendNAK(msg, clientAddr, "No requested IP address")
		return
	}

	fmt.Printf("Validating request for IP %s from MAC %s\n", requestedIP, msg.Chaddr)

	// Validate and create lease
	if s.validateRequest(msg.Chaddr, requestedIP) {
		fmt.Printf("Request validation successful, creating lease\n")
		lease := s.createLease(msg.Chaddr, requestedIP, msg)
		ack := s.createACK(msg, lease)
		err := s.sendDHCPMessage(ack, clientAddr)
		if err != nil {
			fmt.Printf("Failed to send DHCP ACK: %v\n", err)
		} else {
			fmt.Printf("Sent DHCP ACK: %s to %s (MAC: %s)\n", requestedIP, clientAddr, msg.Chaddr)
		}
	} else {
		fmt.Printf("Request validation failed for IP %s\n", requestedIP)
		s.sendNAK(msg, clientAddr, "Invalid IP request")
	}
}

// handleRelease handles DHCP RELEASE messages
func (s *Server) handleRelease(msg *Message, clientAddr *net.UDPAddr) {
	fmt.Printf("Handling DHCP RELEASE from %s (MAC: %s)\n", clientAddr, msg.Chaddr)

	s.mu.Lock()
	defer s.mu.Unlock()

	leaseKey := msg.Chaddr.String()
	if lease, exists := s.leases[leaseKey]; exists {
		fmt.Printf("Released lease: %s for MAC: %s\n", lease.IP, msg.Chaddr)
		delete(s.leases, leaseKey)
	}
}

// handleInform handles DHCP INFORM messages
func (s *Server) handleInform(msg *Message, clientAddr *net.UDPAddr) {
	fmt.Printf("Handling DHCP INFORM from %s (MAC: %s)\n", clientAddr, msg.Chaddr)

	// Create ACK with configuration options only (no IP allocation)
	ack := s.createInformACK(msg)
	_ = s.sendDHCPMessage(ack, clientAddr)

	fmt.Printf("Sent DHCP ACK (INFORM) to %s (MAC: %s)\n", clientAddr, msg.Chaddr)
}

// findOrAllocateIP finds an existing lease or allocates a new IP for the MAC address
func (s *Server) findOrAllocateIP(mac net.HardwareAddr) net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()

	macStr := mac.String()

	// Check for existing lease
	if lease, exists := s.leases[macStr]; exists {
		return lease.IP
	}

	// Check for reservation
	if reservedIP, exists := s.reservations[macStr]; exists {
		return reservedIP
	}

	// Allocate new IP from pool
	return s.allocateFromPool()
}

// allocateFromPool allocates an IP from the available pool
func (s *Server) allocateFromPool() net.IP {
	// Debug: Check if pool is configured
	if s.poolStart == nil || s.poolEnd == nil {
		fmt.Printf("DEBUG: Pool not configured - poolStart: %v, poolEnd: %v\n", s.poolStart, s.poolEnd)
		return nil
	}

	// Ensure we have IPv4 addresses (4 bytes)
	startIP := s.poolStart.To4()
	endIP := s.poolEnd.To4()

	if startIP == nil || endIP == nil {
		fmt.Printf("DEBUG: Invalid IPv4 addresses - poolStart: %v, poolEnd: %v\n", s.poolStart, s.poolEnd)
		return nil
	}

	startInt := binary.BigEndian.Uint32(startIP)
	endInt := binary.BigEndian.Uint32(endIP)

	fmt.Printf("DEBUG: Pool range - Start: %s (%d), End: %s (%d)\n",
		startIP.String(), startInt, endIP.String(), endInt)

	// Find first available IP
	for i := startInt; i <= endInt; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)

		// Check if IP is already leased
		if !s.isIPLeased(ip) {
			fmt.Printf("DEBUG: Allocated IP: %s\n", ip.String())
			return ip
		}
	}

	fmt.Printf("DEBUG: No available IPs in pool\n")
	return nil // No available IPs
}

// isIPLeased checks if an IP is already leased
func (s *Server) isIPLeased(ip net.IP) bool {
	for _, lease := range s.leases {
		if lease.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// validateRequest validates a DHCP REQUEST
func (s *Server) validateRequest(mac net.HardwareAddr, requestedIP net.IP) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if IP is in our pool range
	if !s.isIPInPool(requestedIP) {
		return false
	}

	// Check if IP is available or already leased to this MAC
	macStr := mac.String()
	if lease, exists := s.leases[macStr]; exists {
		return lease.IP.Equal(requestedIP)
	}

	// Check if IP is leased to someone else
	return !s.isIPLeased(requestedIP)
}

// isIPInPool checks if an IP is within the configured pool range
func (s *Server) isIPInPool(ip net.IP) bool {
	// Ensure we have IPv4 addresses
	ipv4 := ip.To4()
	startIPv4 := s.poolStart.To4()
	endIPv4 := s.poolEnd.To4()

	if ipv4 == nil || startIPv4 == nil || endIPv4 == nil {
		fmt.Printf("isIPInPool: Invalid IPv4 address - ip: %v, start: %v, end: %v\n", ip, s.poolStart, s.poolEnd)
		return false
	}

	ipInt := binary.BigEndian.Uint32(ipv4)
	startInt := binary.BigEndian.Uint32(startIPv4)
	endInt := binary.BigEndian.Uint32(endIPv4)

	fmt.Printf("isIPInPool: Checking IP %s (%d) in range %s (%d) - %s (%d)\n",
		ip, ipInt, s.poolStart, startInt, s.poolEnd, endInt)

	return ipInt >= startInt && ipInt <= endInt
}

// createLease creates a new lease
func (s *Server) createLease(mac net.HardwareAddr, ip net.IP, msg *Message) *Lease {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 从DHCP消息中提取主机名
	hostname := ""
	if hostnameData, exists := msg.Options[OptionHostName]; exists && len(hostnameData) > 0 {
		hostname = string(hostnameData)
	}

	lease := &Lease{
		IP:        ip,
		MAC:       mac,
		Hostname:  hostname,
		StartTime: time.Now(),
		Duration:  s.leaseTime,
		State:     "BOUND",
	}

	s.leases[mac.String()] = lease
	return lease
}

// createOffer creates a DHCP OFFER message
func (s *Server) createOffer(request *Message, ip net.IP) *Message {
	offer := &Message{
		Op:      2, // BOOTREPLY
		Htype:   request.Htype,
		Hlen:    request.Hlen,
		Hops:    0,
		Xid:     request.Xid,
		Secs:    0,
		Flags:   request.Flags,
		Ciaddr:  net.IPv4zero,
		Yiaddr:  ip,
		Siaddr:  s.serverIP,
		Giaddr:  request.Giaddr,
		Chaddr:  request.Chaddr,
		Options: make(map[uint8][]byte),
	}

	// Add required options in RFC-compliant order
	s.addStandardOptions(offer, OFFER)

	return offer
}

// createACK creates a DHCP ACK message
func (s *Server) createACK(request *Message, lease *Lease) *Message {
	ack := &Message{
		Op:      2, // BOOTREPLY
		Htype:   request.Htype,
		Hlen:    request.Hlen,
		Hops:    0,
		Xid:     request.Xid,
		Secs:    0,
		Flags:   request.Flags,
		Ciaddr:  request.Ciaddr,
		Yiaddr:  lease.IP,
		Siaddr:  s.serverIP,
		Giaddr:  request.Giaddr,
		Chaddr:  request.Chaddr,
		Options: make(map[uint8][]byte),
	}

	// Add required options in RFC-compliant order
	s.addStandardOptions(ack, ACK)

	return ack
}

// createInformACK creates a DHCP ACK for INFORM message
func (s *Server) createInformACK(request *Message) *Message {
	ack := &Message{
		Op:      2, // BOOTREPLY
		Htype:   request.Htype,
		Hlen:    request.Hlen,
		Hops:    0,
		Xid:     request.Xid,
		Secs:    0,
		Flags:   request.Flags,
		Ciaddr:  request.Ciaddr,
		Yiaddr:  net.IPv4zero, // No IP allocation for INFORM
		Siaddr:  s.serverIP,
		Giaddr:  request.Giaddr,
		Chaddr:  request.Chaddr,
		Options: make(map[uint8][]byte),
	}

	// Add configuration options only (no lease time)
	s.addConfigurationOptions(ack, ACK)

	return ack
}

// addStandardOptions adds standard DHCP options in RFC-compliant order
func (s *Server) addStandardOptions(msg *Message, msgType uint8) {
	// Message Type (MUST be first option)
	msg.Options[OptionDHCPMessageType] = []byte{msgType}

	// Server Identifier (MUST be included in OFFER and ACK)
	msg.Options[OptionServerIdentifier] = s.serverIP.To4()

	// Lease Time (for OFFER and ACK)
	if msgType == OFFER || msgType == ACK {
		leaseTimeBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(leaseTimeBytes, uint32(s.leaseTime.Seconds()))
		msg.Options[OptionIPAddressLeaseTime] = leaseTimeBytes

		// Renewal Time (T1) - 50% of lease time
		renewalTime := uint32(s.leaseTime.Seconds() * 0.5)
		renewalTimeBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(renewalTimeBytes, renewalTime)
		msg.Options[OptionRenewalTimeValue] = renewalTimeBytes

		// Rebinding Time (T2) - 87.5% of lease time
		rebindingTime := uint32(s.leaseTime.Seconds() * 0.875)
		rebindingTimeBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(rebindingTimeBytes, rebindingTime)
		msg.Options[OptionRebindingTimeValue] = rebindingTimeBytes
	}

	// Add configuration options
	s.addConfigurationOptions(msg, msgType)
}

// addConfigurationOptions adds network configuration options
func (s *Server) addConfigurationOptions(msg *Message, msgType uint8) {
	// Subnet Mask - ensure it's in proper 4-byte format
	if len(s.subnetMask) == 4 {
		msg.Options[OptionSubnetMask] = []byte(s.subnetMask)
	} else {
		// Convert to IPv4 mask if needed - handle IPMask properly
		if len(s.subnetMask) == 16 {
			// IPv6 mask, extract IPv4 part
			msg.Options[OptionSubnetMask] = []byte(s.subnetMask[12:16])
		} else {
			// Fallback to default /24 mask
			msg.Options[OptionSubnetMask] = []byte{255, 255, 255, 0}
		}
	}
	fmt.Printf("DEBUG: Added Subnet Mask: %v (bytes: %v)\n", net.IP(s.subnetMask), msg.Options[OptionSubnetMask])

	// Router (Gateway)
	if s.gateway != nil {
		msg.Options[OptionRouter] = s.gateway.To4()
		fmt.Printf("DEBUG: Added Gateway: %v\n", s.gateway)
	}

	// DNS Servers
	if len(s.dnsServers) > 0 {
		dnsBytes := make([]byte, 0, len(s.dnsServers)*4)
		for _, dns := range s.dnsServers {
			dnsBytes = append(dnsBytes, dns.To4()...)
		}
		msg.Options[OptionDomainNameServer] = dnsBytes
		fmt.Printf("DEBUG: Added DNS Servers: %v\n", s.dnsServers)
	}

	// Domain Name
	if s.domainName != "" {
		msg.Options[OptionDomainName] = []byte(s.domainName)
		fmt.Printf("DEBUG: Added Domain Name: %s\n", s.domainName)
	}

	// Broadcast Address
	if len(s.subnetMask) == 4 {
		// Calculate broadcast address
		networkIP := s.serverIP.Mask(s.subnetMask)
		broadcast := make(net.IP, 4)
		copy(broadcast, networkIP)
		for i := 0; i < 4; i++ {
			broadcast[i] |= ^s.subnetMask[i]
		}
		msg.Options[OptionBroadcastAddress] = broadcast.To4()
		fmt.Printf("DEBUG: Added Broadcast Address: %v\n", broadcast)
	}

	// Debug: Print all options being added
	fmt.Printf("DEBUG: Total options in message: %d\n", len(msg.Options))
	for optCode, optValue := range msg.Options {
		fmt.Printf("DEBUG: Option %d: %v\n", optCode, optValue)
	}
}

// sendNAK sends a DHCP NAK message
func (s *Server) sendNAK(request *Message, clientAddr *net.UDPAddr, reason string) {
	nak := &Message{
		Op:      2, // BOOTREPLY
		Htype:   request.Htype,
		Hlen:    request.Hlen,
		Hops:    0,
		Xid:     request.Xid,
		Secs:    0,
		Flags:   request.Flags,
		Ciaddr:  net.IPv4zero,
		Yiaddr:  net.IPv4zero,
		Siaddr:  s.serverIP,
		Giaddr:  request.Giaddr,
		Chaddr:  request.Chaddr,
		Options: make(map[uint8][]byte),
	}

	// Add NAK options
	nak.Options[OptionDHCPMessageType] = []byte{NAK}
	nak.Options[OptionServerIdentifier] = s.serverIP.To4()
	if reason != "" {
		nak.Options[OptionMessage] = []byte(reason)
	}

	_ = s.sendDHCPMessage(nak, clientAddr)

	fmt.Printf("Sent DHCP NAK to %s (MAC: %s): %s\n", clientAddr, request.Chaddr, reason)
}

// sendDHCPMessage sends a DHCP message to the client
func (s *Server) sendDHCPMessage(msg *Message, clientAddr *net.UDPAddr) error {
	data, err := s.serializeDHCPMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to serialize DHCP message: %v", err)
	}

	// Debug: Print message details
	msgType := "UNKNOWN"
	if msgTypeBytes, exists := msg.Options[OptionDHCPMessageType]; exists && len(msgTypeBytes) > 0 {
		switch msgTypeBytes[0] {
		case OFFER:
			msgType = "OFFER"
		case ACK:
			msgType = "ACK"
		case NAK:
			msgType = "NAK"
		}
	}

	fmt.Printf("DEBUG: Preparing to send DHCP %s message:\n", msgType)
	fmt.Printf("  - Yiaddr (Your IP): %s\n", msg.Yiaddr)
	fmt.Printf("  - Siaddr (Server IP): %s\n", msg.Siaddr)
	fmt.Printf("  - Message size: %d bytes\n", len(data))

	// Print key options
	if subnet, exists := msg.Options[OptionSubnetMask]; exists {
		fmt.Printf("  - Subnet Mask: %s\n", net.IP(subnet))
	}
	if gateway, exists := msg.Options[OptionRouter]; exists {
		fmt.Printf("  - Gateway: %s\n", net.IP(gateway))
	}
	if dns, exists := msg.Options[OptionDomainNameServer]; exists && len(dns) >= 4 {
		fmt.Printf("  - DNS Server: %s\n", net.IP(dns[:4]))
	}
	if serverID, exists := msg.Options[OptionServerIdentifier]; exists {
		fmt.Printf("  - Server ID: %s\n", net.IP(serverID))
	}

	// Determine destination address
	var destAddr *net.UDPAddr

	// Check if broadcast flag is set or client IP is 0.0.0.0
	if msg.Flags&0x8000 != 0 || clientAddr.IP.IsUnspecified() || msg.Ciaddr.IsUnspecified() {
		// Calculate network broadcast address
		var broadcastIP net.IP
		if s.subnetMask != nil && s.serverIP != nil {
			// Calculate broadcast address for the network
			// Use server IP instead of gateway for network calculation
			network := s.serverIP.Mask(s.subnetMask)
			broadcast := make(net.IP, 4)
			copy(broadcast, network.To4())

			// Apply inverse mask to get broadcast address
			mask := s.subnetMask
			if len(mask) == 16 {
				mask = mask[12:16] // Get IPv4 part of IPv6 mask
			}
			for i := 0; i < 4; i++ {
				broadcast[i] |= ^mask[i]
			}
			broadcastIP = broadcast
			fmt.Printf("DEBUG: Calculated network broadcast address: %s (network: %s, mask: %s)\n",
				broadcastIP, network, net.IP(mask))
		} else {
			// Fallback to global broadcast
			broadcastIP = net.IPv4bcast
			fmt.Printf("DEBUG: Using global broadcast address: %s\n", broadcastIP)
		}

		destAddr = &net.UDPAddr{
			IP:   broadcastIP,
			Port: 68, // DHCP client port
		}
		fmt.Printf("DEBUG: Sending DHCP message via broadcast to %s (Flags: 0x%04x)\n", destAddr, msg.Flags)
	} else {
		// Unicast to client
		destAddr = &net.UDPAddr{
			IP:   msg.Yiaddr,
			Port: 68,
		}
		fmt.Printf("DEBUG: Sending DHCP message via unicast to %s\n", destAddr)
	}

	_, err = s.conn.WriteToUDP(data, destAddr)
	if err != nil {
		fmt.Printf("ERROR: Failed to send DHCP message to %s: %v\n", destAddr, err)
		return fmt.Errorf("failed to send DHCP message: %v", err)
	}

	fmt.Printf("DEBUG: Successfully sent %d bytes to %s\n", len(data), destAddr)
	return nil
}

// serializeDHCPMessage serializes a DHCP message to bytes
func (s *Server) serializeDHCPMessage(msg *Message) ([]byte, error) {
	buf := make([]byte, 236) // Fixed header size (RFC 2131 standard)

	// Fixed fields
	buf[0] = msg.Op
	buf[1] = msg.Htype
	buf[2] = msg.Hlen
	buf[3] = msg.Hops
	binary.BigEndian.PutUint32(buf[4:8], msg.Xid)
	binary.BigEndian.PutUint16(buf[8:10], msg.Secs)
	binary.BigEndian.PutUint16(buf[10:12], msg.Flags)

	copy(buf[12:16], msg.Ciaddr.To4())
	copy(buf[16:20], msg.Yiaddr.To4())
	copy(buf[20:24], msg.Siaddr.To4())
	copy(buf[24:28], msg.Giaddr.To4())

	// Hardware address
	if len(msg.Chaddr) > 0 {
		copy(buf[28:28+len(msg.Chaddr)], msg.Chaddr)
	}

	copy(buf[44:108], msg.Sname[:])
	copy(buf[108:236], msg.File[:])

	// Add magic cookie
	buf = append(buf, MagicCookie...)

	// Add options in RFC-compliant order (serializeOptions already adds OptionEnd)
	buf = s.serializeOptions(buf, msg.Options)

	return buf, nil
}

// serializeOptions serializes DHCP options in RFC-compliant order
func (s *Server) serializeOptions(buf []byte, options map[uint8][]byte) []byte {
	// Define option order according to RFC 2132 and common practice
	optionOrder := []uint8{
		OptionDHCPMessageType,    // 53 - MUST be first
		OptionServerIdentifier,   // 54 - MUST be in OFFER/ACK
		OptionIPAddressLeaseTime, // 51 - Lease time
		OptionSubnetMask,         // 1  - Subnet mask
		OptionBroadcastAddress,   // 28 - Broadcast address
		OptionRouter,             // 3  - Default gateway
		OptionDomainNameServer,   // 6  - DNS servers
		OptionDomainName,         // 15 - Domain name
		OptionRenewalTimeValue,   // 58 - T1
		OptionRebindingTimeValue, // 59 - T2
		OptionMessage,            // 56 - Error message (for NAK)
	}

	// Add options in the specified order
	for _, optionType := range optionOrder {
		if data, exists := options[optionType]; exists {
			buf = append(buf, optionType)
			buf = append(buf, byte(len(data)))
			buf = append(buf, data...)
		}
	}

	// Add any remaining options not in the standard order
	for optionType, data := range options {
		// Skip if already added
		found := false
		for _, standardOption := range optionOrder {
			if optionType == standardOption {
				found = true
				break
			}
		}
		if !found {
			buf = append(buf, optionType)
			buf = append(buf, byte(len(data)))
			buf = append(buf, data...)
		}
	}

	// Add the End option (255) - required by DHCP protocol
	buf = append(buf, OptionEnd)

	return buf
}

// GetLeases returns all current DHCP leases
func (s *Server) GetLeases() map[string]*Lease {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a copy to avoid race conditions
	leases := make(map[string]*Lease)
	for k, v := range s.leases {
		leases[k] = v
	}
	return leases
}

// GetPools returns the DHCP pool configuration
func (s *Server) GetPools() []Pool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Calculate network
	network := &net.IPNet{
		IP:   s.serverIP.Mask(s.subnetMask),
		Mask: s.subnetMask,
	}

	pools := []Pool{
		{
			Name:       "default",
			StartIP:    s.poolStart,
			EndIP:      s.poolEnd,
			Network:    network,
			Gateway:    s.gateway,
			DNSServers: s.dnsServers,
			DomainName: s.domainName,
			LeaseTime:  s.leaseTime,
		},
	}
	return pools
}

// Pool represents a DHCP address pool
type Pool struct {
	Name       string        `json:"name"`
	StartIP    net.IP        `json:"start_ip"`
	EndIP      net.IP        `json:"end_ip"`
	Network    *net.IPNet    `json:"network"`
	Gateway    net.IP        `json:"gateway"`
	DNSServers []net.IP      `json:"dns_servers"`
	DomainName string        `json:"domain_name"`
	LeaseTime  time.Duration `json:"lease_time"`
}

// GetConfig returns the DHCP server configuration
func (s *Server) GetConfig() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return &Config{
		Enabled:          s.enabled,
		ServerIP:         s.serverIP,
		PoolStart:        s.poolStart,
		PoolEnd:          s.poolEnd,
		SubnetMask:       s.subnetMask,
		Gateway:          s.gateway,
		DNSServers:       s.dnsServers,
		DomainName:       s.domainName,
		LeaseTime:        s.leaseTime,
		Interface:        s.interfaceName,
		ListenAddress:    "0.0.0.0",
		DefaultLeaseTime: s.leaseTime,
	}
}

// Config represents the DHCP server configuration
type Config struct {
	Enabled          bool          `json:"enabled"`
	ServerIP         net.IP        `json:"server_ip"`
	PoolStart        net.IP        `json:"pool_start"`
	PoolEnd          net.IP        `json:"pool_end"`
	SubnetMask       net.IPMask    `json:"subnet_mask"`
	Gateway          net.IP        `json:"gateway"`
	DNSServers       []net.IP      `json:"dns_servers"`
	DomainName       string        `json:"domain_name"`
	LeaseTime        time.Duration `json:"lease_time"`
	Interface        string        `json:"interface"`
	ListenAddress    string        `json:"listen_address"`
	DefaultLeaseTime time.Duration `json:"default_lease_time"`
}

// AddressPool represents a DHCP address pool (for backward compatibility)
type AddressPool struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Network     *net.IPNet      `json:"network"`
	StartIP     net.IP          `json:"start_ip"`
	EndIP       net.IP          `json:"end_ip"`
	Gateway     net.IP          `json:"gateway"`
	DNSServers  []net.IP        `json:"dns_servers"`
	DomainName  string          `json:"domain_name"`
	LeaseTime   time.Duration   `json:"lease_time"`
	Enabled     bool            `json:"enabled"`
	Options     map[byte][]byte `json:"options"`
	ExcludedIPs []net.IP        `json:"excluded_ips"`
	CreatedAt   time.Time       `json:"created_at"`
}

// SetConfig sets the DHCP server configuration
func (s *Server) SetConfig(config *Config) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.enabled = config.Enabled
	s.serverIP = config.ServerIP
	s.poolStart = config.PoolStart
	s.poolEnd = config.PoolEnd
	s.subnetMask = config.SubnetMask
	s.gateway = config.Gateway
	s.dnsServers = config.DNSServers
	s.domainName = config.DomainName
	s.leaseTime = config.LeaseTime
	s.interfaceName = config.Interface

	// Handle new fields
	if config.DefaultLeaseTime > 0 {
		s.leaseTime = config.DefaultLeaseTime
	}
}

// AddPool adds an address pool to the DHCP server
func (s *Server) AddPool(pool *AddressPool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Printf("DEBUG: AddPool - Network: %s, StartIP: %s, EndIP: %s\n",
		pool.Network.String(), pool.StartIP.String(), pool.EndIP.String())
	fmt.Printf("DEBUG: AddPool - Gateway: %s, DNS: %v\n",
		pool.Gateway.String(), pool.DNSServers)

	// Configure server with pool settings
	s.poolStart = pool.StartIP
	s.poolEnd = pool.EndIP
	s.gateway = pool.Gateway
	s.dnsServers = pool.DNSServers
	s.domainName = pool.DomainName
	s.leaseTime = pool.LeaseTime

	fmt.Printf("DEBUG: Set poolStart: %s, poolEnd: %s\n",
		s.poolStart.String(), s.poolEnd.String())

	if pool.Network != nil {
		s.subnetMask = pool.Network.Mask
		fmt.Printf("DEBUG: Set subnet mask: %s\n", net.IP(s.subnetMask).String())

		// Set server IP to gateway if not already set
		if s.serverIP == nil && pool.Gateway != nil {
			s.serverIP = pool.Gateway
			fmt.Printf("DEBUG: Set server IP to gateway: %s\n", s.serverIP.String())
		}
	}

	// Print final configuration
	fmt.Printf("DEBUG: Final DHCP config - ServerIP: %s, Gateway: %s, SubnetMask: %s\n",
		s.serverIP.String(), s.gateway.String(), net.IP(s.subnetMask).String())

	return nil
}

// ConfigExtended Update Config to include missing fields
type ConfigExtended struct {
	*Config
	Interface        string        `json:"interface"`
	ListenAddress    string        `json:"listen_address"`
	DefaultLeaseTime time.Duration `json:"default_lease_time"`
}

// GetConfigExtended returns the extended DHCP server configuration
func (s *Server) GetConfigExtended() *ConfigExtended {
	config := s.GetConfig()
	return &ConfigExtended{
		Config:           config,
		Interface:        "eth0", // Default interface
		ListenAddress:    "0.0.0.0",
		DefaultLeaseTime: s.leaseTime,
	}
}
