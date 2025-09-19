// Package protocols 实现IS-IS协议
// IS-IS (Intermediate System to Intermediate System) 是一个链路状态路由协议
// 遵循 ISO/IEC 10589 标准
package protocols

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"router-os/internal/logging"
	"router-os/internal/routing"
)

// IS-IS协议常量
const (
	// 协议标识符
	ISISProtocolID = 0x83

	// PDU类型
	ISISHelloPDUType = 15 // Hello PDU
	ISISLSPType      = 18 // LSP PDU
	ISISCSNPType     = 24 // Complete Sequence Number PDU
	ISISPSNPType     = 26 // Partial Sequence Number PDU

	// 级别
	ISISLevel1 = 1
	ISISLevel2 = 2

	// 定时器 (秒)
	ISISHelloInterval  = 10
	ISISHoldTime       = 30
	ISISLSPLifetime    = 1200
	ISISLSPRefreshTime = 900
	ISISCSNPInterval   = 10

	// 度量值
	ISISMaxMetric     = 63
	ISISDefaultMetric = 10

	// 系统ID长度
	ISISSystemIDLen = 6

	// 电路ID长度
	ISISCircuitIDLen = 1

	// LSP ID长度
	ISISLSPIDLen = ISISSystemIDLen + 2
)

// TLV类型
const (
	TLVAreaAddresses      = 1   // 区域地址
	TLVISNeighbors        = 2   // IS邻居
	TLVESNeighbors        = 3   // ES邻居
	TLVPartitionDIS       = 4   // 分区DIS
	TLVPrefixNeighbors    = 5   // 前缀邻居
	TLVISReachability     = 22  // IS可达性
	TLVIPReachability     = 128 // IP可达性
	TLVProtocolsSupported = 129 // 支持的协议
	TLVIPInterfaceAddress = 132 // IP接口地址
	TLVHostname           = 137 // 主机名
)

// IS-IS PDU头部
type ISISHeader struct {
	NLPID       uint8 // 网络层协议标识符
	HeaderLen   uint8 // 头部长度
	Version     uint8 // 版本
	IDLen       uint8 // 系统ID长度
	PDUType     uint8 // PDU类型
	Version2    uint8 // 版本2
	Reserved    uint8 // 保留
	MaxAreaAddr uint8 // 最大区域地址数
}

// Hello PDU
type ISISHelloPDU struct {
	Header      ISISHeader
	CircuitType uint8     // 电路类型
	SourceID    []byte    // 源系统ID
	HoldTime    uint16    // 保持时间
	PDULength   uint16    // PDU长度
	Priority    uint8     // 优先级
	LANID       []byte    // LAN ID
	TLVs        []ISISTLV // TLV列表
}

// LSP PDU
type ISISLSP struct {
	Header        ISISHeader
	PDULength     uint16    // PDU长度
	RemainingLife uint16    // 剩余生存时间
	LSPID         []byte    // LSP ID
	SequenceNum   uint32    // 序列号
	Checksum      uint16    // 校验和
	Flags         uint8     // 标志
	TLVs          []ISISTLV // TLV列表
}

// TLV结构
type ISISTLV struct {
	Type   uint8  // TLV类型
	Length uint8  // TLV长度
	Value  []byte // TLV值
}

// IS可达性TLV
type ISReachability struct {
	DefaultMetric uint8  // 默认度量值
	DelayMetric   uint8  // 延迟度量值
	ExpenseMetric uint8  // 费用度量值
	ErrorMetric   uint8  // 错误度量值
	NeighborID    []byte // 邻居ID
}

// IP可达性TLV
type IPReachability struct {
	DefaultMetric uint8      // 默认度量值
	DelayMetric   uint8      // 延迟度量值
	ExpenseMetric uint8      // 费用度量值
	ErrorMetric   uint8      // 错误度量值
	IPAddress     net.IP     // IP地址
	SubnetMask    net.IPMask // 子网掩码
}

// IS-IS邻居
type ISISNeighbor struct {
	SystemID  []byte    // 系统ID
	CircuitID uint8     // 电路ID
	State     int       // 邻居状态
	Priority  uint8     // 优先级
	HoldTime  uint16    // 保持时间
	LastHello time.Time // 最后Hello时间
	Level     int       // 级别
	IPAddress net.IP    // IP地址
}

// 邻居状态
const (
	ISISNeighborDown = iota
	ISISNeighborInit
	ISISNeighborUp
)

// IS-IS接口
type ISISInterface struct {
	Name          string                   // 接口名称
	IPAddress     net.IP                   // IP地址
	Mask          net.IPMask               // 子网掩码
	Level         int                      // 级别
	Priority      uint8                    // 优先级
	HelloInterval time.Duration            // Hello间隔
	HoldTime      time.Duration            // 保持时间
	Neighbors     map[string]*ISISNeighbor // 邻居列表
	DIS           []byte                   // 指定IS
	mutex         sync.RWMutex             // 读写锁
}

// IS-IS区域
type ISISArea struct {
	AreaID     []byte                    // 区域ID
	Level      int                       // 级别
	Interfaces map[string]*ISISInterface // 接口列表
	LSPDB      map[string]*ISISLSP       // LSP数据库
	mutex      sync.RWMutex              // 读写锁
}

// IS-IS管理器
type ISISManager struct {
	SystemID     []byte                        // 系统ID
	Areas        map[string]*ISISArea          // 区域列表
	routingTable routing.RoutingTableInterface // 路由表
	logger       *logging.Logger               // 日志记录器
	ctx          context.Context               // 上下文
	cancel       context.CancelFunc            // 取消函数
	mutex        sync.RWMutex                  // 读写锁
}

// NewISISManager 创建新的IS-IS管理器
func NewISISManager(systemID []byte, routingTable routing.RoutingTableInterface, logger *logging.Logger) *ISISManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &ISISManager{
		SystemID:     systemID,
		Areas:        make(map[string]*ISISArea),
		routingTable: routingTable,
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Start 启动IS-IS协议
func (im *ISISManager) Start() error {
	im.logger.Info("启动IS-IS协议")

	// 启动定期任务
	go im.periodicTasks()

	return nil
}

// Stop 停止IS-IS协议
func (im *ISISManager) Stop() error {
	im.logger.Info("停止IS-IS协议")

	im.cancel()
	return nil
}

// AddArea 添加区域
func (im *ISISManager) AddArea(areaID []byte, level int) error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	areaKey := string(areaID)
	if _, exists := im.Areas[areaKey]; exists {
		return fmt.Errorf("区域 %x 已存在", areaID)
	}

	area := &ISISArea{
		AreaID:     areaID,
		Level:      level,
		Interfaces: make(map[string]*ISISInterface),
		LSPDB:      make(map[string]*ISISLSP),
	}

	im.Areas[areaKey] = area
	im.logger.Info(fmt.Sprintf("添加IS-IS区域 %x (级别: %d)", areaID, level))

	return nil
}

// AddInterface 添加接口到区域
func (im *ISISManager) AddInterface(areaID []byte, ifName string, ipAddr net.IP, mask net.IPMask, priority uint8) error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	areaKey := string(areaID)
	area, exists := im.Areas[areaKey]
	if !exists {
		return fmt.Errorf("区域 %x 不存在", areaID)
	}

	if _, exists := area.Interfaces[ifName]; exists {
		return fmt.Errorf("接口 %s 已存在于区域 %x", ifName, areaID)
	}

	intf := &ISISInterface{
		Name:          ifName,
		IPAddress:     ipAddr,
		Mask:          mask,
		Level:         area.Level,
		Priority:      priority,
		HelloInterval: ISISHelloInterval * time.Second,
		HoldTime:      ISISHoldTime * time.Second,
		Neighbors:     make(map[string]*ISISNeighbor),
	}

	area.Interfaces[ifName] = intf
	im.logger.Info(fmt.Sprintf("添加接口 %s 到IS-IS区域 %x", ifName, areaID))

	// 启动接口Hello发送
	go im.sendHelloLoop(area, intf)

	return nil
}

// periodicTasks 定期任务
func (im *ISISManager) periodicTasks() {
	helloTicker := time.NewTicker(ISISHelloInterval * time.Second)
	lspTicker := time.NewTicker(ISISLSPRefreshTime * time.Second)
	csnpTicker := time.NewTicker(ISISCSNPInterval * time.Second)

	defer helloTicker.Stop()
	defer lspTicker.Stop()
	defer csnpTicker.Stop()

	for {
		select {
		case <-im.ctx.Done():
			return
		case <-helloTicker.C:
			im.checkNeighbors()
		case <-lspTicker.C:
			im.refreshLSPs()
		case <-csnpTicker.C:
			im.sendCSNPs()
		}
	}
}

// sendHelloLoop 发送Hello包循环
func (im *ISISManager) sendHelloLoop(area *ISISArea, intf *ISISInterface) {
	ticker := time.NewTicker(intf.HelloInterval)
	defer ticker.Stop()

	for {
		select {
		case <-im.ctx.Done():
			return
		case <-ticker.C:
			im.sendHello(area, intf)
		}
	}
}

// sendHello 发送Hello包
func (im *ISISManager) sendHello(area *ISISArea, intf *ISISInterface) {
	hello := &ISISHelloPDU{
		Header: ISISHeader{
			NLPID:       ISISProtocolID,
			HeaderLen:   27,
			Version:     1,
			IDLen:       ISISSystemIDLen,
			PDUType:     ISISHelloPDUType,
			Version2:    1,
			MaxAreaAddr: 3,
		},
		CircuitType: uint8(intf.Level),
		SourceID:    im.SystemID,
		HoldTime:    uint16(intf.HoldTime.Seconds()),
		Priority:    intf.Priority,
		LANID:       append(intf.DIS, 0),
	}

	// 添加TLV
	hello.TLVs = append(hello.TLVs, ISISTLV{
		Type:   TLVAreaAddresses,
		Length: uint8(len(area.AreaID) + 1),
		Value:  append([]byte{uint8(len(area.AreaID))}, area.AreaID...),
	})

	// 添加IP接口地址TLV
	hello.TLVs = append(hello.TLVs, ISISTLV{
		Type:   TLVIPInterfaceAddress,
		Length: 4,
		Value:  intf.IPAddress.To4(),
	})

	// 这里应该实际发送Hello包，简化实现
	im.logger.Debug(fmt.Sprintf("发送IS-IS Hello包到接口 %s (级别: %d)", intf.Name, intf.Level))
}

// processHello 处理接收到的Hello包
func (im *ISISManager) processHello(hello *ISISHelloPDU, srcAddr net.IP, intf *ISISInterface) {
	neighborKey := string(hello.SourceID)

	intf.mutex.Lock()
	defer intf.mutex.Unlock()

	neighbor, exists := intf.Neighbors[neighborKey]
	if !exists {
		neighbor = &ISISNeighbor{
			SystemID:  hello.SourceID,
			State:     ISISNeighborInit,
			Priority:  hello.Priority,
			IPAddress: srcAddr,
			Level:     int(hello.CircuitType),
		}
		intf.Neighbors[neighborKey] = neighbor
		im.logger.Info(fmt.Sprintf("发现新IS-IS邻居 %x", hello.SourceID))
	}

	neighbor.HoldTime = hello.HoldTime
	neighbor.LastHello = time.Now()

	// 更新邻居状态
	if neighbor.State == ISISNeighborInit {
		neighbor.State = ISISNeighborUp
		im.logger.Info(fmt.Sprintf("IS-IS邻居 %x 状态变为Up", hello.SourceID))

		// 触发SPF计算
		go im.runSPF()
	}
}

// checkNeighbors 检查邻居状态
func (im *ISISManager) checkNeighbors() {
	im.mutex.RLock()
	defer im.mutex.RUnlock()

	for _, area := range im.Areas {
		for _, intf := range area.Interfaces {
			intf.mutex.Lock()
			for key, neighbor := range intf.Neighbors {
				if time.Since(neighbor.LastHello) > time.Duration(neighbor.HoldTime)*time.Second {
					neighbor.State = ISISNeighborDown
					delete(intf.Neighbors, key)
					im.logger.Warn(fmt.Sprintf("IS-IS邻居 %x 超时，移除邻居关系", neighbor.SystemID))

					// 触发SPF计算
					go im.runSPF()
				}
			}
			intf.mutex.Unlock()
		}
	}
}

// generateLSP 生成LSP
func (im *ISISManager) generateLSP(area *ISISArea) *ISISLSP {
	lsp := &ISISLSP{
		Header: ISISHeader{
			NLPID:       ISISProtocolID,
			HeaderLen:   27,
			Version:     1,
			IDLen:       ISISSystemIDLen,
			PDUType:     ISISLSPType,
			Version2:    1,
			MaxAreaAddr: 3,
		},
		RemainingLife: ISISLSPLifetime,
		LSPID:         append(im.SystemID, 0, 0),
		SequenceNum:   uint32(time.Now().Unix()),
		Flags:         0,
	}

	// 添加IS可达性TLV
	var isReach []ISReachability
	for _, intf := range area.Interfaces {
		for _, neighbor := range intf.Neighbors {
			if neighbor.State == ISISNeighborUp {
				reach := ISReachability{
					DefaultMetric: ISISDefaultMetric,
					NeighborID:    neighbor.SystemID,
				}
				isReach = append(isReach, reach)
			}
		}
	}

	if len(isReach) > 0 {
		var tlvValue []byte
		for _, reach := range isReach {
			reachBytes := make([]byte, 11)
			reachBytes[0] = reach.DefaultMetric
			reachBytes[1] = reach.DelayMetric
			reachBytes[2] = reach.ExpenseMetric
			reachBytes[3] = reach.ErrorMetric
			copy(reachBytes[4:], reach.NeighborID)
			tlvValue = append(tlvValue, reachBytes...)
		}

		lsp.TLVs = append(lsp.TLVs, ISISTLV{
			Type:   TLVISReachability,
			Length: uint8(len(tlvValue)),
			Value:  tlvValue,
		})
	}

	// 添加IP可达性TLV
	var ipReach []IPReachability
	for _, intf := range area.Interfaces {
		reach := IPReachability{
			DefaultMetric: ISISDefaultMetric,
			IPAddress:     intf.IPAddress.Mask(intf.Mask),
			SubnetMask:    intf.Mask,
		}
		ipReach = append(ipReach, reach)
	}

	if len(ipReach) > 0 {
		var tlvValue []byte
		for _, reach := range ipReach {
			reachBytes := make([]byte, 12)
			reachBytes[0] = reach.DefaultMetric
			reachBytes[1] = reach.DelayMetric
			reachBytes[2] = reach.ExpenseMetric
			reachBytes[3] = reach.ErrorMetric
			copy(reachBytes[4:8], reach.IPAddress.To4())
			copy(reachBytes[8:12], reach.SubnetMask)
			tlvValue = append(tlvValue, reachBytes...)
		}

		lsp.TLVs = append(lsp.TLVs, ISISTLV{
			Type:   TLVIPReachability,
			Length: uint8(len(tlvValue)),
			Value:  tlvValue,
		})
	}

	return lsp
}

// refreshLSPs 刷新LSP
func (im *ISISManager) refreshLSPs() {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	for _, area := range im.Areas {
		lsp := im.generateLSP(area)
		lspKey := string(lsp.LSPID)

		area.mutex.Lock()
		area.LSPDB[lspKey] = lsp
		area.mutex.Unlock()

		im.logger.Debug(fmt.Sprintf("刷新IS-IS LSP %x", lsp.LSPID))
	}
}

// sendCSNPs 发送CSNP
func (im *ISISManager) sendCSNPs() {
	// 简化实现，实际应该发送完整序列号包
	im.logger.Debug("发送IS-IS CSNP")
}

// runSPF 运行SPF算法
func (im *ISISManager) runSPF() {
	im.mutex.RLock()
	defer im.mutex.RUnlock()

	for _, area := range im.Areas {
		im.logger.Info(fmt.Sprintf("运行IS-IS SPF算法 (区域: %x)", area.AreaID))

		// 构建拓扑图
		graph := make(map[string]map[string]int)

		area.mutex.RLock()
		for _, lsp := range area.LSPDB {
			sourceID := string(lsp.LSPID[:ISISSystemIDLen])
			if graph[sourceID] == nil {
				graph[sourceID] = make(map[string]int)
			}

			// 解析IS可达性TLV
			for _, tlv := range lsp.TLVs {
				if tlv.Type == TLVISReachability {
					for i := 0; i < len(tlv.Value); i += 11 {
						if i+11 <= len(tlv.Value) {
							metric := int(tlv.Value[i])
							neighborID := string(tlv.Value[i+4 : i+10])
							graph[sourceID][neighborID] = metric
						}
					}
				}
			}
		}
		area.mutex.RUnlock()

		// 运行Dijkstra算法
		distances := im.dijkstra(graph, string(im.SystemID))

		// 安装路由
		im.installRoutes(area, distances)
	}
}

// dijkstra Dijkstra最短路径算法
func (im *ISISManager) dijkstra(graph map[string]map[string]int, source string) map[string]int {
	distances := make(map[string]int)
	visited := make(map[string]bool)

	// 初始化距离
	for node := range graph {
		distances[node] = int(^uint(0) >> 1) // 最大整数值
	}
	distances[source] = 0

	for len(visited) < len(graph) {
		// 找到未访问的最小距离节点
		minNode := ""
		minDist := int(^uint(0) >> 1)
		for node, dist := range distances {
			if !visited[node] && dist < minDist {
				minNode = node
				minDist = dist
			}
		}

		if minNode == "" {
			break
		}

		visited[minNode] = true

		// 更新邻居距离
		for neighbor, weight := range graph[minNode] {
			if !visited[neighbor] {
				newDist := distances[minNode] + weight
				if newDist < distances[neighbor] {
					distances[neighbor] = newDist
				}
			}
		}
	}

	return distances
}

// installRoutes 安装路由
func (im *ISISManager) installRoutes(area *ISISArea, distances map[string]int) {
	area.mutex.RLock()
	defer area.mutex.RUnlock()

	for _, lsp := range area.LSPDB {
		sourceID := string(lsp.LSPID[:ISISSystemIDLen])

		// 跳过自己的LSP
		if bytes.Equal(lsp.LSPID[:ISISSystemIDLen], im.SystemID) {
			continue
		}

		distance, exists := distances[sourceID]
		if !exists || distance == int(^uint(0)>>1) {
			continue
		}

		// 解析IP可达性TLV
		for _, tlv := range lsp.TLVs {
			if tlv.Type == TLVIPReachability {
				for i := 0; i < len(tlv.Value); i += 12 {
					if i+12 <= len(tlv.Value) {
						metric := int(tlv.Value[i])
						ipAddr := net.IP(tlv.Value[i+4 : i+8])
						mask := net.IPMask(tlv.Value[i+8 : i+12])

						// 创建路由
						route := &routing.Route{
							Destination: &net.IPNet{
								IP:   ipAddr,
								Mask: mask,
							},
							Gateway:   nil, // 需要计算下一跳
							Interface: "",  // 需要确定出接口
							Metric:    distance + metric,
							Type:      routing.RouteTypeDynamic,
						}

						// 添加到路由表
						im.routingTable.AddRoute(*route)
						im.logger.Debug(fmt.Sprintf("安装IS-IS路由: %s/%d (度量: %d)",
							ipAddr, mask, route.Metric))
					}
				}
			}
		}
	}
}

// GetProtocolName 获取协议名称
func (im *ISISManager) GetProtocolName() string {
	return "IS-IS"
}

// GetNeighbors 获取邻居信息
func (im *ISISManager) GetNeighbors() []interface{} {
	im.mutex.RLock()
	defer im.mutex.RUnlock()

	var neighbors []interface{}
	for _, area := range im.Areas {
		for _, intf := range area.Interfaces {
			intf.mutex.RLock()
			for _, neighbor := range intf.Neighbors {
				neighbors = append(neighbors, map[string]interface{}{
					"system_id": fmt.Sprintf("%x", neighbor.SystemID),
					"state":     neighbor.State,
					"priority":  neighbor.Priority,
					"level":     neighbor.Level,
					"address":   neighbor.IPAddress.String(),
					"interface": intf.Name,
				})
			}
			intf.mutex.RUnlock()
		}
	}

	return neighbors
}

// GetLSPDatabase 获取LSP数据库
func (im *ISISManager) GetLSPDatabase() map[string]*ISISLSP {
	im.mutex.RLock()
	defer im.mutex.RUnlock()

	allLSPs := make(map[string]*ISISLSP)
	for _, area := range im.Areas {
		area.mutex.RLock()
		for key, lsp := range area.LSPDB {
			allLSPs[key] = lsp
		}
		area.mutex.RUnlock()
	}

	return allLSPs
}
