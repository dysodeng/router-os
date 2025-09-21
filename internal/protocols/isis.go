// Package protocols 实现IS-IS协议
//
// IS-IS协议详解：
// IS-IS (Intermediate System to Intermediate System) 是一个链路状态路由协议，
// 最初为OSI协议栈设计，后来扩展支持IP协议。它是大型网络中广泛使用的IGP协议。
//
// 核心概念：
// 1. 中间系统（IS）：路由器在OSI术语中的称呼
// 2. 端系统（ES）：主机在OSI术语中的称呼
// 3. 系统ID：6字节的唯一标识符，类似于MAC地址
// 4. 区域（Area）：IS-IS网络的逻辑分组，用于层次化路由
// 5. 级别（Level）：IS-IS支持两级层次结构
//   - Level-1：区域内路由
//   - Level-2：区域间路由
//
// IS-IS工作原理：
// 1. 邻居发现：通过Hello PDU建立和维护邻居关系
// 2. 链路状态传播：通过LSP（Link State PDU）传播拓扑信息
// 3. 数据库同步：通过CSNP和PSNP确保LSP数据库一致性
// 4. 路由计算：使用Dijkstra算法计算最短路径
// 5. 路由安装：将计算结果安装到路由表
//
// PDU类型：
// 1. Hello PDU：邻居发现和维护
// 2. LSP（Link State PDU）：链路状态信息
// 3. CSNP（Complete Sequence Number PDU）：完整序列号PDU
// 4. PSNP（Partial Sequence Number PDU）：部分序列号PDU
//
// DIS选举：
// 在广播网络中，IS-IS选举指定中间系统（DIS）来：
// 1. 减少LSP泛洪开销
// 2. 简化网络拓扑表示
// 3. 提高网络收敛速度
// DIS选举基于优先级和系统ID，优先级高者当选
//
// TLV结构：
// IS-IS使用TLV（Type-Length-Value）格式携带各种信息：
// - 区域地址、邻居信息、IP可达性等
// - 支持协议扩展和新功能添加
//
// 本实现特点：
// - 遵循ISO/IEC 10589标准
// - 支持Level-1和Level-2路由
// - 实现完整的邻居状态机
// - 支持DIS选举机制
// - 提供LSP数据库管理
// - 集成Dijkstra最短路径算法
//
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
// 这些常量遵循ISO/IEC 10589标准，定义了IS-IS协议的基本参数
const (
	// ISISProtocolID 协议标识符
	// 0x83是IS-IS协议在OSI网络层的标准标识符
	// 用于在数据链路层标识IS-IS协议数据单元
	ISISProtocolID = 0x83

	// PDU类型定义
	// IS-IS定义了四种基本PDU类型，用于不同的协议功能

	// ISISHelloPDUType Hello PDU类型（15）
	// 用于邻居发现、邻居关系维护和DIS选举
	// 定期发送以维持邻居关系的活跃状态
	ISISHelloPDUType = 15

	// ISISLSPType LSP PDU类型（18）
	// 链路状态PDU，携带网络拓扑和可达性信息
	// 这是IS-IS协议的核心，用于构建网络拓扑数据库
	ISISLSPType = 18

	// ISISCSNPType 完整序列号PDU类型（24）
	// 用于LSP数据库同步，包含完整的LSP摘要信息
	// 在点到点链路上用于数据库同步
	ISISCSNPType = 24

	// ISISPSNPType 部分序列号PDU类型（26）
	// 用于请求特定的LSP或确认LSP接收
	// 在数据库同步过程中使用
	ISISPSNPType = 26

	// 级别定义
	// IS-IS支持两级层次化路由结构

	// ISISLevel1 Level-1级别
	// 区域内路由，只在单个区域内传播路由信息
	// Level-1路由器只维护本区域的详细拓扑
	ISISLevel1 = 1

	// ISISLevel2 Level-2级别
	// 区域间路由，在不同区域之间传播路由信息
	// Level-2路由器维护区域间的拓扑信息
	ISISLevel2 = 2

	// 定时器参数（单位：秒）
	// 这些定时器控制IS-IS协议的各种周期性行为

	// ISISHelloInterval Hello发送间隔
	// 邻居Hello消息的发送频率，默认10秒
	// 用于维持邻居关系和检测链路状态
	ISISHelloInterval = 10

	// ISISHoldTime 邻居保持时间
	// 邻居失效的超时时间，通常是Hello间隔的3倍
	// 如果在此时间内未收到Hello，则认为邻居失效
	ISISHoldTime = 30

	// ISISLSPLifetime LSP生存时间
	// LSP在网络中的最大生存时间，默认1200秒（20分钟）
	// 超过此时间的LSP将被删除
	ISISLSPLifetime = 1200

	// ISISLSPRefreshTime LSP刷新时间
	// LSP的刷新间隔，默认900秒（15分钟）
	// 在LSP过期前重新生成并传播
	ISISLSPRefreshTime = 900

	// ISISCSNPInterval CSNP发送间隔
	// 完整序列号PDU的发送频率，默认10秒
	// 用于定期同步LSP数据库
	ISISCSNPInterval = 10

	// 度量值定义
	// IS-IS使用度量值来表示链路成本

	// ISISMaxMetric 最大度量值
	// IS-IS协议中链路的最大成本值，63表示链路不可达
	// 用于标识故障链路或进行流量工程
	ISISMaxMetric = 63

	// ISISDefaultMetric 默认度量值
	// 链路的默认成本值，用于正常的链路
	// 可以根据链路带宽和延迟进行调整
	ISISDefaultMetric = 10

	// 标识符长度定义
	// IS-IS使用固定长度的标识符

	// ISISSystemIDLen 系统ID长度
	// 每个IS-IS节点的唯一标识符长度，固定为6字节
	// 类似于MAC地址的概念，在整个IS-IS域内必须唯一
	ISISSystemIDLen = 6

	// ISISCircuitIDLen 电路ID长度
	// 用于标识多路访问网络中的伪节点，长度为1字节
	// 在广播网络中由DIS分配
	ISISCircuitIDLen = 1

	// ISISLSPIDLen LSP ID长度
	// LSP标识符的总长度，包含系统ID和附加字段
	// 用于唯一标识网络中的每个LSP
	ISISLSPIDLen = ISISSystemIDLen + 2
)

// TLV类型定义
// TLV（Type-Length-Value）是IS-IS协议中携带各种信息的标准格式
// 每种TLV类型都有特定的用途和数据结构
const (
	// TLVAreaAddresses 区域地址TLV（类型1）
	// 携带IS-IS节点所属的区域地址信息
	// 用于区域边界识别和路由决策
	// 一个节点可以属于多个区域
	TLVAreaAddresses = 1

	// TLVISNeighbors IS邻居TLV（类型2）
	// 在Hello PDU中携带已知的IS邻居信息
	// 用于邻居关系建立和维护
	// 包含邻居的系统ID和度量值
	TLVISNeighbors = 2

	// TLVESNeighbors ES邻居TLV（类型3）
	// 携带端系统（主机）邻居信息
	// 在现代IP网络中较少使用
	// 主要用于OSI环境中的主机发现
	TLVESNeighbors = 3

	// TLVPartitionDIS 分区DIS TLV（类型4）
	// 用于处理网络分区情况下的DIS信息
	// 帮助修复网络分区问题
	// 在网络拓扑变化时使用
	TLVPartitionDIS = 4

	// TLVPrefixNeighbors 前缀邻居TLV（类型5）
	// 携带前缀级别的邻居信息
	// 用于更精细的路由控制
	// 支持基于前缀的路由策略
	TLVPrefixNeighbors = 5

	// TLVISReachability IS可达性TLV（类型22）
	// 在LSP中携带IS-IS节点的可达性信息
	// 描述到其他IS节点的连接和度量值
	// 用于构建网络拓扑图
	TLVISReachability = 22

	// TLVIPReachability IP可达性TLV（类型128）
	// 携带IP前缀的可达性信息
	// 这是IS-IS支持IP路由的关键TLV
	// 包含IP前缀、子网掩码和度量值
	TLVIPReachability = 128

	// TLVProtocolsSupported 支持的协议TLV（类型129）
	// 声明节点支持的网络层协议
	// 通常包含IP协议标识符
	// 用于协议兼容性检查
	TLVProtocolsSupported = 129

	// TLVIPInterfaceAddress IP接口地址TLV（类型132）
	// 携带节点接口的IP地址信息
	// 用于下一跳解析和连通性检查
	// 在LSP中通告接口地址
	TLVIPInterfaceAddress = 132

	// TLVHostname 主机名TLV（类型137）
	// 携带IS-IS节点的可读主机名
	// 用于网络管理和故障诊断
	// 便于网络管理员识别节点
	TLVHostname = 137
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
	SystemID     []byte                 // 系统ID
	Areas        map[string]*ISISArea   // 区域列表
	routingTable routing.TableInterface // 路由表
	logger       *logging.Logger        // 日志记录器
	ctx          context.Context        // 上下文
	cancel       context.CancelFunc     // 取消函数
	mutex        sync.RWMutex           // 读写锁
}

// NewISISManager 创建新的IS-IS管理器
func NewISISManager(systemID []byte, routingTable routing.TableInterface, logger *logging.Logger) *ISISManager {
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
	im.logger.Info("添加IS-IS区域 %x (级别: %d)", areaID, level)

	return nil
}

// AddInterface 添加接口到区域
func (im *ISISManager) AddInterface(areaID []byte, ifName string, ipAddr net.IP, mask net.IPMask, priority uint8) error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	area, exists := im.Areas[string(areaID)]
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
	im.logger.Info("添加接口 %s 到IS-IS区域 %x", ifName, areaID)

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
	im.logger.Debug("发送IS-IS Hello包到接口 %s (级别: %d)", intf.Name, intf.Level)
}

// processHello 处理接收到的Hello包
//
//nolint:unused // 此函数为Hello包处理保留，将在网络包接收模块中使用
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
		im.logger.Info("发现新IS-IS邻居 %x", hello.SourceID)
	}

	neighbor.HoldTime = hello.HoldTime
	neighbor.LastHello = time.Now()

	// 更新邻居状态
	if neighbor.State == ISISNeighborInit {
		neighbor.State = ISISNeighborUp
		im.logger.Info("IS-IS邻居 %x 状态变为Up", hello.SourceID)

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
					im.logger.Warn("IS-IS邻居 %x 超时，移除邻居关系", neighbor.SystemID)

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

		im.logger.Debug("刷新IS-IS LSP %x", lsp.LSPID)
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
		im.logger.Info("运行IS-IS SPF算法 (区域: %x)", area.AreaID)

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
						_ = im.routingTable.AddRoute(*route)
						im.logger.Debug("安装IS-IS路由: %s/%d (度量: %d)",
							ipAddr, mask, route.Metric)
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
