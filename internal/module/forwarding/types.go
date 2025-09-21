package forwarding

import (
	"net"
	"sync"
	"time"

	"router-os/internal/module/routing"
)

// TrafficShaper 流量整形
type TrafficShaper struct {
	mu       sync.RWMutex
	policies map[string]*ShapingPolicy
	buckets  map[string]*TokenBucket
	queues   map[string]*PriorityQueue
}

type ShapingPolicy struct {
	Rate       uint64 // bits per second
	BurstSize  uint64 // bytes
	Priority   int    // 0-7, 0 is highest
	MaxDelay   time.Duration
	DropPolicy DropPolicy
}

type DropPolicy int

const (
	DropTail DropPolicy = iota
	DropRandom
	DropRED
)

type TokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	rate       float64
	lastUpdate time.Time
}

// PriorityQueue 优先级队列
type PriorityQueue struct {
	mu      sync.Mutex
	queues  [8][]*QueuedPacket
	weights [8]int
	sizes   [8]int
	maxSize int
}

type QueuedPacket struct {
	Packet    *IPPacket
	Priority  int
	Timestamp time.Time
	Size      int
}

// ForwardingCache 转发缓存
type ForwardingCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	maxSize int
	ttl     time.Duration
	lru     *LRUCache
}

type CacheEntry struct {
	Route     routing.Route
	NextHop   net.IP
	Interface string
	MAC       net.HardwareAddr
	Timestamp time.Time
	HitCount  uint64
}

// LRUCache LRU缓存
type LRUCache struct {
	capacity int
	items    map[string]*LRUNode
	head     *LRUNode
	tail     *LRUNode
}

type LRUNode struct {
	key   string
	value *CacheEntry
	prev  *LRUNode
	next  *LRUNode
}

type PacketWorker struct {
	id     int
	engine *Engine
	queue  chan *IPPacket
	stop   chan struct{}
}

// MetricsCollector 指标收集器
type MetricsCollector struct {
	mu       sync.RWMutex
	metrics  map[string]interface{}
	interval time.Duration
	stop     chan struct{}
}

// AlertManager 告警管理器
type AlertManager struct {
	mu       sync.RWMutex
	rules    []AlertRule
	alerts   []Alert
	handlers []AlertHandler
	stop     chan struct{}
}

type AlertRule struct {
	ID        string
	Metric    string
	Operator  string
	Threshold interface{}
	Duration  time.Duration
	Level     AlertLevel
}

type RouteEntry struct {
	Route      routing.Route
	Weight     int
	Health     bool
	LastCheck  time.Time
	Latency    time.Duration
	PacketLoss float64
}

// FailoverManager 故障切换管理器
type FailoverManager struct {
	mu              sync.RWMutex
	primaryRoutes   map[string]RouteEntry
	backupRoutes    map[string][]RouteEntry
	healthCheckers  map[string]*HealthChecker
	failoverHistory map[string][]FailoverEvent
}

type FailoverEvent struct {
	Timestamp time.Time
	Route     string
	Event     string
	Reason    string
	Duration  time.Duration
}

// HealthChecker 健康检查
type HealthChecker struct {
	mu        sync.RWMutex
	target    net.IP
	interval  time.Duration
	timeout   time.Duration
	threshold int
	failures  int
	lastCheck time.Time
	isHealthy bool
	stopChan  chan struct{}
	running   bool
}

// PerformanceMonitor 性能监控
type PerformanceMonitor struct {
	mu              sync.RWMutex
	metrics         map[string]*RouteMetrics
	alertThresholds AlertThresholds
	alerts          []Alert
	collectors      []MetricCollector
}

type RouteMetrics struct {
	PacketsForwarded uint64
	BytesForwarded   uint64
	Latency          time.Duration
	PacketLoss       float64
	Bandwidth        uint64
	Utilization      float64
	ErrorRate        float64
	LastUpdate       time.Time
}

type AlertThresholds struct {
	MaxLatency     time.Duration
	MaxPacketLoss  float64
	MaxUtilization float64
	MaxErrorRate   float64
}

type Alert struct {
	ID        string
	Timestamp time.Time
	Level     AlertLevel
	Route     string
	Metric    string
	Value     interface{}
	Threshold interface{}
	Message   string
	Resolved  bool
}

type AlertLevel int

const (
	AlertInfo AlertLevel = iota
	AlertWarning
	AlertCritical
)

type MetricCollector interface {
	CollectMetrics(route string) (*RouteMetrics, error)
	GetName() string
}

type AlertHandler interface {
	HandleAlert(alert Alert) error
	GetName() string
}
