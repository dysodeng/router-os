package forwarding

import "time"

func NewTrafficShaper() *TrafficShaper {
	return &TrafficShaper{
		policies: make(map[string]*ShapingPolicy),
		buckets:  make(map[string]*TokenBucket),
		queues:   make(map[string]*PriorityQueue),
	}
}

func (ts *TrafficShaper) AddPolicy(route string, policy *ShapingPolicy) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.policies[route] = policy
	ts.buckets[route] = NewTokenBucket(float64(policy.Rate), float64(policy.BurstSize))
	ts.queues[route] = NewPriorityQueue(1000) // 最大1000个数据包
}

func (ts *TrafficShaper) ShapePacket(route string, packet *IPPacket) bool {
	ts.mu.RLock()
	policy, exists := ts.policies[route]
	bucket, bucketExists := ts.buckets[route]
	queue, queueExists := ts.queues[route]
	ts.mu.RUnlock()

	if !exists || !bucketExists || !queueExists {
		return true // 没有策略，直接通过
	}

	// 检查令牌桶
	if bucket.TakeTokens(float64(packet.Size)) {
		return true // 有足够令牌，直接发送
	}

	// 没有足够令牌，加入队列
	queuedPacket := &QueuedPacket{
		Packet:    packet,
		Priority:  policy.Priority,
		Timestamp: time.Now(),
		Size:      packet.Size,
	}

	return queue.Enqueue(queuedPacket)
}

func NewTokenBucket(rate, capacity float64) *TokenBucket {
	return &TokenBucket{
		tokens:     capacity,
		capacity:   capacity,
		rate:       rate,
		lastUpdate: time.Now(),
	}
}

func (tb *TokenBucket) TakeTokens(tokens float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()

	// 添加新令牌
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	tb.lastUpdate = now

	if tb.tokens >= tokens {
		tb.tokens -= tokens
		return true
	}

	return false
}

func NewPriorityQueue(maxSize int) *PriorityQueue {
	pq := &PriorityQueue{
		maxSize: maxSize,
	}

	// 初始化权重（优先级越低，权重越高）
	for i := 0; i < 8; i++ {
		pq.weights[i] = 8 - i
	}

	return pq
}

func (pq *PriorityQueue) Enqueue(packet *QueuedPacket) bool {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	priority := packet.Priority
	if priority < 0 || priority >= 8 {
		priority = 7 // 默认最低优先级
	}

	// 检查队列是否已满
	totalSize := 0
	for i := 0; i < 8; i++ {
		totalSize += pq.sizes[i]
	}

	if totalSize >= pq.maxSize {
		// 队列已满，根据丢弃策略处理
		return false
	}

	pq.queues[priority] = append(pq.queues[priority], packet)
	pq.sizes[priority]++

	return true
}

func (pq *PriorityQueue) Dequeue() *QueuedPacket {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	// 按优先级顺序检查队列
	for i := 0; i < 8; i++ {
		if pq.sizes[i] > 0 {
			packet := pq.queues[i][0]
			pq.queues[i] = pq.queues[i][1:]
			pq.sizes[i]--
			return packet
		}
	}

	return nil
}
