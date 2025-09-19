package forwarding

import (
	"net"
	"router-os/internal/routing"
	"time"
)

func NewForwardingCache(maxSize int, ttl time.Duration) *ForwardingCache {
	return &ForwardingCache{
		entries: make(map[string]*CacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
		lru:     NewLRUCache(maxSize),
	}
}

func (fc *ForwardingCache) Get(destination net.IP) (*CacheEntry, bool) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	key := destination.String()
	entry, exists := fc.entries[key]

	if !exists {
		return nil, false
	}

	// 检查是否过期
	if time.Since(entry.Timestamp) > fc.ttl {
		delete(fc.entries, key)
		fc.lru.Remove(key)
		return nil, false
	}

	// 更新LRU
	fc.lru.Get(key)
	entry.HitCount++

	return entry, true
}

func (fc *ForwardingCache) Put(destination net.IP, route routing.Route, nextHop net.IP, iface string, mac net.HardwareAddr) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	key := destination.String()
	entry := &CacheEntry{
		Route:     route,
		NextHop:   nextHop,
		Interface: iface,
		MAC:       mac,
		Timestamp: time.Now(),
		HitCount:  0,
	}

	// 检查缓存大小
	if len(fc.entries) >= fc.maxSize {
		// 移除LRU条目
		oldestKey := fc.lru.RemoveLRU()
		if oldestKey != "" {
			delete(fc.entries, oldestKey)
		}
	}

	fc.entries[key] = entry
	fc.lru.Put(key, entry)
}

func NewLRUCache(capacity int) *LRUCache {
	lru := &LRUCache{
		capacity: capacity,
		items:    make(map[string]*LRUNode),
	}

	// 创建哨兵节点
	lru.head = &LRUNode{}
	lru.tail = &LRUNode{}
	lru.head.next = lru.tail
	lru.tail.prev = lru.head

	return lru
}

func (lru *LRUCache) Get(key string) *CacheEntry {
	if node, exists := lru.items[key]; exists {
		lru.moveToHead(node)
		return node.value
	}
	return nil
}

func (lru *LRUCache) Put(key string, value *CacheEntry) {
	if node, exists := lru.items[key]; exists {
		node.value = value
		lru.moveToHead(node)
	} else {
		newNode := &LRUNode{
			key:   key,
			value: value,
		}

		if len(lru.items) >= lru.capacity {
			tail := lru.removeTail()
			delete(lru.items, tail.key)
		}

		lru.items[key] = newNode
		lru.addToHead(newNode)
	}
}

func (lru *LRUCache) Remove(key string) {
	if node, exists := lru.items[key]; exists {
		lru.removeNode(node)
		delete(lru.items, key)
	}
}

func (lru *LRUCache) RemoveLRU() string {
	tail := lru.removeTail()
	if tail != nil {
		delete(lru.items, tail.key)
		return tail.key
	}
	return ""
}

func (lru *LRUCache) addToHead(node *LRUNode) {
	node.prev = lru.head
	node.next = lru.head.next
	lru.head.next.prev = node
	lru.head.next = node
}

func (lru *LRUCache) removeNode(node *LRUNode) {
	node.prev.next = node.next
	node.next.prev = node.prev
}

func (lru *LRUCache) moveToHead(node *LRUNode) {
	lru.removeNode(node)
	lru.addToHead(node)
}

func (lru *LRUCache) removeTail() *LRUNode {
	lastNode := lru.tail.prev
	if lastNode == lru.head {
		return nil
	}
	lru.removeNode(lastNode)
	return lastNode
}
