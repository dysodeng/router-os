package routing

import (
	"net"
	"sync"
)

// TrieNode Trie树节点
// Trie树是一种专门用于前缀匹配的数据结构，非常适合路由查找
// 每个节点代表IP地址的一个比特位，从根到叶子的路径代表一个网络前缀
type TrieNode struct {
	// children 子节点数组，索引0代表比特0，索引1代表比特1
	// 对于IPv4，每个节点最多有2个子节点（0和1）
	children [2]*TrieNode
	
	// route 存储在此节点的路由信息
	// 只有当这个节点代表一个完整的网络前缀时才会有值
	route *Route
	
	// isEndOfPrefix 标记这个节点是否是某个网络前缀的结束
	// 用于区分中间节点和实际的路由节点
	isEndOfPrefix bool
}

// RouteTrie 路由Trie树
// 这是一个专门为路由查找优化的Trie树实现
// 支持IPv4和IPv6的快速前缀匹配
type RouteTrie struct {
	// root Trie树的根节点
	root *TrieNode
	
	// mu 读写锁，保护Trie树的并发访问
	// 使用读写锁允许多个查找操作并发进行
	mu sync.RWMutex
	
	// size 树中路由的数量，用于统计
	size int
}

// NewRouteTrie 创建新的路由Trie树
func NewRouteTrie() *RouteTrie {
	return &RouteTrie{
		root: &TrieNode{},
		size: 0,
	}
}

// Insert 插入路由到Trie树
// 时间复杂度：O(前缀长度)，通常比线性搜索快得多
func (rt *RouteTrie) Insert(route *Route) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	
	// 获取网络地址和前缀长度
	network := route.Destination.IP
	prefixLen, _ := route.Destination.Mask.Size()
	
	// 从根节点开始遍历
	current := rt.root
	
	// 按位遍历网络地址，构建Trie路径
	for i := 0; i < prefixLen; i++ {
		// 计算当前比特位的值（0或1）
		bit := getBit(network, i)
		
		// 如果对应的子节点不存在，创建新节点
		if current.children[bit] == nil {
			current.children[bit] = &TrieNode{}
		}
		
		// 移动到子节点
		current = current.children[bit]
	}
	
	// 在最终节点存储路由信息
	if !current.isEndOfPrefix {
		rt.size++
	}
	current.route = route
	current.isEndOfPrefix = true
}

// Search 在Trie树中查找最长前缀匹配的路由
// 这是路由查找的核心算法，实现最长前缀匹配（LPM）
// 时间复杂度：O(32) 对于IPv4，O(128) 对于IPv6
func (rt *RouteTrie) Search(ip net.IP) *Route {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	
	current := rt.root
	var bestMatch *Route
	
	// 确保IP地址是4字节（IPv4）或16字节（IPv6）
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	
	// 遍历IP地址的每一位，寻找最长匹配
	maxBits := len(ip) * 8 // IPv4: 32位, IPv6: 128位
	
	for i := 0; i < maxBits; i++ {
		// 如果当前节点有路由，更新最佳匹配
		// 这确保了我们总是保留最长的匹配前缀
		if current.isEndOfPrefix && current.route != nil {
			bestMatch = current.route
		}
		
		// 获取当前比特位
		bit := getBit(ip, i)
		
		// 如果没有对应的子节点，搜索结束
		if current.children[bit] == nil {
			break
		}
		
		// 移动到子节点继续搜索
		current = current.children[bit]
	}
	
	// 检查最后一个节点是否也有路由
	if current.isEndOfPrefix && current.route != nil {
		bestMatch = current.route
	}
	
	return bestMatch
}

// Delete 从Trie树中删除路由
func (rt *RouteTrie) Delete(destination *net.IPNet) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	
	network := destination.IP
	prefixLen, _ := destination.Mask.Size()
	
	// 找到要删除的节点
	current := rt.root
	path := make([]*TrieNode, 0, prefixLen+1)
	path = append(path, current)
	
	for i := 0; i < prefixLen; i++ {
		bit := getBit(network, i)
		if current.children[bit] == nil {
			return false // 路由不存在
		}
		current = current.children[bit]
		path = append(path, current)
	}
	
	// 检查是否确实有路由在这个位置
	if !current.isEndOfPrefix {
		return false
	}
	
	// 删除路由
	current.route = nil
	current.isEndOfPrefix = false
	rt.size--
	
	// 清理不必要的节点（自底向上）
	rt.cleanup(path, network, prefixLen)
	
	return true
}

// cleanup 清理Trie树中不必要的节点
// 这个方法确保Trie树保持最小化，避免内存浪费
func (rt *RouteTrie) cleanup(path []*TrieNode, network net.IP, prefixLen int) {
	// 从叶子节点向根节点检查
	for i := len(path) - 1; i > 0; i-- {
		current := path[i]
		parent := path[i-1]
		
		// 如果当前节点有路由或有子节点，不能删除
		if current.isEndOfPrefix || current.children[0] != nil || current.children[1] != nil {
			break
		}
		
		// 删除当前节点
		bit := getBit(network, i-1)
		parent.children[bit] = nil
	}
}

// Size 返回Trie树中路由的数量
func (rt *RouteTrie) Size() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.size
}

// Clear 清空Trie树
func (rt *RouteTrie) Clear() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.root = &TrieNode{}
	rt.size = 0
}

// GetAllRoutes 获取Trie树中的所有路由
// 使用深度优先搜索遍历整个树
func (rt *RouteTrie) GetAllRoutes() []*Route {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	
	var routes []*Route
	rt.dfsCollectRoutes(rt.root, &routes)
	return routes
}

// dfsCollectRoutes 深度优先搜索收集所有路由
func (rt *RouteTrie) dfsCollectRoutes(node *TrieNode, routes *[]*Route) {
	if node == nil {
		return
	}
	
	// 如果当前节点有路由，添加到结果中
	if node.isEndOfPrefix && node.route != nil {
		*routes = append(*routes, node.route)
	}
	
	// 递归遍历子节点
	rt.dfsCollectRoutes(node.children[0], routes)
	rt.dfsCollectRoutes(node.children[1], routes)
}

// getBit 获取IP地址指定位置的比特位
// 这是Trie树操作的基础函数，用于确定在树中的路径
func getBit(ip net.IP, position int) int {
	// 计算字节索引和位索引
	byteIndex := position / 8
	bitIndex := 7 - (position % 8) // 网络字节序，高位在前
	
	// 检查边界
	if byteIndex >= len(ip) {
		return 0
	}
	
	// 提取指定位的值
	return int((ip[byteIndex] >> bitIndex) & 1)
}

// PrefixMatch 检查两个IP网络是否有前缀匹配关系
// 这个函数用于路由聚合和冲突检测
func PrefixMatch(net1, net2 *net.IPNet) bool {
	// 获取较短的前缀长度
	len1, _ := net1.Mask.Size()
	len2, _ := net2.Mask.Size()
	minLen := len1
	if len2 < len1 {
		minLen = len2
	}
	
	// 比较前minLen位是否相同
	for i := 0; i < minLen; i++ {
		bit1 := getBit(net1.IP, i)
		bit2 := getBit(net2.IP, i)
		if bit1 != bit2 {
			return false
		}
	}
	
	return true
}