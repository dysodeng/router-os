package main

import (
	"flag"
	"fmt"
	"os"
	"router-os/examples/demo"
)

func main() {
	var demoType = flag.String("demo", "basic", "演示类型: basic, performance, algorithms, advanced")
	flag.Parse()

	fmt.Println("🚀 Router OS 演示程序")
	fmt.Println("======================")

	switch *demoType {
	case "basic":
		fmt.Println("📋 运行基础功能演示...")
		demo.RunBasicDemo()
	case "advanced":
		fmt.Println("📋 运行高级功能演示...")
		demo.RunAdvancedRoutingDemo()
	case "performance":
		fmt.Println("⚡ 运行性能优化演示...")
		demo.RunPerformanceDemo()
	case "algorithms":
		fmt.Println("🧮 运行路由算法演示...")
		demo.RunAlgorithmsDemo()
	default:
		fmt.Printf("❌ 未知的演示类型: %s\n", *demoType)
		fmt.Println("可用的演示类型:")
		fmt.Println("  basic      - 基础功能演示")
		fmt.Println("  performance - 性能优化演示")
		fmt.Println("  algorithms  - 路由算法演示")
		fmt.Println("\n使用方法:")
		fmt.Println("  go run examples/*.go -demo=basic")
		fmt.Println("  go run examples/*.go -demo=performance")
		fmt.Println("  go run examples/*.go -demo=algorithms")
		os.Exit(1)
	}
}
