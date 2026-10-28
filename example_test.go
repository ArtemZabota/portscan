package portscan_test

import (
	"context"
	"fmt"
	"net"
	"time"

	"example.com/portscan"
)

func ExampleScanner_Scan() {
	// A local listener makes this example runnable without external services.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.Ports(port))
	if err != nil {
		panic(err)
	}
	for result := range results {
		fmt.Println(result.Host, result.State)
	}
	if err := ctx.Err(); err != nil {
		panic(err)
	}
	// Output: 127.0.0.1 open
}
