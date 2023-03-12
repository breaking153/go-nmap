package main

import (
	"fmt"
	"github.com/breaking153/go-nmap/core"
	"time"
)

// 用于进行测试！！！
func main() {
	var scanner = core.New()
	host := "127.0.0.1"
	port := 5001
	status, response := scanner.ScanTimeout(host, port, time.Second*30)

	fmt.Println(status, response.FingerPrint.Service, host, ":", port)
	port = 22
	status, response = scanner.ScanTimeout(host, port, time.Second*30)

	fmt.Println(status, response.FingerPrint.Service, host, ":", port)
	port = 5000
	status, response = scanner.ScanTimeout(host, port, time.Second*30)
	fmt.Println(status, response.FingerPrint.Service, host, ":", port)
	port = 445
	status, response = scanner.ScanTimeout(host, port, time.Second*30)
	fmt.Println(status, response.FingerPrint.Service, host, ":", port)
}
