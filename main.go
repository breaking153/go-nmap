package main

import (
	"github.com/breaking153/go-nmap/core"
	"github.com/breaking153/go-nmap/type"
	"time"
)

// 用于进行测试！！！
func main() {
	var scanner = core.New()
	host := "185.199.108.153"
	port := 80
	//扫描，status的枚举为Closed、Open、Matched、NotMatched、Unknown,分别为端口关闭，端口开启，匹配到指纹，未匹配到指纹
	status, response := scanner.ScanTimeout(host, port, time.Second*30)
	switch status {
	case _type.Closed:
		print("端口关闭")
		break
	default:
		print(host + ":" + response.FingerPrint.Service)
	}
}
