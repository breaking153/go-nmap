# go-nmap
gonmap是一个go语言的nmap端口扫描库，使用纯go实现nmap的扫描逻辑，而非调用nmap来进行扫描。
修改自lcvvvv/gonmap，支持更新修改nmap协议指纹库

## 使用
*直接下载源码编译go build .即可编译main.go中的测试代码进行测试*
### Scanner主调用类

```
	var scanner = core.New()
	host := "127.0.0.1"
	port := 5001
	//开始扫描，status的枚举为Closed、Open、Matched、NotMatched、Unknown,分别为端口关闭，端口开启，匹配到指纹，未匹配到指纹
	status, response := scanner.ScanTimeout(host, port, time.Second*30)
	switch status {
	case _type.Closed:
		print("端口关闭")
		break
	default:
		print(host + response.Raw)
	}
```
