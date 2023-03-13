package _type

import (
	"context"
	"embed"
	"fmt"
	"github.com/miekg/dns"
	"strconv"
	"strings"
	"time"
)

var NmapServices []string
var nmapServicesString = ``
var NmapServiceProbes = ``

//go:embed Resource/*
var ResourceFS embed.FS

func init() {
	probesFile, err := ResourceFS.ReadFile("Resource/Probes.txt")
	if err != nil {
		panic("[error] can't Find Resource/Probes.txt")
	}
	serviceFile, err := ResourceFS.ReadFile("Resource/Services.txt")
	if err != nil {
		panic("[error] can't Find Resource/Services.txt")
	}
	nmapServicesString = strings.ReplaceAll(string(serviceFile), "\r\n", "\n")
	NmapServiceProbes = strings.ReplaceAll(string(probesFile), "\r\n", "\n")
	//初始化NmapService列表
	NmapServices = func() []string {
		var r []string
		for _, line := range strings.Split(nmapServicesString, "\r\n") {
			index := strings.Index(line, "\t")
			v1 := line[:index]
			v2 := line[index+1:]
			port, _ := strconv.Atoi(v1)
			protocol := v2
			for i := len(r); i < port; i++ {
				r = append(r, "unknown")
			}
			r = append(r, protocol)
		}
		return r
	}()
}

type Nmap struct {
	Exclude      PortList          // 不进行扫描的端口列表
	PortProbeMap map[int]ProbeList //
	ProbeNameMap map[string]*Probe // 探针索引列表（名称）
	ProbeSort    ProbeList         // 排序后的探针列表

	ProbeUsed ProbeList //使用的探针列表

	Filter int //需要筛选的探针等级，默认为9

	//检测端口存活的超时时间
	Timeout time.Duration

	BypassAllProbePort PortList
	SslSecondProbeMap  ProbeList
	AllProbeMap        ProbeList
	SslProbeMap        ProbeList
}

// 扫描类
func (n *Nmap) ScanTimeout(ip string, port int, timeout time.Duration) (status Status, response *Response) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	var resChan = make(chan bool)

	defer func() {
		close(resChan)
		cancel()
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				if fmt.Sprint(r) != "send on closed channel" {
					panic(r)
				}
			}
		}()
		status, response = n.scan(ip, port)
		resChan <- true
	}()

	select {
	case <-ctx.Done():
		return Closed, nil
	case <-resChan:
		return status, response
	}
}

// 内部扫描单个线程
func (n *Nmap) scan(ip string, port int) (status Status, response *Response) {
	var probeNames ProbeList
	if n.BypassAllProbePort.exist(port) == true {
		probeNames = append(n.PortProbeMap[port], n.AllProbeMap...)
	} else {
		probeNames = append(n.AllProbeMap, n.PortProbeMap[port]...)
	}
	probeNames = append(probeNames, n.SslProbeMap...)
	//探针去重
	probeNames = probeNames.removeDuplicate()

	firstProbe := probeNames[0]
	status, response = n.getRealResponse(ip, port, n.Timeout, firstProbe)
	if status == Closed || status == Matched {
		return status, response
	}
	otherProbes := probeNames[1:]
	return n.getRealResponse(ip, port, 2*time.Second, otherProbes...)
}

func (n *Nmap) getRealResponse(host string, port int, timeout time.Duration, probes ...string) (status Status, response *Response) {
	status, response = n.getResponseByProbes(host, port, timeout, probes...)
	if status != Matched {
		return status, response
	}
	if response.FingerPrint.Service == "ssl" {
		status, response := n.getResponseBySSLSecondProbes(host, port, timeout)
		if status == Matched {
			return Matched, response
		}
	}
	return status, response
}

func (n *Nmap) getResponseBySSLSecondProbes(host string, port int, timeout time.Duration) (status Status, response *Response) {
	status, response = n.getResponseByProbes(host, port, timeout, n.SslSecondProbeMap...)
	if status != Matched || response.FingerPrint.Service == "ssl" {
		status, response = n.getResponseByHTTPS(host, port, timeout)
	}
	if status == Matched && response.FingerPrint.Service != "ssl" {
		if response.FingerPrint.Service == "http" {
			response.FingerPrint.Service = "https"
		}
		return Matched, response
	}
	return NotMatched, response
}

func (n *Nmap) getResponseByHTTPS(host string, port int, timeout time.Duration) (status Status, response *Response) {
	var httpRequest = n.ProbeNameMap["TCP_GetRequest"]
	return n.getResponse(host, port, true, timeout, httpRequest)
}

func (n *Nmap) getResponseByProbes(host string, port int, timeout time.Duration, probes ...string) (status Status, response *Response) {
	var responseNotMatch *Response
	for _, requestName := range probes {
		if n.ProbeUsed.exist(requestName) {
			continue
		}
		n.ProbeUsed = append(n.ProbeUsed, requestName)
		p := n.ProbeNameMap[requestName]

		status, response = n.getResponse(host, port, p.Sslports.exist(port), timeout, p)
		//如果端口未开放，则等待10s后重新连接
		//if b.status == Closed {
		//	time.Sleep(time.Second * 10)
		//	b.Load(n.getResponse(host, port, n.probeNameMap[requestName]))
		//}

		//logger.Printf("Target:%s:%d,Probe:%s,Status:%v", host, port, requestName, status)

		if status == Closed || status == Matched {
			responseNotMatch = nil
			break
		}
		if status == NotMatched {
			responseNotMatch = response
		}
	}
	if responseNotMatch != nil {
		response = responseNotMatch
	}
	return status, response
}

func (n *Nmap) getResponse(host string, port int, tls bool, timeout time.Duration, p *Probe) (Status, *Response) {
	if port == 53 {
		if DnsScan(host, port) {
			return Matched, &dnsResponse
		} else {
			return Closed, nil
		}
	}
	text, tls, err := p.scan(host, port, tls, timeout, 10240)
	if err != nil {
		if strings.Contains(err.Error(), "STEP1") {
			return Closed, nil
		}
		if strings.Contains(err.Error(), "STEP2") {
			return Closed, nil
		}
		if p.protocol == "UDP" && strings.Contains(err.Error(), "refused") {
			return Closed, nil
		}
		return Open, nil
	}

	response := &Response{
		Raw:         text,
		TLS:         tls,
		FingerPrint: &FingerPrint{},
	}
	//若存在返回包，则开始捕获指纹
	fingerPrint := n.getFinger(text, tls, p.name)
	response.FingerPrint = fingerPrint

	if fingerPrint.Service == "" {
		return NotMatched, response
	} else {
		return Matched, response
	}
	//如果成功匹配指纹，则直接返回指纹
}

func (n *Nmap) getFinger(responseRaw string, tls bool, requestName string) *FingerPrint {
	data := n.convResponse(responseRaw)
	probe := n.ProbeNameMap[requestName]

	finger := probe.match(data)

	if tls == true {
		if finger.Service == "http" {
			finger.Service = "https"
		}
	}

	if finger.Service != "" || n.ProbeNameMap[requestName].Fallback == "" {
		//标记当前探针名称
		finger.ProbeName = requestName
		return finger
	}

	fallback := n.ProbeNameMap[requestName].Fallback
	fallbackProbe := n.ProbeNameMap[fallback]
	for fallback != "" {
		GlobalLogger.Println(requestName, " fallback is :", fallback)
		finger = fallbackProbe.match(data)
		fallback = n.ProbeNameMap[fallback].Fallback
		if finger.Service != "" {
			break
		}
	}
	//标记当前探针名称
	finger.ProbeName = requestName
	return finger
}

func (n *Nmap) convResponse(s1 string) string {
	//为了适配go语言的沙雕正则，只能讲二进制强行转换成UTF-8
	b1 := []byte(s1)
	var r1 []rune
	for _, i := range b1 {
		r1 = append(r1, rune(i))
	}
	s2 := string(r1)
	return s2
}

//配置类

func (n *Nmap) SetTimeout(timeout time.Duration) {
	n.Timeout = timeout
}

func (n *Nmap) OpenDeepIdentify() {
	//-sV参数深度解析
	n.AllProbeMap = n.ProbeSort
}

func (n *Nmap) AddMatch(probeName string, expr string) {
	var probe = n.ProbeNameMap[probeName]
	probe.loadMatch(expr, false)
}

// 初始化类
func (n *Nmap) Loads(s string) {
	lines := strings.Split(s, "\n")
	var probeGroups [][]string
	var probeLines []string
	for _, line := range lines {
		if !n.isCommand(line) {
			continue
		}
		commandName := line[:strings.Index(line, " ")]
		if commandName == "Exclude" {
			n.loadExclude(line)
			continue
		}
		if commandName == "Probe" {
			if len(probeLines) != 0 {
				probeGroups = append(probeGroups, probeLines)
				probeLines = []string{}
			}
		}
		probeLines = append(probeLines, line)
	}
	probeGroups = append(probeGroups, probeLines)

	for _, lines := range probeGroups {
		p := parseProbe(lines)
		n.pushProbe(*p)
	}
}

func GuessProtocol(port int) string {
	protocol := NmapServices[port]
	if protocol == "unknown" {
		protocol = "http"
	}
	return protocol
}

func (n *Nmap) loadExclude(expr string) {
	n.Exclude = parsePortList(expr)
}

func (n *Nmap) pushProbe(p Probe) {
	n.ProbeSort = append(n.ProbeSort, p.name)
	n.ProbeNameMap[p.name] = &p

	//建立端口扫描对应表，将根据端口号决定使用何种请求包
	//如果端口列表为空，则为全端口
	if p.rarity > n.Filter {
		return
	}
	//0记录所有使用的探针
	n.PortProbeMap[0] = append(n.PortProbeMap[0], p.name)

	//分别压入sslports,ports
	for _, i := range p.ports {
		n.PortProbeMap[i] = append(n.PortProbeMap[i], p.name)
	}

	for _, i := range p.Sslports {
		n.PortProbeMap[i] = append(n.PortProbeMap[i], p.name)
	}

}

// 修改FallBack内容
func (n *Nmap) FixFallback() {
	for probeName, probeType := range n.ProbeNameMap {
		fallback := probeType.Fallback
		if fallback == "" {
			continue
		}
		if _, ok := n.ProbeNameMap["TCP_"+fallback]; ok {
			n.ProbeNameMap[probeName].Fallback = "TCP_" + fallback
		} else {
			n.ProbeNameMap[probeName].Fallback = "UDP_" + fallback
		}
	}
}

func (n *Nmap) isCommand(line string) bool {
	//删除注释行和空行
	if len(line) < 2 {
		return false
	}
	if line[:1] == "#" {
		return false
	}
	//删除异常命令
	commandName := line[:strings.Index(line, " ")]
	commandArr := []string{
		"Exclude", "Probe", "match", "softmatch", "ports", "sslports", "totalwaitms", "tcpwrappedms", "rarity", "fallback",
	}
	for _, item := range commandArr {
		if item == commandName {
			return true
		}
	}
	return false
}

func (n *Nmap) SortOfRarity(list ProbeList) ProbeList {
	if len(list) == 0 {
		return list
	}
	var raritySplice []int
	for _, probeName := range list {
		rarity := n.ProbeNameMap[probeName].rarity
		raritySplice = append(raritySplice, rarity)
	}

	for i := 0; i < len(raritySplice)-1; i++ {
		for j := 0; j < len(raritySplice)-i-1; j++ {
			if raritySplice[j] > raritySplice[j+1] {
				m := raritySplice[j+1]
				raritySplice[j+1] = raritySplice[j]
				raritySplice[j] = m
				mp := list[j+1]
				list[j+1] = list[j]
				list[j] = mp
			}
		}
	}

	for _, probeName := range list {
		rarity := n.ProbeNameMap[probeName].rarity
		raritySplice = append(raritySplice, rarity)
	}

	return list
}

// 工具函数
func DnsScan(host string, port int) bool {
	domainServer := fmt.Sprintf("%s:%d", host, port)
	c := dns.Client{
		Timeout: 2 * time.Second,
	}
	m := dns.Msg{}
	// 最终都会指向一个ip 也就是typeA, 这样就可以返回所有层的cname.
	m.SetQuestion("www.baidu.com.", dns.TypeA)
	_, _, err := c.Exchange(&m, domainServer)
	if err != nil {
		return false
	}
	return true
}
