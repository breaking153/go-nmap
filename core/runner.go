package core

import (
	_type "github.com/breaking153/go-nmap/type"
	"time"
)

var nmap *_type.Nmap
var ProbesCount = 0     //探针数
var MatchCount = 0      //指纹数
var UsedProbesCount = 0 //已使用探针数
var UsedMatchCount = 0  //已使用指纹数

// 功能类
func New() *_type.Nmap {
	n := *nmap
	return &n
}

func init() {
	initWithFilter(9)
}

func initWithFilter(filter int) {
	//初始化NMAP探针库
	repairNMAPString()
	nmap = &_type.Nmap{
		Exclude:      _type.EmptyPortList,
		ProbeNameMap: make(map[string]*_type.Probe),
		ProbeSort:    []string{},
		PortProbeMap: make(map[int]_type.ProbeList),

		Filter:  filter,
		Timeout: time.Second,

		ProbeUsed:          _type.EmptyProbeList,
		BypassAllProbePort: []int{161, 137, 139, 135, 389, 443, 548, 1433, 6379, 1883, 5432, 1521, 3389, 3388, 3389, 33890, 33900},
		SslSecondProbeMap:  []string{"TCP_TerminalServerCookie", "TCP_TerminalServer"},
		AllProbeMap:        []string{"TCP_GetRequest", "TCP_NULL"},
		SslProbeMap:        []string{"TCP_TLSSessionReq", "TCP_SSLSessionReq", "TCP_SSLv23SessionReq"},
	}
	for i := 0; i <= 65535; i++ {
		nmap.PortProbeMap[i] = []string{}
	}
	nmap.Loads(_type.NmapServiceProbes)
	//修复fallback
	nmap.FixFallback()
	//新增自定义指纹信息
	customNMAPMatch()
	//优化检测逻辑，及端口对应的默认探针
	optimizeNMAPProbes()
	//排序
	nmap.SslSecondProbeMap = nmap.SortOfRarity(nmap.SslSecondProbeMap)
	nmap.AllProbeMap = nmap.SortOfRarity(nmap.AllProbeMap)
	nmap.SslProbeMap = nmap.SortOfRarity(nmap.SslProbeMap)
	for index, value := range nmap.PortProbeMap {
		nmap.PortProbeMap[index] = nmap.SortOfRarity(value)
	}
	//输出统计数据状态
	statistical()
}
func statistical() {
	ProbesCount = len(nmap.ProbeSort)
	for _, p := range nmap.ProbeNameMap {
		MatchCount += len(p.MatchGroup)
	}
	UsedProbesCount = len(nmap.PortProbeMap[0])
	for _, p := range nmap.PortProbeMap[0] {
		UsedMatchCount += len(nmap.ProbeNameMap[p].MatchGroup)
	}
}

// 配置方法
func SetFilter(filter int) {
	initWithFilter(filter)
}

func SetLogger(v _type.Logger) {
	_type.GlobalLogger = v
}
