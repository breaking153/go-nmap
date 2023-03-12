package core

import (
	"github.com/breaking153/go-nmap/type"
	"strings"
)

func customNMAPMatch() {
	//新增自定义指纹信息
	nmap.AddMatch("TCP_GetRequest", `echo m|^GET / HTTP/1.0\r\n\r\n$|s`)
	nmap.AddMatch("TCP_GetRequest", `mongodb m|.*It looks like you are trying to access MongoDB.*|s p/MongoDB/`)
	nmap.AddMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]+\r\n)*?Server: ([^\r\n]+)| p/$1/`)
	nmap.AddMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d|`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MariaDB server| p/MariaDB/`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MySQL server| p/MySQL/`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a(\d+\.\d+\.\d+)\x00.*caching_sha2_password\x00| p/MariaDB/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a(\d+\.\d+\.\d+)\x00.*caching_sha2_password\x00| p/MariaDB/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a([\d.-]+)-MariaDB\x00.*mysql_native_password\x00| p/MariaDB/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `redis m|-DENIED Redis is running in.*| p/Redis/ i/Protected mode/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Welcome to visit (.*) series router!.*|s p/$1 Router/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^Username: ??|`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Telnet service is disabled or Your telnet session has expired due to inactivity.*|s i/Disabled/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Telnet connection from (.*) refused.*|s i/Refused/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Command line is locked now, please retry later.*\x0d\x0a\x0d\x0a|s i/Locked/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet.*|s`)
	nmap.AddMatch("TCP_NULL", `telnet m|^telnetd:|s`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Quopin CLI for (.*)\x0d\x0a\x0d\x0a|s p/$1/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^\x0d\x0aHello, this is FRRouting \(version ([\d.]+)\).*|s p/FRRouting/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*User Access Verification.*Username:|s`)
	nmap.AddMatch("TCP_NULL", `telnet m|^Connection failed.  Windows CE Telnet Service cannot accept anymore concurrent users.|s o/Windows/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^\x0d\x0a\x0d\x0aWelcome to the host.\x0d\x0a.*|s o/Windows/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Welcome Visiting Huawei Home Gateway\x0d\x0aCopyright by Huawei Technologies Co., Ltd.*Login:|s p/Huawei/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^..\x01..\x03..\x18..\x1f|s p/Huawei/`)
	nmap.AddMatch("TCP_NULL", `smtp m|^220 ([a-z0-1.-]+).*| h/$1/`)
	nmap.AddMatch("TCP_NULL", `ftp m|^220 H3C Small-FTP Server Version ([\d.]+).* | p/H3C Small-FTP/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `ftp m|^421[- ]Service not available..*|`)
	nmap.AddMatch("TCP_NULL", `ftp m|^220[- ].*filezilla.*|i p/FileZilla/`)
	nmap.AddMatch("TCP_TerminalServerCookie", `ms-wbt-server m|^\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02.*\0\x02\0\0\0| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a`)
	nmap.AddMatch("TCP_redis-server", `redis m|^.*redis_version:([.\d]+)\n|s p/Redis key-value store/ v/$1/ cpe:/a:redislabs:redis:$1/`)
	nmap.AddMatch("TCP_redis-server", `redis m|^-NOAUTH Authentication required.|s p/Redis key-value store/`)
}

func repairNMAPString() {
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, "${backquote}", "`")
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `q|GET / HTTP/1.0\r\n\r\n|`,
		`q|GET / HTTP/1.0\r\nHost: {Host}\r\nUser-Agent: Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)\r\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\nAccept: */*\r\n\r\n|`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `\1`, `$1`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?=\\)`, `(?:\\)`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?=[\w._-]{5,15}\r?\n$)`, `(?:[\w._-]{5,15}\r?\n$)`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?:[^\r\n]*r\n(?!\r\n))*?`, `(?:[^\r\n]+\r\n)*?`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?:[^\r\n]*\r\n(?!\r\n))*?`, `(?:[^\r\n]+\r\n)*?`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?:[^\r\n]+\r\n(?!\r\n))*?`, `(?:[^\r\n]+\r\n)*?`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?!2526)`, ``)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?!400)`, ``)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?!\0\0)`, ``)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?!/head>)`, ``)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?!HTTP|RTSP|SIP)`, ``)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?!.*[sS][sS][hH]).*`, `.*`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?!\xff)`, `.`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?!x)`, `[^x]`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?<=.)`, `(?:.)`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `(?<=\?)`, `(?:\?)`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `\x20\x02\x00.`, `\x20\x02..`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `match rtmp`, `# match rtmp`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `nmap`, `pamn`)
	_type.NmapServiceProbes = strings.ReplaceAll(_type.NmapServiceProbes, `Nmap`, `pamn`)
}
func optimizeNMAPProbes() {
	nmap.ProbeNameMap["TCP_GenericLines"].Sslports = nmap.ProbeNameMap["TCP_GenericLines"].Sslports.Append(993, 994, 456, 995)
	//优化检测逻辑，及端口对应的默认探针
	nmap.PortProbeMap[993] = append([]string{"TCP_GenericLines"}, nmap.PortProbeMap[993]...)
	nmap.PortProbeMap[994] = append([]string{"TCP_GenericLines"}, nmap.PortProbeMap[994]...)
	nmap.PortProbeMap[995] = append([]string{"TCP_GenericLines"}, nmap.PortProbeMap[995]...)
	nmap.PortProbeMap[465] = append([]string{"TCP_GenericLines"}, nmap.PortProbeMap[465]...)
	nmap.PortProbeMap[3390] = append(nmap.PortProbeMap[3390], "TCP_TerminalServer")
	nmap.PortProbeMap[3390] = append(nmap.PortProbeMap[3390], "TCP_TerminalServerCookie")
	nmap.PortProbeMap[33890] = append(nmap.PortProbeMap[33890], "TCP_TerminalServer")
	nmap.PortProbeMap[33890] = append(nmap.PortProbeMap[33890], "TCP_TerminalServerCookie")
	nmap.PortProbeMap[33900] = append(nmap.PortProbeMap[33900], "TCP_TerminalServer")
	nmap.PortProbeMap[33900] = append(nmap.PortProbeMap[33900], "TCP_TerminalServerCookie")
	nmap.PortProbeMap[7890] = append(nmap.PortProbeMap[7890], "TCP_Socks5")
	nmap.PortProbeMap[7891] = append(nmap.PortProbeMap[7891], "TCP_Socks5")
	nmap.PortProbeMap[4000] = append(nmap.PortProbeMap[4000], "TCP_Socks5")
	nmap.PortProbeMap[2022] = append(nmap.PortProbeMap[2022], "TCP_Socks5")
	nmap.PortProbeMap[6000] = append(nmap.PortProbeMap[6000], "TCP_Socks5")
	nmap.PortProbeMap[7000] = append(nmap.PortProbeMap[7000], "TCP_Socks5")
	//将TCP_GetRequest的fallback参数设置为NULL探针，避免漏资产
	nmap.ProbeNameMap["TCP_GenericLines"].Fallback = "TCP_NULL"
	nmap.ProbeNameMap["TCP_GetRequest"].Fallback = "TCP_NULL"
	nmap.ProbeNameMap["TCP_TerminalServerCookie"].Fallback = "TCP_GetRequest"
	nmap.ProbeNameMap["TCP_TerminalServer"].Fallback = "TCP_GetRequest"
}
