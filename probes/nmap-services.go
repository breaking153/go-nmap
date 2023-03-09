package probes

import (
	"os"
	"regexp"
	"strconv"
	"strings"
)

var nmapServicesString = ``
var regexpFirstNum = regexp.MustCompile(`^\d`)

func init() {
	openFile, err := os.OpenFile("./Services.txt", os.O_RDONLY, 0444)
	if err != nil {
		panic("[error] probes\\services.txt file not found.")
	}
	stat, err := openFile.Stat()
	if err != nil {
		panic("[error] services.txt stat aquire failed")
	}
	var buffer = make([]byte, stat.Size())
	_, err = openFile.Read([]byte(buffer))
	if err != nil {
		panic("[error] probes\\services.txt file read error.")
	}
	nmapServicesString = string(buffer)
}
func GuessProtocol(port int) string {
	protocol := NmapServices[port]
	if protocol == "unknown" {
		protocol = "http"
	}
	return protocol
}

func FixProtocol(oldProtocol string) string {
	//进行最后输出修饰
	if oldProtocol == "ssl/http" {
		return "https"
	}
	if oldProtocol == "http-proxy" {
		return "http"
	}
	if oldProtocol == "ms-wbt-server" {
		return "rdp"
	}
	if oldProtocol == "microsoft-ds" {
		return "smb"
	}
	if oldProtocol == "netbios-ssn" {
		return "netbios"
	}
	if oldProtocol == "oracle-tns" {
		return "oracle"
	}
	if oldProtocol == "msrpc" {
		return "rpc"
	}
	if oldProtocol == "ms-sql-s" {
		return "mssql"
	}
	if oldProtocol == "domain" {
		return "dns"
	}
	if oldProtocol == "svnserve" {
		return "svn"
	}
	if oldProtocol == "ibm-db2" {
		return "db2"
	}
	if oldProtocol == "socks-proxy" {
		return "socks5"
	}
	if len(oldProtocol) > 4 {
		if oldProtocol[:4] == "ssl/" {
			return oldProtocol[4:] + "-ssl"
		}
	}
	if regexpFirstNum.MatchString(oldProtocol) {
		oldProtocol = "S" + oldProtocol
	}
	oldProtocol = strings.ReplaceAll(oldProtocol, "_", "-")
	return oldProtocol
}

var NmapServices = func() []string {
	var r []string
	for _, line := range strings.Split(nmapServicesString, "\n") {
		index := strings.Index(line, "\t")
		v1 := line[:index]
		v2 := line[index+1:]
		port, _ := strconv.Atoi(v1)
		protocol := v2

		for i := len(r); i < port; i++ {
			r = append(r, "unknown")
		}

		protocol = FixProtocol(protocol)
		r = append(r, protocol)
	}
	return r
}()
