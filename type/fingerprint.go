package _type

type FingerPrint struct {
	ProbeName        string //匹配到探针名称
	MatchRegexString string //匹配的正则
	Service          string //匹配到的服务指纹
	ProductName      string //
	Version          string
	Info             string
	Hostname         string
	OperatingSystem  string
	DeviceType       string
	//  p/vendorproductname/
	//	v/version/
	//	i/info/
	//	h/hostname/
	//	o/operatingsystem/
	//	d/devicetype/
}
