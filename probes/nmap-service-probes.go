package probes

import (
	"os"
)

var NmapServiceProbes = ``

// 修改了初始化的逻辑，将指纹放入probes.txt
func init() {
	openFile, err := os.OpenFile("./Probes.txt", os.O_RDONLY, 0444)
	if err != nil {
		panic("[error] probes\\Probes.txt file not found.")
	}
	stat, err := openFile.Stat()
	if err != nil {
		return
	}
	var buffer = make([]byte, stat.Size())
	_, err = openFile.Read([]byte(buffer))
	if err != nil {
		panic("[error] probes\\Probes.txt file read error.")
	}
	NmapServiceProbes = string(buffer)
}
