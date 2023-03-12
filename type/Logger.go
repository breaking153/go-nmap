package _type

import (
	"log"
	"os"
)

var GlobalLogger = Logger(log.New(os.Stderr, "[gonmap] ", log.Ldate|log.Ltime|log.Lshortfile))

type Logger interface {
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}
