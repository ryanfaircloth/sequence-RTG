package sequence

import (
	"encoding/json"
	"fmt"
	"strings"
)

type LogRecord struct {
	Service string
	Message string
}

func ReadLogRecordTxt(fname string) []LogRecord {
	var lr []LogRecord
	var count int64 = 0
	iscan, ifile := OpenInputFile(fname)
	defer ifile.Close()
	for iscan.Scan() && count < config.maxBatchSize{
		message := iscan.Text()
		if len(message) == 0 || message[0] == '#' {
			continue
		}
		//the first field is the service, delimited by a space
		k := strings.Fields(message)
		s := k[0]
		//we need to remove the service from the remaining message
		i := len(s) + 1
		m := message[i:]
		r := LogRecord{Service: s, Message: m}
		lr = append(lr, r)
		count++
	}
	return lr
}

//this method expects a json record in the format {"service": "service-name", message: "log message"}
//eg {"service":"remctld","message":"error receiving initial token: unexpected end of file"}
func ReadLogRecordJson(fname string) []LogRecord {
	var lr []LogRecord
	var count int64  = 0
	iscan, ifile := OpenInputFile(fname)
	defer ifile.Close()
	for iscan.Scan() && count < config.maxBatchSize {
		message := iscan.Text()
		if len(message) == 0 || message[0] == '#' {
			continue
		}
		r := LogRecord{}
		_ = json.Unmarshal([]byte(message), &r)
		lr = append(lr, r)
		count++
	}
	fmt.Printf("File loaded: %d records found\n", len(lr))
	return lr
}
