package sequence

import (
	"encoding/json"
	"strings"
)

type LogRecord struct {
	Service string
	Message string
}

type LogRecordCollection struct {
	Service string
	Records []LogRecord
}

//if json, this method expects record in the format {"service": "service-name", message: "log message"}
//eg {"service":"remctld","message":"error receiving initial token: unexpected end of file"}
func ReadLogRecord(fname string, format string) []LogRecord {
	var lr []LogRecord
	iscan, ifile := OpenInputFile(fname)
	defer ifile.Close()
	var r LogRecord
	for iscan.Scan() {
		message := iscan.Text()
		if message == "q"{
			break
		}
		if len(message) == 0 || message[0] == '#' {
			continue
		}
		if format == "json"{
			r = LogRecord{}
			_ = json.Unmarshal([]byte(message), &r)
			//check for an empty service and set it to none
			if r.Service == ""{
				r.Service = "none"
			}
		}else{
			//the first field is the service, delimited by a space
			k := strings.Fields(message)
			s := k[0]
			//we need to remove the service from the remaining message
			i := len(s) + 1
			m := message[i:]
			r = LogRecord{Service: s, Message: m}
		}
		lr = append(lr, r)
	}
	//fmt.Printf("File loaded: %d records found\n", len(lr))
	return lr
}

//if json, this method expects record in the format {"service": "service-name", message: "log message"}
//eg {"service":"remctld","message":"error receiving initial token: unexpected end of file"}
func ReadLogRecordAsMap(fname string, format string) (int, map[string] LogRecordCollection){
	var lr LogRecordCollection
	var count = 0
	var smap = make(map[string] LogRecordCollection)
	iscan, ifile := OpenInputFile(fname)
	defer ifile.Close()
	var r LogRecord
	for iscan.Scan() {
		message := iscan.Text()
		// this is for the stdin to halt.
		if message == "q"{
			break
		}
		if len(message) == 0 || message[0] == '#' {
			continue
		}
		if format == "json"{
			r = LogRecord{}
			_ = json.Unmarshal([]byte(message), &r)
			//check for an empty service and set it to none
			if r.Service == ""{
				r.Service = "none"
			}
		}else{
			//the first field is the service, delimited by a space
			k := strings.Fields(message)
			s := k[0]
			//we need to remove the service from the remaining message
			i := len(s) + 1
			m := message[i:]
			r = LogRecord{Service: s, Message: m}
		}
		//look for the service in the map
		if val, ok := smap[r.Service]; ok {
			val.Records = append(val.Records, r)
			smap[r.Service] = val
		} else{
			lr = LogRecordCollection{Service:r.Service}
			lr.Records = append(lr.Records, r)
			smap[r.Service] = lr
		}
		count++
	}
	return count, smap
}
