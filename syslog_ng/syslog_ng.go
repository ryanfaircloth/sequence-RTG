package syslog_ng

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sequence"
	"sort"
	"strings"
)

type LogRecord struct {
	Service string
	Message string
}

var syslog_ng = map[string]string{
	"%string%"		:   "@ESTRING::@",
	"%string%:"		:   "@ESTRING:::@",
	"\"%string%\""	:   "@QSTRING::\"@",
	"[%string%]"	:	"@QSTRING::[]@",
	"(%string%)"	:	"@QSTRING::()@",
	"`%string%`"	:	"@QSTRING::`@",
   	"%srcemail%"	: 	"@EMAIL:srcemail:@",
	"%float%"		:   "@FLOAT@",
	"%integer%"		:  	"@NUMBER@",
	"%srcip%"		:   "@IPvANY:srcip@",
	"%dstip%"		:   "@IPvANY:dstip@",
	"%msgtime%"		:  	"@ESTRING:msgtime:@",
	"%protocol%"	: 	"@ESTRING:protocol:@",
	"%msgid%" 		:   "@ESTRING:msgid:@",
	"%severity%" 	:	"@ESTRING:severity:@",
	"priority%" 	: 	"@ESTRING:priority:@",
	"%apphost%" 	: 	"@ESTRING:apphost:@",
	"%appip%" 		:   "@ESTRING:appip:@",
	"%appvendor%"	:	"@ESTRING:appvendor:@",
	"%appname%" 	: 	"@ESTRING:appname:@",
	"%srcdomain%"	:	"@ESTRING:srcdomain:@",
	"%srczone%" 	: 	"@ESTRING:srczone:@",
	"%srchost%" 	: 	"@HOSTNAME:srchost@",
	"%srcipnat%" 	:	"@ESTRING:srcipnat:@",
	"%srcport%" 	: 	"@NUMBER:srcport@",
	"%srcportnat%" 	: 	"@ESTRING:srcportnat:@",
	"%srcmac%" 		: 	"@MACADDR:srcmac@",
	"%srcuser%" 	: 	"@ESTRING:srcuser:@",
	"%srcuid%" 		: 	"@ESTRING:srcuid:@",
	"%srcgid%" 		: 	"@ESTRING:srcgid:@",
	"%dstdomain%" 	: 	"@ESTRING:dstdomain:@",
	"%dstzone%" 	: 	"@ESTRING:dstzone:@",
	"%dsthost%" 	: 	"@HOSTNAME:dsthost:@",
	"%dstipnat%" 	: 	"@ESTRING:dstipnat:@",
	"%dstport%" 	: 	"@NUMBER:dstport@",
	"%dstportnat%" 	: 	"@ESTRING:dstportnat:@",
	"%dstmac%" 		: 	"@MACADDR:dstmac@",
	"%dstuser%" 	: 	"@ESTRING:dstuser:@",
	"%dstuid%" 		: 	"@ESTRING:dstuid:@",
	"%dstgroup%" 	: 	"@ESTRING:dstgroup:@",
	"%dstgid%" 		: 	"@ESTRING:dstgid:@",
	"%dstemail%" 	: 	"@ESTRING:dstemail:@",
	"%iniface%" 	: 	"@ESTRING:iniface:@",
	"%outiface%" 	: 	"@ESTRING:outiface:@",
	"%policyid%" 	: 	"@ESTRING:policyid:@",
	"%sessionid%" 	: 	"@ESTRING:sessionid:@",
	"%action%" 		: 	"@ESTRING:action:@",
	"%command%" 	: 	"@ESTRING:command:@",
	"%object%" 		: 	"@ESTRING:object:@",
	"%method%" 		: 	"@ESTRING:method:@",
	"%status%" 		: 	"@ESTRING:status:@",
	"%reason%" 		: 	"@ESTRING:reason:@",
	"%bytesrecv%" 	: 	"@ESTRING:bytesrecv:@",
	"%bytessent%" 	: 	"@ESTRING:bytessent:@",
	"%pktsrecv%" 	: 	"@ESTRING:pktsrecv:@",
	"%pktssent%" 	: 	"@ESTRING:pktssent:@",
	"%duration%" 	: 	"@ESTRING:duration:@",
	"%uri%"			:	"@ESTRING:uri:@",
}

var syslog_ng_quote = map[string]string{
	"qstring"		: 	"@QSTRING:[fieldname]:[del]@",
}

//this replaces the sequence tags with the syslog-ng tags
func replaceTags(pattern string) string{
	s := strings.Fields(pattern)
	var new []string
	var del = ""
	for _, p := range s{
		//this is to catch a delimiter char and skip it
		if del == p{
			del = ""
			continue
		}
		if val, ok := syslog_ng[p]; ok {
			p=val
		}
		//reconstruct
		new = append(new, p)
	}
	var result string
	var space = ""
	for _, k := range new{
		result += space + k
		space = " "
	}
	return result
}

func getSpecial(p, del string) string {
	if val, ok := syslog_ng_quote["qstring"]; ok{
		fieldname := strings.TrimSuffix(p[1:], "%")
		if fieldname == "string"{
			fieldname = "unknown"
		}
		result := strings.Replace(val, "[fieldname]", fieldname, 1)
		result = strings.Replace(result, "[del]", del, 1)
		return result
	}
	return p
}

func checkIfNew(pattern sequence.AnalyzerResult) bool {
	return false
}

//this is so that the same pattern will have the same id
//in all files and the id is reproducible
//returns a sha1 hash as the id
func generateIDFromPattern(pattern string) string{
	h := sha1.New()
	h.Write([]byte(pattern))
	sha := h.Sum(nil)  // "sha" is uint8 type, encoded in base16
	shaStr := hex.EncodeToString(sha)  // String representation
	return shaStr
}

func GetThreshold(numTotal int) int {
	trPercent := 0.001
	total := float64(numTotal)
	t := trPercent * total
	tr := int(math.Floor(t))
	return tr
}

func ReadLogRecordTxt(fname string) []LogRecord {
	var lr []LogRecord
	iscan, ifile := OpenInputFile(fname)
	defer ifile.Close()
	for iscan.Scan() {
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
	}
	return lr
}

//this method expects a json record in the format {"service": "service-name", message: "log message"}
//eg {"service":"remctld","message":"error receiving initial token: unexpected end of file"}
func ReadLogRecordJson(fname string) []LogRecord {
	var lr []LogRecord
	iscan, ifile := OpenInputFile(fname)
	defer ifile.Close()
	for iscan.Scan() {
		message := iscan.Text()
		if len(message) == 0 || message[0] == '#' {
			continue
		}
		r := LogRecord{}
		_ = json.Unmarshal([]byte(message), &r)
		lr = append(lr, r)
	}
	return lr
}

//this can be used to sort and inspect the records in order
func SortandPrintLogMessages(lr []LogRecord, fname string  ){
	sort.Slice(lr, func(i, j int) bool {
		if lr[i].Service != lr[j].Service {
			return lr[i].Service < lr[j].Service
		}

		return lr[i].Message < lr[j].Message
	})
	ofile := OpenOutputFile(fname)
	defer ofile.Close()
	for _, r := range lr{
		fmt.Fprintf(ofile, "%s: %s\n", r.Service, r.Message )
	}
}



