package syslog_ng

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"index/suffixarray"
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
	"%string%"		:   "@ESTRING:: @",
	"%string%:"		:   "@ESTRING:::@",
	"\"%string%\""	:   "@QSTRING::\"@",
	"[%string%]"	:	"@QSTRING::[]@",
	"(%string%)"	:	"@QSTRING::()@",
	"<%string%>"	:   "@QSTRING::<>@",
	"(%srcuser%)"   :	"@QSTRING:srcuser:()@",
	"<%srcuser%>"   :	"@QSTRING:srcuser:<>@",
	"`%string%`"	:	"@QSTRING::`@",
   	"%srcemail%"	: 	"@EMAIL:srcemail:@",
	"%float%"		:   "@FLOAT@",
	"%integer%"		:  	"@NUMBER@",
	"%srcip%"		:   "@IPvANY:srcip@",
	"%dstip%"		:   "@IPvANY:dstip@",
	"%msgtime%"		:  	"@ESTRING:msgtime: @",
	"%protocol%"	: 	"@ESTRING:protocol: @",
	"%msgid%" 		:   "@ESTRING:msgid: @",
	"%severity%" 	:	"@ESTRING:severity: @",
	"priority%" 	: 	"@ESTRING:priority: @",
	"%apphost%" 	: 	"@ESTRING:apphost: @",
	"%appip%" 		:   "@ESTRING:appip: @",
	"%appvendor%"	:	"@ESTRING:appvendor: @",
	"%appname%" 	: 	"@ESTRING:appname: @",
	"%srcdomain%"	:	"@ESTRING:srcdomain: @",
	"%srczone%" 	: 	"@ESTRING:srczone: @",
	"%srchost%" 	: 	"@HOSTNAME:srchost@",
	"%srcipnat%" 	:	"@ESTRING:srcipnat: @",
	"%srcport%" 	: 	"@NUMBER:srcport@",
	"%srcportnat%" 	: 	"@ESTRING:srcportnat: @",
	"%srcmac%" 		: 	"@MACADDR:srcmac@",
	"%srcuser%" 	: 	"@ESTRING:srcuser: @",
	"%srcuid%" 		: 	"@ESTRING:srcuid: @",
	"%srcgid%" 		: 	"@ESTRING:srcgid: @",
	"%dstdomain%" 	: 	"@ESTRING:dstdomain: @",
	"%dstzone%" 	: 	"@ESTRING:dstzone: @",
	"%dsthost%" 	: 	"@HOSTNAME:dsthost:@",
	"%dstipnat%" 	: 	"@ESTRING:dstipnat: @",
	"%dstport%" 	: 	"@NUMBER:dstport@",
	"%dstportnat%" 	: 	"@ESTRING:dstportnat: @",
	"%dstmac%" 		: 	"@MACADDR:dstmac@",
	"%dstuser%" 	: 	"@ESTRING:dstuser: @",
	"%dstuid%" 		: 	"@ESTRING:dstuid: @",
	"%dstgroup%" 	: 	"@ESTRING:dstgroup: @",
	"%dstgid%" 		: 	"@ESTRING:dstgid: @",
	"%dstemail%" 	: 	"@ESTRING:dstemail: @",
	"%iniface%" 	: 	"@ESTRING:iniface: @",
	"%outiface%" 	: 	"@ESTRING:outiface: @",
	"%policyid%" 	: 	"@ESTRING:policyid: @",
	"%sessionid%" 	: 	"@ESTRING:sessionid: @",
	"%action%" 		: 	"@ESTRING:action: @",
	"%command%" 	: 	"@ESTRING:command: @",
	"%object%" 		: 	"@ESTRING:object: @",
	"%method%" 		: 	"@ESTRING:method: @",
	"%status%" 		: 	"@ESTRING:status: @",
	"%reason%" 		: 	"@ESTRING:reason: @",
	"%bytesrecv%" 	: 	"@ESTRING:bytesrecv: @",
	"%bytessent%" 	: 	"@ESTRING:bytessent: @",
	"%pktsrecv%" 	: 	"@ESTRING:pktsrecv: @",
	"%pktssent%" 	: 	"@ESTRING:pktssent: @",
	"%duration%" 	: 	"@ESTRING:duration: @",
	"%uri%"			:	"@ESTRING:uri: @",
}

var syslog_ng_quote = map[string]string{
	"qstring"		: 	"@QSTRING:[fieldname]:[del]@",
}

//this replaces the sequence tags with the syslog-ng tags
//first we replace the easy ones that are surrounded by spaces
//then we deal with the compound ones
func replaceTags(pattern string) string{
	s := strings.Fields(pattern)
	var new []string
	for _, p := range s{
		if val, ok := syslog_ng[p]; ok {
			p=val
		}else{
			p=getSpecial(p)
		}
		//reconstruct
		new = append(new, p)
	}
	var result string
	//no space at the start
	var space = ""
	for _, k := range new{
		result += space + k
		space = " "
	}
	return result
}

func getSpecial(p string) string {
	//first get the indexes of the % function
	k := p
	index := suffixarray.New([]byte(p))
	offsets := index.Lookup([]byte("%"), -1)
	sort.Slice(offsets, func(i, j int) bool {
		return offsets[i] < offsets[j]
	})

	for i, off := range offsets {
		if i % 2 == 0{
			//s:= p[off:offsets[i+1]+1]
			s:= getWithDelimiters(p, off, offsets[i+1]+1)
			if val, ok := syslog_ng[s]; ok {
				k = strings.Replace(k, s, val, 1)
			}

		}
	}
	return k
}

func getWithDelimiters(p string, start, end int ) string{
	if start > 0 && end < len(p) {
		before := p[start-1:start]
		after :=  p[end:end+1]
		switch {
		case before == after && (before == "\"" || before == "'"):
			return p[start-1:end+1]
		case before == "(" && after == ")":
			return p[start-1:end+1]
		case before == "<" && after == ">":
			return p[start-1:end+1]
		}
	}else if end < len(p){
		after :=  p[end:end+1]
		if after == ":" {
			return p[start:end+1]
		}
		return p[start:end]
	}
	return p[start:end]
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



