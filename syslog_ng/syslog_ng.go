package syslog_ng

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"index/suffixarray"
	"sequence"
	"sort"
	"strings"
)

var syslog_ng = map[string]string{
	"%string%"		:   "@ESTRING:: @",
	"%alphanum%"	:   "@ESTRING:: @",
	"%path%"		:   "@ESTRING:path: @",
	"%id%"			:   "@ESTRING:id: @",
   	"%srcemail%"	: 	"@EMAIL:srcemail:@",
	"%float%"		:   "@FLOAT@",
	"%integer%"		:  	"@NUMBER@",
	"%integer%:"	:  	"@NUMBER@:",
	"(%integer%)"	:	"(@NUMBER@)",
	"'%integer%'"	:   "'@NUMBER@'",
	"%srcip%"		:   "@IPvANY:srcip@",
	"%dstip%"		:   "@IPvANY:dstip@",
	"%msgtime%"		:  	"@ESTRING:msgtime: @",
	"%protocol%"	: 	"@ESTRING:protocol: @",
	"%msgid%" 		:   "@ESTRING:msgid: @",
	"%severity%" 	:	"@ESTRING:severity: @",
	"%priority%" 	: 	"@ESTRING:priority: @",
	"%apphost%" 	: 	"@ESTRING:apphost: @",
	"%appip%" 		:   "@ESTRING:appip: @",
	"%appvendor%"	:	"@ESTRING:appvendor: @",
	"%appname%" 	: 	"@ESTRING:appname: @",
	"%srcdomain%"	:	"@ESTRING:srcdomain: @",
	"%srczone%" 	: 	"@ESTRING:srczone: @",
	"%srchost%" 	: 	"@HOSTNAME:srchost@",
	"%srcipnat%" 	:	"@ESTRING:srcipnat: @",
	"%srcport%" 	: 	"@NUMBER:srcport@",
	"%srcport%:" 	: 	"@NUMBER:srcport@:",
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
	"%object%:"		:	"@ESTRING:object::@",
	"%method%" 		: 	"@ESTRING:method: @",
	"%status%" 		: 	"@ESTRING:status: @",
	"%status%:" 	: 	"@ESTRING:status::@",
	"%reason%" 		: 	"@ESTRING:reason: @",
	"%bytesrecv%" 	: 	"@ESTRING:bytesrecv: @",
	"%bytessent%" 	: 	"@ESTRING:bytessent: @",
	"%pktsrecv%" 	: 	"@ESTRING:pktsrecv: @",
	"%pktssent%" 	: 	"@ESTRING:pktssent: @",
	"%duration%" 	: 	"@ESTRING:duration: @",
	"%uri%"			:	"@ESTRING:uri: @",
}

var syslog_ng_string = map[string]string{
	"()"		: 	"@QSTRING:[fieldname]:()@",
	"[]"		: 	"@QSTRING:[fieldname]:[]@",
	"\"\""		: 	"@QSTRING:[fieldname]:\"@",
	"''"		: 	"@QSTRING:[fieldname]:'@",
	"<>"		:	"@QSTRING:[fieldname]:<>@",
	"``"		:	"@QSTRING:[fieldname]:`@",
	":"			:	"@ESTRING:[fieldname]::@",
	","			:	"@ESTRING:[fieldname]:,@",
	";"			:	"@ESTRING:[fieldname]:;@",
	">"			:	"@ESTRING:[fieldname]:>@",

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
		//need to remove the space after an ESTRING if space delimited
		if len(k) > 10 {
			if k[len(k)-3:] == ": @"{
				space = ""
			}
		}
	}
	// if the pattern ends looking for a space delimiter
	// remove the space
	if result[len(result)-3:] == ": @"{
		result = result[:len(result)-3] + ":@"
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
		if i % 2 == 0 && i < len(offsets)-1{
			//s:= p[off:offsets[i+1]+1]
			s, pat, fieldname := getWithDelimiters(p, off, offsets[i+1]+1)
			if pat != ""{
				if val, ok := syslog_ng_string[pat]; ok {
					val = strings.Replace(val, "[fieldname]", fieldname, 1)
					k = strings.Replace(k, s, val, 1)
				}
			}else{
				if val, ok := syslog_ng[s]; ok {
					k = strings.Replace(k, s, val, 1)
				}
			}

		}
	}
	return k
}

func getWithDelimiters(p string, start, end int ) (string, string, string){
	fieldname := p[start+1:end-1]
	//integer fields are not considered strings so can bypass this
	if fieldname == "integer"{
		return p[start:end], "", fieldname
	}
	if start > 0 && end < len(p) {
		before := p[start-1:start]
		after :=  p[end:end+1]
		switch {
		case before == after && (before == "\"" || before == "'" || before == "`"):
			return p[start-1:end+1], before + after, fieldname
		case (before == "(" && after == ")") || (before == "[" && after == "]") :
			return p[start-1:end+1], before + after, fieldname
		case before == "<" && after == ">":
			return p[start-1:end+1], before + after, fieldname
		case after == ":" || after == "," || after == ";" || after == ">":
			return p[start:end+1], after, fieldname
		}
	}else if end < len(p){
		after :=  p[end:end+1]
		if after == ":" || after == "," || after == ";" {
			return p[start:end+1], after, fieldname
		}
		return p[start:end], "", fieldname
	}
	return p[start:end], "", fieldname
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




//this can be used to sort and inspect the records in order
//useful for checking the patterns against all the examples
func SortandPrintLogMessages(lr []sequence.LogRecord, fname string  ){
	sort.Slice(lr, func(i, j int) bool {
		if lr[i].Service != lr[j].Service {
			return lr[i].Service < lr[j].Service
		}

		return lr[i].Message < lr[j].Message
	})
	ofile := sequence.OpenOutputFile(fname)
	defer ofile.Close()
	for _, r := range lr{
		fmt.Fprintf(ofile, "%s  %s\n",  r.Service, r.Message )
	}
}



