package syslog_ng

import (
	"crypto/sha1"
	"encoding/hex"
	"math"
	"sequence"
	"strings"
)

var syslog_ng = map[string]string{
	"%string%"		:   "@ESTRING:unknown:@",
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

func replaceTags(pattern string) string{
	s := strings.Fields(pattern)
	new := ""
	for _, p := range s{
		if val, ok := syslog_ng[p]; ok {
			//replace with the new values
			p = val
		}
		//reconstruct
		new += " " + p
	}
	return new
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

