package syslog_ng

import (
	"fmt"
	"index/suffixarray"
	"os"
	"sequence"
	"sort"
	"strings"
	"time"
)

var syslog_ng = map[string]string{
	"%string%"		:   "@ESTRING:: @",
	"%alphanum%"	:   "@ESTRING:alphanum: @",
	"%path%"		:   "@ESTRING:path: @",
	"%id%"			:   "@ESTRING:id: @",
   	"%srcemail%"	: 	"@EMAIL:srcemail:@",
	"%float%"		:   "@FLOAT@",
	"%integer%"		:  	"@NUMBER@",
	"%integer%:"	:  	"@NUMBER@:",
	"(%integer%)"	:	"(@NUMBER@)",
	"'%integer%'"	:   "'@NUMBER@'",
	"%srcip%"		:   "@IPvANY:srcip@",
	"%srcip%,"		:   "@IPvANY:srcip@",
	"%dstip%"		:   "@IPvANY:dstip@",
	"%ipv6%"		:   "@IPv6:srcip@",
	"%msgtime%"		:  	"@ESTRING:msgtime: @",
	"%time%"		:	"@ESTRING:time: @",
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
	"'"			:	"@ESTRING:[fieldname]:'@",
	"no-sp"		:	"@ESTRING:[fieldname]:@",

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
	if len(result) > 6{
		if result[len(result)-3:] == ": @"{
			result = result[:len(result)-3] + ":@"
		}
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
			s, del, fieldname := getWithDelimiters(p, off, offsets[i+1]+1)
			if del != ""{
				if val, ok := syslog_ng_string[del]; ok {
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
		case after == ":" || after == "," || after == ";" || after == ">" || after == "'":
			return p[start:end+1], after, fieldname
		}
	}else if end < len(p){
		after :=  p[end:end+1]
		if after == ":" || after == "," || after == ";" {
			return p[start:end+1], after, fieldname
		} else if after != "%"{
			return p[start:end], "no-sp", fieldname
		}
	}
	return p[start:end], "", fieldname
}


func SortLogMessages(lr []sequence.LogRecord) []sequence.LogRecord{
	sort.Slice(lr, func(i, j int) bool {
		if lr[i].Service != lr[j].Service {
			return lr[i].Service < lr[j].Service
		}

		return lr[i].Message < lr[j].Message
	})
	return lr
}

//this can be used to sort and inspect the records in order
//useful for checking the patterns against all the examples
func SortandSaveLogMessages(lr []sequence.LogRecord, fname string  ){
	sort.Slice(lr, func(i, j int) bool {
		if lr[i].Service != lr[j].Service {
			return lr[i].Service < lr[j].Service
		}

		return lr[i].Message < lr[j].Message
	})
	ofile, _ := sequence.OpenOutputFile(fname)
	defer ofile.Close()
	for _, r := range lr{
		fmt.Fprintf(ofile, "%s  %s\n",  r.Service, r.Message )
	}
}

func SaveToDatabase(amap map[string]sequence.AnalyzerResult) {
	db, ctx := sequence.OpenDbandSetContext()
	defer db.Close()
	//exisitng services
	smap := sequence.GetServicesFromDatabase(db, ctx)
	//services to be added to db
	nmap := make(map[string]string)
	//add the patterns and examples
	for _, result := range amap {
		//start with the service, so not to cause a primary key violation
		sid := sequence.GenerateIDFromService(result.Examples[0].Service)
		//check the services if it exists and if not append.
		_, ok := smap[sid]
		if !ok{
			nmap[sid] = result.Examples[0].Service
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		logger.HandleFatal("Could not start a transaction to save to the database.")
	}
	//start with the service, so not to cause a primary key violation
	for sid, m := range nmap{
		sequence.AddService(ctx, tx, sid, m)
	}
	tx.Commit()

	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		logger.HandleFatal("Could not start a transaction to save to the database.")
	}
	//technically we should have any existing patterns passed to here, but just in case
	//lets check first
	pmap := sequence.GetPatternsFromDatabase(db, ctx)
	for pat, result := range amap {
		_, found := pmap[result.PatternId]
		if !found{
			result.Pattern = pat
			sid := sequence.GenerateIDFromService(result.Examples[0].Service)
			sequence.AddPattern(ctx, tx, result, sid)
		}
	}
	tx.Commit()

}

func OutputToFiles(outformat string, outfile string) error{

	var (
			txtFile *os.File
			xmlFile *os.File
			yamlFile *os.File
			xPattDB XPatternDB
	    	yPattDB YPatternDB
			vals []int
			err error
		)


	db, ctx := sequence.OpenDbandSetContext()
	defer db.Close()
	patmap := sequence.GetPatternsWithExamplesFromDatabase(db,ctx)

	outformats := strings.Split(outformat, ",")
	//open the output files for saving data and add any headers
	var fname string
	for _, fmat := range outformats{
		if fmat == "" || fmat == "txt"{
			//open the file for the text output
			if outfile != ""{
				fname =  outfile  + ".txt"
			}
			txtFile, err = sequence.OpenOutputFile(fname)
			if err != nil{
				return err
			}
			defer txtFile.Close()
		}
		if fmat == "yaml" {
			//open the file for the xml output and write the header
			if outfile != ""{
				fname =  outfile  + ".yaml"
			}
			yamlFile, err = sequence.OpenOutputFile(fname)
			defer yamlFile.Close()
			if err != nil{
				return err
			}
			yPattDB = YPatternDB{}
			yPattDB.Rulesets = make(map[string]YRuleset)
			yPattDB.Rules = make(map[string]YRule)
		}
		if fmat == "xml" {
			//open the file for the xml output and write the header
			if outfile != ""{
				fname =  outfile  + ".xml"
			}
			xmlFile, err = sequence.OpenOutputFile(fname)
			defer xmlFile.Close()
			if err != nil{
				return err
			}
			fmt.Fprintf(xmlFile, "<?xml version='1.0' encoding='UTF-8'?>\n")
			xPattDB = XPatternDB{Version: "4", Pubdate:time.Now().Format("2006-01-02 15:04:05")}
		}
	}
	//add the patterns and examples
	for _, result := range patmap {
		vals = append(vals, result.ExampleCount)
		for _, fmat := range outformats {
			if fmat == "" || fmat == "txt"{
				fmt.Fprintf(txtFile, "# %s\n %s\n# %d log messages matched\n# %s\n\n", result.PatternId, result.Pattern, result.ExampleCount, result.Examples[0].Message)
			}
			if fmat == "yaml" {
				yPattDB = AddToYaml(result, yPattDB)
			}
			if fmat == "xml" {
				xPattDB = AddToRuleset(result, xPattDB)
			}
		}
	}

	//finalise the files
	for _, fmat := range outformats{
		if fmat == "yaml" {
			//write to the file
			y := ConvertToYaml(yPattDB)
			fmt.Fprintf(yamlFile, "%s", y)
		}
		if fmat == "xml" {
			//write to the file
			x := ConvertToXml(xPattDB)
			fmt.Fprintf(xmlFile, "%s", x)
		}
	}

	return err
}



