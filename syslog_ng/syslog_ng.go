package syslog_ng

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"index/suffixarray"
	"os"
	"sequence"
	"sequence/models"
	"sort"
	"strconv"
	"strings"
	"time"
)

var(
	tags struct {
		general map[string]string
		delstr  map[string]string
		cfield	map[string]string
	}
)


func readConfig(file string) error {
	var configInfo struct{
		Tags struct {
			General  		map[string]string
			DelimitedString	map[string]string
			Fieldname  		map[string]string
		}
	}
	if _, err := toml.DecodeFile(file, &configInfo); err != nil {
		return err
	}

	tags.general = configInfo.Tags.General
	tags.delstr = configInfo.Tags.DelimitedString
	tags.cfield = configInfo.Tags.Fieldname

	return nil
}

//this replaces the sequence tags with the syslog-ng tags
//first we replace the easy ones that are surrounded by spaces
//then we deal with the compound ones
func replaceTags(pattern string) string{
	s := strings.Fields(pattern)
	var new []string
	mtc := make(map[string]int)
	for _, p := range s{
		if val, ok := tags.general[p]; ok {
			p, mtc = getUpdatedTag(p, mtc, val, "")
		}else{
			p, mtc = getSpecial(p, mtc)
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

func getUpdatedTag(p string, mtc map[string]int, tag string, del string) (string, map[string]int){
	tok := ""
	xchars := len(del)
	if xchars == 2{
		tok = p[2:len(p)-2]
	}else if xchars == 1 {
		tok = p[1:len(p)-2]
	}else{
		tok = p[1:len(p)-1]
	}
	//replace any field names that have a custom value in the config
	tok = checkForCustomFieldName(tok)
	fieldname := tok
	//check if there is more than one in the pattern and number
	if t, ok := mtc[tok]; ok {
		fieldname = fieldname + strconv.Itoa(t)
		mtc[tok] = t+1
		p = strings.Replace(tag, "[fieldname]", fieldname, 1)
	}else{
		mtc[tok] = 1
		p = strings.Replace(tag, "[fieldname]", fieldname, 1)
	}
	return p, mtc
}

func getSpecial(p string, mtc map[string]int) (string, map[string]int) {
	//first get the indexes of the % function
	k := p
	index := suffixarray.New([]byte(p))
	offsets := index.Lookup([]byte("%"), -1)
	sort.Slice(offsets, func(i, j int) bool {
		return offsets[i] < offsets[j]
	})

	for i, off := range offsets {
		if i % 2 == 0 && i < len(offsets)-1{
			s, del, fieldname := getWithDelimiters(p, off, offsets[i+1]+1)
			fieldname = checkForCustomFieldName(fieldname)
			//check if a time regex tag, this needs some manipulation
			if strings.Contains(s, sequence.TagRegExTime.String()) && del == ""{
				r, rg := getTimeRegex(s)
				// look for the pattern
				if val, ok := tags.general[r]; ok {
					r = val
					if rg != ""{
						r = strings.Replace(r, "[regexnotfound]", rg, 1)
					}
				}
				k = strings.Replace(k, s, r, 1)
			} else if del != ""{
				//remove any extra colons and numbers
				if strings.Contains(s, sequence.TagRegExTime.String()){
					fieldname = sequence.TagRegExTime.String()
				}
				if val, ok := tags.delstr[del]; ok {
					val, mtc = getUpdatedTag(s, mtc, val, del)
					k = strings.Replace(k, s, val, 1)
				}
			}else{
				if val, ok := tags.general[s]; ok {
					val, mtc = getUpdatedTag(s, mtc, val, del)
					k = strings.Replace(k, s, val, 1)
				}
			}
		}
	}
	return k, mtc
}

func CreateRulesetName(slice models.ServiceSlice) (string, string){
	//order the services, so concat is always in the same order
	sort.Slice(slice, func(i, j int) bool {
		return slice[i].Name < slice[j].Name
	})
	rname := ""
	for _, s := range slice{
		//try a couple of small intelligent guesses
		d := strings.Split(s.Name, "-")
		if rname != d[0]{
			if len(rname)>0{
				rname += "_"
			}
			rname += d[0]
		}
	}
	return rname, sequence.GenerateIDFromString(rname)
}

func checkForCustomFieldName(f string) string{
	if val, ok := tags.cfield[f]; ok{
		return val
	}
	return f
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
		case after == ":" || after == "," || after == ";" || after == ">" || after == "'" || after == "?" || after == "&":
			return p[start:end+1], after, fieldname
		}
	}else if end < len(p){
		after :=  p[end:end+1]
		if after == ":" || after == "," || after == ";" {
			return p[start:end+1], after, fieldname
		}else if after != "%"{
			return p[start:end], "no-sp", fieldname
		}
	}
	return p[start:end], "", fieldname
}

func getTimeRegex(p string) (string, string){
	//this should be in the format %regextime:number%, the number is the regex id
	//find the colon
	i := strings.Index(p, ":")
	h := p[i+1:len(p)-1]
	rg, ok := sequence.GetTimeSettingsRegExValue(h)
	if ok {
		p = p[:i] + "%"
	}
	return p, rg
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

func SaveLogMessages(lr sequence.LogRecordCollection, fname string  ){
	ofile, _ := sequence.OpenOutputFile(fname)
	defer ofile.Close()
	for _, r := range lr.Records{
		fmt.Fprintf(ofile, "%s  %s\n",  r.Service, r.Message )
	}
}

func SaveExistingToDatabase(rmap map[string]sequence.AnalyzerResult) {
	db, ctx := sequence.OpenDbandSetContext()
	defer db.Close()
	//exisitng services
	smap := sequence.GetServicesFromDatabase(db, ctx)
	//services to be added to db
	nmap := make(map[string]string)
	//add the patterns and examples
	for _, result := range rmap {
		for _, s := range result.Services{
			//check the services if it exists and if not append.
			_, ok := smap[s.ID]
			if !ok{
				nmap[s.ID] = s.Name
			}
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
	//here we want to update the existing patterns with count and last matched
	pmap := sequence.GetPatternsFromDatabase(db, ctx)
	for _, result := range rmap {
		_, found := pmap[result.PatternId]
		if found{
			sequence.UpdatePattern(ctx, tx, result)
		}
	}
	tx.Commit()

}

func SaveToDatabase(amap map[string]sequence.AnalyzerResult) int {
	db, ctx := sequence.OpenDbandSetContext()
	new := 0
	defer db.Close()
	//exisitng services
	smap := sequence.GetServicesFromDatabase(db, ctx)
	//services to be added to db
	nmap := make(map[string]string)
	//add the patterns and examples
	for _, result := range amap {
		for _, s := range result.Services{
			//check the services if it exists and if not append.
			_, ok := smap[s.ID]
			if !ok{
				nmap[s.ID] = s.Name
			}
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
	//technically we should not have any existing patterns passed to here, but just in case
	//lets check first
	pmap := sequence.GetPatternsFromDatabase(db, ctx)
	for _, result := range amap {
		_, found := pmap[result.PatternId]
		if !found{
			sequence.AddPattern(ctx, tx, result)
			new++
		}else{
			sequence.UpdatePattern(ctx, tx, result)
		}
	}
	tx.Commit()

	return new
}

func OutputToFiles(outformat string, outfile string, config string) (int, string, error){

	var (
			txtFile *os.File
			xmlFile *os.File
			yamlFile *os.File
			xPattDB XPatternDB
	    	yPattDB YPatternDB
			vals []int
			err error
			count int
			top5 string
		)

	if config == ""{
		config = "./custom_parser.toml"
	}
	//read the config to load the tags
	if err = readConfig(config); err != nil{
		return count, top5, err
	}
	db, ctx := sequence.OpenDbandSetContext()
	defer db.Close()
	patmap, top5 := sequence.GetPatternsWithExamplesFromDatabase(db,ctx)
    count = len(patmap)
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
				return count, top5, err
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
				return count, top5, err
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
				return count, top5, err
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
			err := SaveAsYaml(yamlFile, yPattDB)
			if err != nil{
				logger.HandleError(err.Error())
			}
		}
		if fmat == "xml" {
			//write to the file
			x := ConvertToXml(xPattDB)
			fmt.Fprintf(xmlFile, "%s", x)
		}
	}

	return count, top5, err
}



