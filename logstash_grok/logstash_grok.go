package logstash_grok

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"sequence"
)

var(
	tags struct {
		general map[string]string
		delstr  map[string]string
		cfield	map[string]string
	}
	logger *sequence.StandardLogger
)


func SetLogger(log *sequence.StandardLogger) {
	logger = log
}

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


func OutputToFiles(outfile string, config string) (int, string, error){
	var (
		err error
		count int
	)

	if config == ""{
		config = "./custom_parser.toml"
	}
	//read the config to load the tags
	if err = readConfig(config); err != nil{
		return count, "", err
	}
	db, ctx := sequence.OpenDbandSetContext()
	defer db.Close()
	patmap, top5 := sequence.GetPatternsWithExamplesFromDatabase(db,ctx)
	logger.HandleInfo(fmt.Sprintf("Found %d patterns for output", len(patmap)))
	count = len(patmap)
	//open the file for the text output
	txtFile, err := sequence.OpenOutputFile(outfile)
	if err != nil{
		return count, top5, err
	}
	defer txtFile.Close()
	fmt.Fprintf(txtFile, "filter {\n")
	fmt.Fprintf(txtFile, "\t grok {\n")

	//add all the patterns here

	fmt.Fprintf(txtFile, "\t }\n")
	fmt.Fprintf(txtFile, "}\n")


	return 0, top5, nil
}