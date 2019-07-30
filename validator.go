package sequence

import "strings"

//this file is for various validation that may be called from more than one method

//validation of the argument input from the command line

//input format
//the in-format is for supporting a feed that has the service and the message provided.
//this can be either txt or json
func ValidateInformat(informat string) string {
	if (informat == "json") || (informat == "txt") {
		return ""
	}
	return informat + " is not a supported input format type, please select either json or txt"
}

//output format
func ValidateOutformat(outformat string) string {
	outformats := strings.Split(outformat, ",")
	//open the output files for saving data and add any headers
	for _, fmat := range outformats {
		if (fmat != "xml") && (fmat != "yaml") && (fmat != "txt") {
			return outformat + " is not a supported output format type, only xml, yaml or txt are supported"
		}
	}
	return ""
}


func ValidateAllInOne(outfile string, outformat string, outsystem string) string {
	errors := ValidateOutFile(outfile)
	errors = errors + ValidateOutFormatWithFile(outfile, outformat)
	errors = errors + ValidateOutformat(outformat)
	errors += ValidateOutsystem(outsystem)
	return errors
}

func ValidateOutsystem(outsystem string) string {
	if (outsystem == "patterndb") || (outsystem == "grok") {
		return ""
	}
	return outsystem + " is not a supported out system type, please select either patterndb or grok."
}

//
func ValidateOutFormatWithFile(outfile string, outformat string) string {
	outformats := strings.Split(outformat, ",")
	if len(outformats) > 1 && outfile == "" {
		return "Stdout can only supported one output format type, please select only one."
	}
	return ""
}

//for the create database
func ValidateOutFile(outfile string) string {
	if outfile == "" {
		return "Out file name must be specified for this method."
	}
	return ""
}

func ValidateBatchSize(batchsize int) string {
	if batchsize < 0 {
		return "Batch size must be zero or greater. Negative numbers are not permitted."
	}
	return ""
}

func ValidateLogLevel(lvl string) string{
	if len(lvl) > 0 {
		switch lvl{
		case "debug", "trace", "info", "error", "fatal" :
			//valid - do nothing
			return ""
		default:
			return "Valid values for log level are: trace, debug, info, error or fatal, defaults to info. Please pass one of these values."
		}
	}
	return ""
}

func ValidateType(dbtype string) string{
	switch dbtype{
	case "sqlite3", "postgres", "mssql", "mysql":
		//valid - do nothing
		return ""
	default:
		return "Valid values for database type are: sqlite3, postgres, mssql or mysql. Please pass one of these values."
	}
}