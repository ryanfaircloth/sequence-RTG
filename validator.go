package sequence

import "strings"

//this file is for various validation that may be called from more than one method

//validation of the argument input from the command line

//input format
//the in-format is for supporting a feed that has the service and the message provided.
//this can be either txt or json
func ValidateInformat(informat string) string {
	if (informat == "json") ||  (informat == "txt"){
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

//
func ValidateOutFormatWithFile(outfile string, outformat string) string {
	outformats := strings.Split(outformat, ",")
	if len(outformats) > 1 && outfile == ""{
		return "Stdout can only supported one output format type, please select only one."
	}
	return ""
}

//for the create database
func ValidateOutFile(outfile string) string {
	if outfile == ""{
		return "Out file name must be specified for creating a database."
	}
	return ""
}

func ValidateBatchSize(batchsize int) string {
	if batchsize < 0{
		return "Batch size must be zero or greater. Negative numbers are not permitted."
	}
	return ""
}

func ValidateMode(mode string) string {
	if mode != "" && mode != "cont" && mode != "sing"{
		return "Mode can either be omitted, 'sing' or 'cont'. Other values are not supported"
	}
	return ""
}


