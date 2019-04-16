package sequence

import "strings"

var syslog_ng = map[string]string{
	"%string%":"@STRING@",
	"%srcemail%":"@EMAIL@",
	"%float%":"@FLOAT@",
	"%integer%":"@NUMBER@",
	"%srcip%":"@IPvANY@",
	"%msgtime%":"@ANYSTRING@",
	"%protocol%":"@IPvANY@",
}

//pattern to be used as the starting block for
//all conversions
type AnalyzerResult struct {
	Pattern string
	ExampleCount int
	Example string
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
