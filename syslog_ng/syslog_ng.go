package syslog_ng

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
