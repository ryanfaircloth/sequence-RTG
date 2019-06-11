package grok_logstash

import "sequence"

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

func OutputToFiles(outformat string, outfile string, config string) (int, string, error){
	return 0, " ", nil
}