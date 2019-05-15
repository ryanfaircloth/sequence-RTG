package syslog_ng

import(
	"sequence"
)

var(
	logger *sequence.StandardLogger
)

func SetLogger(log *sequence.StandardLogger) {
	logger = log
}

func GetLogger() *sequence.StandardLogger{
	return logger
}
