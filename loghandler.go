package sequence

import (
	"github.com/sirupsen/logrus"
	"os"
)

//this log wrapper makes it easy to change logging library in one
//place if other golang logging libraries are preferred.

// Event stores messages to log later, from our standard interface
type Event struct {
	id      int
	message string
}

// StandardLogger enforces specific log message formats
type StandardLogger struct {
	*logrus.Logger
}

// NewLogger initializes the standard logger
func NewLogger(fname string) *StandardLogger {
	var baseLogger = logrus.New()

	var standardLogger = &StandardLogger{baseLogger}
	if len(fname) == 0{
		fname = "sequence.log"
	}
	file, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err == nil {
		standardLogger.Out = file
	} else {
		standardLogger.HandleInfo("Failed to log to file, using default stderr")
	}

	standardLogger.Formatter = &logrus.JSONFormatter{}

	// Only log the warning severity or above.
	standardLogger.SetLevel(logrus.DebugLevel)
	return standardLogger
}

// Declare variables to store log messages as new Events
var (
	errorGenericInfo = Event{100, "%s"}
	errorGenericError = Event{200, "%s"}
	errorAnalysisFailed = Event{201, "Unable to analyze: %s"}
	errorDbInsertFailed = Event{301, "Failed to insert record into %s table, id: %s, reason: %s"}
	errorDbSelectFailed = Event{302, "Failed to select record(s) from %s table, query: %s, reason: %s"}
	errorGenericFatal = Event{400, "Fatal error occurred, reason: %s"}
	errorGenericPanic = Event{500, "Panic occurred, reason: %s"}
)

func (l *StandardLogger) LogAnalysisFailed(lr LogRecord){
	l.WithFields(logrus.Fields{
		"id": errorAnalysisFailed.id,
	}).Errorf(errorAnalysisFailed.message, lr.Message)
}

func (l *StandardLogger) DatabaseInsertFailed(tablename string, id string, reason string){
	l.WithFields(logrus.Fields{
		"id": errorDbInsertFailed.id,
	}).Errorf(errorDbInsertFailed.message, tablename, id, reason)
}

func (l *StandardLogger) DatabaseSelectFailed(tablename string, query string, reason string){
	l.WithFields(logrus.Fields{
		"id": errorDbSelectFailed.id,
	}).Errorf(errorDbSelectFailed.message, tablename, query, reason)
}

func (l *StandardLogger) HandleFatal(err string){
	l.WithFields(logrus.Fields{
		"id": errorGenericFatal.id,
	}).Fatalf(errorGenericFatal.message, err)
}

func (l *StandardLogger) HandlePanic(err string){
	l.WithFields(logrus.Fields{
		"id": errorGenericPanic.id,
	}).Panicf(errorGenericPanic.message, err)
}

func (l *StandardLogger) HandleInfo(message string){
	l.WithFields(logrus.Fields{
		"id": errorGenericInfo.id,
	}).Infof(errorGenericInfo.message, message)
}

func (l *StandardLogger) HandleError(message string){
	l.WithFields(logrus.Fields{
		"id": errorGenericError.id,
	}).Infof(errorGenericError.message, message)
}

