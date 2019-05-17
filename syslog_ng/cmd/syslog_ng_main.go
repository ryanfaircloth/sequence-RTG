package main

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"runtime/pprof"
	"sequence"
	"sequence/syslog_ng"
	"strings"
	"time"
)

var (
	cfgfile    string
	infile     string
	outfile    string
	logfile    string
	outformat  string
	informat  string
	patfile    string
	cpuprofile string
	workers    int
	format     string
	parcfgfile string
	batchsize  int
	standardLogger *sequence.StandardLogger

	quit chan struct{}
	done chan struct{}
)

func profile() {
	var f *os.File
	var err error

	if cpuprofile != "" {
		f, err = os.Create(cpuprofile)
		if err != nil {
			sequence.StandardLogger{}.Fatal(err)
		}

		pprof.StartCPUProfile(f)
	}

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, os.Kill)
	go func() {
		select {
		case sig := <-sigchan:
			standardLogger.HandleInfo(fmt.Sprintf("Existing due to trapped signal; %v", sig))

		case <-quit:
			standardLogger.HandleInfo("Quiting...")

		}

		if f != nil {
			standardLogger.HandleError("Stopping profile")
			pprof.StopCPUProfile()
			f.Close()
		}

		close(done)
		os.Exit(0)
	}()
}

func start(){
	standardLogger = sequence.NewLogger(logfile)
	readConfig()
	validateInputs("analyze")
	profile()
}


func analyze(cmd *cobra.Command, args []string) {
	start()
	parser := buildParser()
	analyzer := sequence.NewAnalyzer()
	scanner := sequence.NewScanner()

	startTime := time.Now()

	//We load the file completely
	var lr []sequence.LogRecord
	lr = sequence.ReadLogRecord(infile, informat, lr, batchsize)

	//get the threshold for including the pattern in the
	//output files
	threshold := sequence.GetThreshold(len(lr))

	// For all the log messages, if we can't parse it, then let's add it to the
	// analyzer for pattern analysis, this requires the previous pattern file/folder
	//	to be passed in
	for _, r := range lr {
		//TODO Fix this so it doesn't scan twice or parse twice
		seq := scanMessage(scanner, r.Message)
		if _, err := parser.Parse(seq); err != nil {
			analyzer.Add(seq)
		}
	}
	analyzer.Finalize()

	//Uncomment this to sort the slice by the service
	//Useful for debugging
	syslog_ng.SortLogMessages(lr)

	//these are existing patterns
	pmap := make(map[string]struct {
		ex  string
		cnt int
		svc string
	})
	//these are the newly discovered patterns
	amap := make(map[string]sequence.AnalyzerResult)

	// Now that we have built the analyzer, let's go through each log message again
	// to determine the unique patterns
	err_count := 0
	processed := 0

	for _, l := range lr {
		//TODO Fix this so it doesn't scan twice or parse twice
		seq := scanMessage(scanner, l.Message)

		pseq, err := parser.Parse(seq)
		if err == nil {
			pat := strings.TrimSpace(pseq.String())
			stat, ok := pmap[pat]
			if !ok {
				stat = struct {
					ex  string
					cnt int
					svc string
				}{}
			}
			stat.ex = l.Message
			stat.cnt++
			stat.svc = l.Service
			pmap[pat] = stat
		} else {
			aseq, err := analyzer.Analyze(seq)
			if err != nil {
				standardLogger.LogAnalysisFailed(l)
				err_count++
			} else {
				pat := strings.TrimSpace(aseq.String())
				stat, ok := amap[pat]
				if !ok {
					stat = sequence.AnalyzerResult{}
				}
				sequence.AddExampleToAnalyzerResult(&stat, l, threshold)
				stat.PatternId = sequence.GenerateIDFromPattern(pat, stat.Examples[0].Service)
				stat.ExampleCount++
				amap[pat] = stat
			}
		}
		processed++
	}

	syslog_ng.SaveToDatabase(amap)

	standardLogger.HandleInfo(fmt.Sprintf("Analyzed %d messages, found %d unique patterns, %d are new. %d messages errored\n", len(lr), len(pmap)+len(amap), len(amap), err_count))
	anTime := time.Since(startTime)
	standardLogger.HandleInfo(fmt.Sprintf("Analysed in: %s\n", anTime))
}

func analyzebyservice(cmd *cobra.Command, args []string) {
	start()
	scanner := sequence.NewScanner()

	startTime := time.Now()
	lrMap := make(map[string] sequence.LogRecordCollection)
	var total = 0
	//We load the file completely
	total, lrMap = sequence.ReadLogRecordAsMap(infile, informat, lrMap, batchsize)

	if sequence.GetIncludeBelowThreshold(){
		//var reused = 0
		//TODO change to get these from the db
		//reused, lrMap = sequence.ReadLogRecordAsMap(sequence.GetBelowThresholdPath(), informat, lrMap, 0)
		//total += reused
	}

	//get the threshold for including the pattern in the
	//output files
	threshold := sequence.GetThreshold(total)

	//Here we group by service and process
	//We lose the cross service patterns but we get better
	//within service patterns
	err_count := 0
	processed := 0
	amap := make(map[string]sequence.AnalyzerResult)
	pmap := make(map[string]string)
	for svc, lrc := range lrMap{
		// For all the log messages, if we can't parse it, then let's add it to the
		// analyzer for pattern analysis, this requires the previous pattern file/folder
		//	to be passed in
		analyzer := sequence.NewAnalyzer()
		sid := sequence.GenerateIDFromService(svc)
		parser := buildParserFromDb(sid)
		for _, l := range lrc.Records {
			//TODO Fix this so it doesn't scan twice or parse twice
			seq := scanMessage(scanner, l.Message)
			_, err := parser.Parse(seq)
			if err != nil {
				analyzer.Add(seq)
			}
		}
		analyzer.Finalize()

		for _, l := range lrc.Records {
			seq := scanMessage(scanner, l.Message)
			pseq, err := parser.Parse(seq)
			if err == nil {
				pat := pseq.String()
				pmap[pat] = "found"
			}else {
				aseq, err := analyzer.Analyze(seq)
				if err != nil {
					standardLogger.LogAnalysisFailed(l)
					err_count++
				} else {
					pat := aseq.String()
					ar, ok := amap[pat]
					if !ok {
						ar = sequence.AnalyzerResult{}
					}
					sequence.AddExampleToAnalyzerResult(&ar, l, threshold)
					ar.PatternId = sequence.GenerateIDFromPattern(pat, ar.Examples[0].Service)
					ar.ExampleCount++
					amap[pat] = ar
				}
			}
			processed++
		}
		//fmt.Printf("Processed: %d\n", processed)
	}
	anTime := time.Since(startTime)
	standardLogger.HandleInfo(fmt.Sprintf("Analysed in: %s\n", anTime))

	syslog_ng.SaveToDatabase(amap)

	//debugging what is coming out as new
	oFile, _:= sequence.OpenOutputFile("C:\\data\\debug.txt")
	defer oFile.Close()
	for pat, stat := range amap {
		fmt.Fprintf(oFile, "%s\n# %d log messages matched\n# %s\n\n", pat, stat.ExampleCount, stat.Examples[0].Message)
	}

	standardLogger.HandleInfo(fmt.Sprintf("Analyzed %d messages, found %d unique patterns, %d are new. %d messages errored, time taken: %s", processed, len(amap)+len(pmap), len(amap), err_count, time.Since(startTime)))
}

func outputtofile(cmd *cobra.Command, args []string) {
	start()
	syslog_ng.OutputToFiles(outformat, outfile, parcfgfile)
}

func validateInputs(commandType string) {
	var errors string
	switch commandType {
	case "analyze":
		//set the formats to lower before we start
		informat = strings.ToLower(informat)
		outformat = strings.ToLower(outformat)

		//validate input file
		if infile == "" {
			errors = errors + "Invalid input file specified"
		}
		err := sequence.ValidateInformat(informat)
		if err != "" {
			errors = errors + ", " + err
		}
		err = sequence.ValidateOutformat(outformat)
		if err != "" {
			errors = errors + ", " + err
		}
		err = sequence.ValidateOutFormatWithFile(outfile, outformat)
		if err != "" {
			errors = errors + ", " + err
		}
		err = sequence.ValidateBatchSize(batchsize)
		if err != "" {
			errors = errors + ", " + err
		}
	case "outputtofiles":
		//set the formats to lower before we start
		outformat = strings.ToLower(outformat)
		err := sequence.ValidateOutformat(outformat)
		if err != "" {
			errors = errors + ", " + err
		}
		err = sequence.ValidateOutFormatWithFile(outfile, outformat)
		if err != "" {
			errors = errors + ", " + err
		}
	}
	if errors != ""{
		standardLogger.HandleFatal(errors)
	}
}


func scanMessage(scanner *sequence.Scanner, data string) sequence.Sequence {
	var (
		seq sequence.Sequence
		err error
	)

	if testJson(data){
		seq, err = scanner.ScanJson(data)
	} else {
		switch format {
		case "json":
			seq, err = scanner.ScanJson(data)

		default:
			seq, err = scanner.Scan(data, false)
		}
	}
	if err != nil {
		standardLogger.HandleFatal(err.Error())
	}
	return seq
}

func testJson(data string)bool{
	data = strings.TrimSpace(data)
	var js string
	if data[:1] == "{" && data[len(data)-1:] == "}"{
		//try to marshall the json
		return json.Unmarshal([]byte(data), &js) == nil
	}
	return false
}


func buildParser() *sequence.Parser {
	parser := sequence.NewParser()

	if patfile == "" {
		return parser
	}

	var files []string

	if fi, err := os.Stat(patfile); err != nil {
		standardLogger.HandleFatal(err.Error())
	} else if fi.Mode().IsDir() {
		files, err = sequence.GetDirOfFiles(patfile)
	} else {
		files = append(files, patfile)
	}

	scanner := sequence.NewScanner()

	for _, file := range files {
		// Open pattern file
		pscan, pfile, err:= sequence.OpenInputFile(file)
		defer pfile.Close()
		if err != nil {
			standardLogger.HandleFatal(err.Error())
		}

		for pscan.Scan() {
			line := pscan.Text()
			if len(line) == 0 || line[0] == '#' {
				continue
			}

			seq, err := scanner.Scan(line, true)
			if err != nil {
				standardLogger.HandleFatal(err.Error())
			}

			if err := parser.Add(seq); err != nil {
				standardLogger.HandleFatal(err.Error())
			}
		}
	}

	return parser
}

func buildParserFromDb(serviceid string) *sequence.Parser {
	parser := sequence.NewParser()
	scanner := sequence.NewScanner()
	db, ctx := sequence.OpenDbandSetContext()
	defer db.Close()
	//load all patterns from the database
	pmap := sequence.GetPatternsFromDatabaseByService(db, ctx, serviceid)

	for _, pat := range pmap {
		seq, err := scanner.Scan(pat, true)
		if err != nil {
			standardLogger.HandleFatal(err.Error())
		}

		if err := parser.Add(seq); err != nil {
			standardLogger.HandleFatal(err.Error())
		}
	}
	return parser
}


func readConfig() {
	if cfgfile == "" {
		cfgfile = "./sequence.toml"

		if _, err := os.Stat(cfgfile); err != nil {
			if slash := strings.LastIndex(os.Args[0], "/"); slash != -1 {
				cfgfile = os.Args[0][:slash] + "/sequence.toml"

				if _, err := os.Stat(cfgfile); err != nil {
					standardLogger.HandleFatal("No configuration file found")
				}
			}
		}
	}

	if err := sequence.ReadConfig(cfgfile); err != nil {
		standardLogger.HandleFatal(err.Error())
	}
	//set the logger for the sequence and syslog_ng modules
	sequence.SetLogger(standardLogger)
	syslog_ng.SetLogger(standardLogger)
}

func main() {
	quit = make(chan struct{})
	done = make(chan struct{})

	var (
		sequenceCmd = &cobra.Command{
			Use:   "sequence",
			Short: "sequence is a high performance sequential log analyzer and parser",
		}

		analyzeCmd = &cobra.Command{
			Use:   "analyze",
			Short: "analyzes a log file and output a list of patterns that will match all the log messages",
		}

		analyzeByServiceCmd = &cobra.Command{
			Use:   "analyzebyservice",
			Short: "analyzes a log file and output a list of patterns that will match all the log messages",
		}

		outToFileCmd = &cobra.Command{
			Use:   "outputtofile",
			Short: "outputs a list of patterns to the files in the formats requested",
		}
	)

	sequenceCmd.PersistentFlags().StringVarP(&cfgfile, "config", "", "", "TOML-formatted configuration file, default checks ./sequence.toml, then sequence.toml in the same directory as program")
	sequenceCmd.PersistentFlags().StringVarP(&infile, "input", "i", "", "input file, required, if - then stdin")
	sequenceCmd.PersistentFlags().StringVarP(&outfile, "output", "o", "", "output file, if omitted, to stdout, if multiple out-formats will use the same file name with diff extensions")
	sequenceCmd.PersistentFlags().StringVarP(&patfile, "patterns", "p", "", "existing patterns text file, can be a file or directory")
	sequenceCmd.PersistentFlags().StringVarP(&outformat, "out-format", "f", "", "format of the output file, can be yaml, xml or txt or a combo comma separated eg txt,xml, if empty it uses text, used by analyze")
	sequenceCmd.PersistentFlags().StringVarP(&informat, "in-format", "k", "", "format of the input data, can be json or text, if empty it uses text, used by analyze")
	sequenceCmd.PersistentFlags().IntVarP(&batchsize, "batch-size", "b", 0, "if using a large file or stdin, the batch size sets the limit of how many to process at one time")
	sequenceCmd.PersistentFlags().StringVarP(&logfile, "log-file", "l", "", "location of log file if different from the exe directory")
	sequenceCmd.PersistentFlags().StringVarP(&parcfgfile, "custom-parser-config", "c", "", "TOML-formatted configuration file, default checks ./custom_parser.toml, then custom_parser.toml in the same directory as program")

	analyzeCmd.Run = analyze
	analyzeByServiceCmd.Run = analyzebyservice
	outToFileCmd.Run = outputtofile

	sequenceCmd.AddCommand(analyzeCmd)
	sequenceCmd.AddCommand(analyzeByServiceCmd)
	sequenceCmd.AddCommand(outToFileCmd)

	sequenceCmd.Execute()
}
