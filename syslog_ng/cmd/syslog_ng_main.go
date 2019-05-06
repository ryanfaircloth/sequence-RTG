package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/surge/glog"
	"log"
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
	outformat  string
	informat  string
	patfile    string
	cpuprofile string
	workers    int
	format     string

	quit chan struct{}
	done chan struct{}
)

func profile() {
	var f *os.File
	var err error

	if cpuprofile != "" {
		f, err = os.Create(cpuprofile)
		if err != nil {
			log.Fatal(err)
		}

		pprof.StartCPUProfile(f)
	}

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, os.Kill)
	go func() {
		select {
		case sig := <-sigchan:
			log.Printf("Existing due to trapped signal; %v", sig)

		case <-quit:
			log.Println("Quiting...")

		}

		if f != nil {
			glog.Errorf("Stopping profile")
			pprof.StopCPUProfile()
			f.Close()
		}

		close(done)
		os.Exit(0)
	}()
}


func analyze(cmd *cobra.Command, args []string) {
	readConfig()
	if infile == "" {
		log.Fatal("Invalid input file specified")
	}
	informat = strings.ToLower(informat)
	err := sequence.ValidateInformat(informat)
	if err != "" {
		log.Fatal(err)
	}
	outformat = strings.ToLower(outformat)
	err = sequence.ValidateOutformat(outformat)
	if err != "" {
		log.Fatal(err)
	}
	profile()
	parser := buildParser()
	analyzer := sequence.NewAnalyzer()
	scanner := sequence.NewScanner()

	startTime := time.Now()

	//We load the file completely
	var lr []sequence.LogRecord
	lr = sequence.ReadLogRecord(infile, informat, lr)

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
				sequence.LogAnalysisFailed(l)
				err_count++
			} else {
				pat := strings.TrimSpace(aseq.String())
				stat, ok := amap[pat]
				if !ok {
					stat = sequence.AnalyzerResult{}
				}
				sequence.AddExampleToAnalyzerResult(&stat, l, threshold)
				stat.PatternId = sequence.GenerateIDFromPattern(pat)
				stat.ExampleCount++
				amap[pat] = stat
			}
		}
		processed++
	}

	val := syslog_ng.SaveToOutputFiles(informat, outformat, outfile, amap)

	log.Printf("Analyzed %d messages, found %d unique patterns, %d are new. %d passed the threshold and were added to the xml/yaml file, %d messages errored\n", len(lr), len(pmap)+len(amap), len(amap), val, err_count)
	anTime := time.Since(startTime)
	fmt.Printf("Analysed in: %s\n", anTime)
}

func analyzebyservice(cmd *cobra.Command, args []string) {
	readConfig()
	if infile == "" {
		log.Fatal("Invalid input file specified")
	}
	informat = strings.ToLower(informat)
	err := sequence.ValidateInformat(informat)
	if err != "" {
		log.Fatal(err)
	}
	outformat = strings.ToLower(outformat)
	err = sequence.ValidateOutformat(outformat)
	if err != "" {
		log.Fatal(err)
	}
	profile()
	parser := buildParser()
	analyzer := sequence.NewAnalyzer()
	scanner := sequence.NewScanner()

	startTime := time.Now()
	lrMap := make(map[string] sequence.LogRecordCollection)
	var total = 0
	//We load the file completely
	total, lrMap = sequence.ReadLogRecordAsMap(infile, informat, lrMap)

	if sequence.GetIncludeBelowThreshold() && len(sequence.GetBelowThresholdPath()) > 0{
		var reused = 0
		reused, lrMap = sequence.ReadLogRecordAsMap(sequence.GetBelowThresholdPath(), informat, lrMap)
		total += reused
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
	for _, lrc := range lrMap{
		// For all the log messages, if we can't parse it, then let's add it to the
		// analyzer for pattern analysis, this requires the previous pattern file/folder
		//	to be passed in
		analyzer = sequence.NewAnalyzer()
		for _, l := range lrc.Records {
			//TODO Fix this so it doesn't scan twice or parse twice
			seq := scanMessage(scanner, l.Message)
			if _, err := parser.Parse(seq); err != nil {
				analyzer.Add(seq)
			}
		}
		analyzer.Finalize()

		for _, l := range lrc.Records {
			seq := scanMessage(scanner, l.Message)
			aseq, err := analyzer.Analyze(seq)
			if err != nil {
				sequence.LogAnalysisFailed(l)
				err_count++
			} else {
				pat := strings.TrimSpace(aseq.String())
				ar, ok := amap[pat]
				if !ok {
					ar = sequence.AnalyzerResult{}
				}
				sequence.AddExampleToAnalyzerResult(&ar, l, threshold)
				ar.PatternId = sequence.GenerateIDFromPattern(pat)
				ar.ExampleCount++
				amap[pat] = ar
			}
			processed++
		}
		//fmt.Printf("Processed: %d\n", processed)
	}
	anTime := time.Since(startTime)
	fmt.Printf("Analysed in: %s\n", anTime)

	val := syslog_ng.SaveToOutputFiles(informat, outformat, outfile, amap)

	log.Printf("Analyzed %d messages, found %d unique patterns, %d are new. %d passed the threshold, %d messages errored, time taken: %s", processed, len(amap), len(amap), val, err_count, time.Since(startTime))
}

func scanMessage(scanner *sequence.Scanner, data string) sequence.Sequence {
	var (
		seq sequence.Sequence
		err error
	)

	switch format {
	case "json":
		seq, err = scanner.ScanJson(data)

	default:
		seq, err = scanner.Scan(data)
	}

	if err != nil {
		log.Fatal(err)
	}
	return seq
}

func buildParser() *sequence.Parser {
	parser := sequence.NewParser()

	if patfile == "" {
		return parser
	}

	var files []string

	if fi, err := os.Stat(patfile); err != nil {
		log.Fatal(err)
	} else if fi.Mode().IsDir() {
		files = sequence.GetDirOfFiles(patfile)
	} else {
		files = append(files, patfile)
	}

	scanner := sequence.NewScanner()

	for _, file := range files {
		// Open pattern file
		pscan, pfile := sequence.OpenInputFile(file)

		for pscan.Scan() {
			line := pscan.Text()
			if len(line) == 0 || line[0] == '#' {
				continue
			}

			seq, err := scanner.Scan(line)
			if err != nil {
				log.Fatal(err)
			}

			if err := parser.Add(seq); err != nil {
				log.Fatal(err)
			}
		}

		pfile.Close()
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
					log.Fatalln("No configuration file found")
				}
			}
		}
	}

	if err := sequence.ReadConfig(cfgfile); err != nil {
		log.Fatal(err)
	}
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
	)

	sequenceCmd.PersistentFlags().StringVarP(&cfgfile, "config", "", "", "TOML-formatted configuration file, default checks ./sequence.toml, then sequence.toml in the same directory as program")
	sequenceCmd.PersistentFlags().StringVarP(&infile, "input", "i", "", "input file, required, if - then stdin")
	sequenceCmd.PersistentFlags().StringVarP(&outfile, "output", "o", "", "output file, if omitted, to stdout, if multiple out-formats will use the same file name with diff extensions")
	sequenceCmd.PersistentFlags().StringVarP(&patfile, "patterns", "p", "", "existing patterns text file, can be a file or directory")
	sequenceCmd.PersistentFlags().StringVarP(&outformat, "out-format", "f", "", "format of the output file, can be yaml, xml or txt or a combo comma separated eg txt,xml, if empty it uses text, used by analyze")
	sequenceCmd.PersistentFlags().StringVarP(&informat, "in-format", "k", "", "format of the input data, can be json or text, if empty it uses text, used by analyze")

	analyzeCmd.Run = analyze
	analyzeByServiceCmd.Run = analyzebyservice

	sequenceCmd.AddCommand(analyzeCmd)
	sequenceCmd.AddCommand(analyzeByServiceCmd)

	sequenceCmd.Execute()
}
