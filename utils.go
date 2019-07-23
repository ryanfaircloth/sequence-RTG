package sequence

import (
	"encoding/json"
	"math"
	"os"
	"strconv"
	"strings"
)

func ScanMessage(scanner *Scanner, data string, format string) (Sequence, error) {
	var (
		seq Sequence
		err error
		pos []int
	)

	if testJson(data) {
		seq, err = scanner.ScanJson_Preserve(data)
	} else {
		switch format {
		case "json":
			seq, err = scanner.ScanJson(data)

		default:
			seq, err = scanner.Scan(data, false, pos)
		}
	}
	return seq, err
}

func testJson(data string) bool {
	data = strings.TrimSpace(data)
	var js interface{}
	if data[:1] == "{" && data[len(data)-1:] == "}" {
		//try to marshall the json
		x := json.Unmarshal([]byte(data), &js)
		return x == nil
	}
	return false
}

func BuildParser(patfile string) *Parser {
	parser := NewParser()

	if patfile == "" {
		return parser
	}

	var files []string
	var pos []int

	if fi, err := os.Stat(patfile); err != nil {
		logger.HandleFatal(err.Error())
	} else if fi.Mode().IsDir() {
		files, err = GetDirOfFiles(patfile)
	} else {
		files = append(files, patfile)
	}

	scanner := NewScanner()

	for _, file := range files {
		// Open pattern file
		pscan, pfile, err := OpenInputFile(file)
		defer pfile.Close()
		if err != nil {
			logger.HandleFatal(err.Error())
		}

		for pscan.Scan() {
			line := pscan.Text()
			if len(line) == 0 || line[0] == '#' {
				continue
			}

			seq, err := scanner.Scan(line, true, pos)
			if err != nil {
				logger.HandleError(err.Error())
			}

			if err := parser.Add(seq); err != nil {
				logger.HandleError(err.Error())
			}
		}
	}

	return parser
}

func BuildParserFromDb(serviceid string) *Parser {
	parser := NewParser()
	scanner := NewScanner()
	db, ctx := OpenDbandSetContext()
	defer db.Close()
	//load all patterns from the database
	pmap := GetPatternsFromDatabaseByService(db, ctx, serviceid)
	for _, ar := range pmap {
		pos := SplitToInt(ar.TagPositions, ",")
		seq, err := scanner.Scan(ar.Pattern, true, pos)
		if err != nil {
			logger.HandleError(err.Error())
		}

		if err := parser.Add(seq); err != nil {
			logger.HandleError(err.Error())
		}
	}
	return parser
}

//Calculate the threshold value to use when exporting patterns from the database.
func getThreshold(numTotal int) int {
	t := config.matchThresholdType
	if t == "count" {
		tr, err := strconv.Atoi(config.matchThresholdValue)
		if err != nil {
			return 0
		} else {
			return tr
		}
	} else {
		f, err := strconv.ParseFloat(config.matchThresholdValue, 64)
		if err != nil {
			return 0
		} else {
			total := float64(numTotal)
			t := f * total
			tr := int(math.Floor(t))
			return tr
		}
	}
	return 0
}
