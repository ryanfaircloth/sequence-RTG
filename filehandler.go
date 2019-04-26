package sequence

import (
	"bufio"
	"compress/gzip"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func GetDirOfFiles(path string) []string {
	filenames := make([]string, 0, 10)

	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		filenames = append(filenames, path+"/"+f.Name())
	}

	return filenames
}

func OpenInputFile(fname string) (*bufio.Scanner, *os.File) {
	var s *bufio.Scanner
	f, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}

	if strings.HasSuffix(fname, ".gz") {
		gunzip, err := gzip.NewReader(f)
		if err != nil {
			log.Fatal(err)
		}

		s = bufio.NewScanner(gunzip)
	} else {
		s = bufio.NewScanner(f)
	}

	return s, f
}

func OpenOutputFile(fname string) *os.File {
	var (
		ofile *os.File
		err   error
	)

	if fname == "" {
		ofile = os.Stdin
	} else {
		// Open output file
		ofile, err = os.OpenFile(fname, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
	}

	return ofile
}


