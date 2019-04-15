package sequence

import (
	"fmt"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"log"
	"strconv"
	"strings"
)

var syslog_ng = map[string]string{
	"%string%":"@STRING@",
	"%srcemail%":"@EMAIL@",
	"%float%":"@FLOAT@",
	"%integer%":"@NUMBER@",
	"%srcip%":"@IPvANY@",
	"%msgtime%":"@ANYSTRING@",
	"%protocol%":"@IPvANY@",
}

type Pattern struct {
	Pattern string
	ExampleCount string
	Example string
}

type Rule struct{
	Details RuleDetails
}

//This represents a rule section in the sys-log ng yaml file
type RuleDetails struct{
	Ruleset string `yaml:"ruleset"`
	Seqmatches int `yaml:"seq-matches"`
	Patterns []string `yaml:"patterns"`
	Examples []string `yaml:"examples"`
}

//This represents a ruleset section in the sys-log ng yaml file
type Ruleset struct{
	ID string
	Pubdate string
	Parser int
}

//This method takes the path to the file output by the analyzer as in and
//converts it to Yaml and saves in the out path.
func ConvertToYaml(pattern Pattern) {
	//check if the pattern exists
	var rule Rule
	if !checkIfNew(pattern){
		rule = buildRule(pattern)
	}
	// turn the rule into YAML format
	y, _ := yaml.Marshal(rule)
	//add the id field
	AddIdField(string(y))
}

//for syslog-ng we need to customise how the rule id
//is represented, easier to modify this small part than
//to build a complete custom Marshal function
func AddIdField(y string) string{
	//s := strings.Split(y,"\n")
	//remove the id: qualifier
	//create a new UUID
	id := uuid.Must(uuid.NewRandom()).String()
	//remove the details header
	y = strings.Replace(y, "details", id, 1)
	fmt.Println(y)
	return y
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

func buildRule (pattern Pattern) Rule{
	var err error
	rule := Rule{}
	// get the example count from the string
	s := strings.Fields(pattern.ExampleCount)
	rule.Details.Seqmatches, err = strconv.Atoi(s[1])
	if err != nil {
		log.Fatal(err)
	}
	//remove the first two chars, TODO try to prevent them in the source file.
	if pattern.Example[0:2] == "# "{
		pattern.Example = pattern.Example[2:len(pattern.Example)]
	}
	//get the ruleset from the example (first string)
	s = strings.Fields(pattern.Example)
	rule.Details.Ruleset =	s[0]
	rule.Details.Patterns = append(rule.Details.Patterns, replaceTags(pattern.Pattern))
	rule.Details.Examples = append(rule.Details.Examples, pattern.Example)
	return rule
}

func checkIfNew(pattern Pattern) bool {
	return false
}

//convert each pattern, check if it exists, ignore if yes, add if no
//do a formatting check
//if ok save a new file, else rename _old and send alert
//auto check in to repo ?

