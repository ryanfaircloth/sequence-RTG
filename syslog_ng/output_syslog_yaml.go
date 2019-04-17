package syslog_ng

import (
	"gopkg.in/yaml.v3"
	"log"
	"sequence"
	"strings"
)

type YRule struct{
	Details YRuleDetails `yaml:"details"`
}

//This represents a rule section in the sys-log ng yaml file
type YRuleDetails struct{
	Ruleset  string      `yaml:"ruleset"`
	Patterns []string    `yaml:"patterns"`
	Examples []string    `yaml:"examples"`
	Values   YRuleValues `yaml:"values"`
	ID       string      `yaml:"id,omitempty"`
}

type YRuleValues struct {
	Seqmatches int `yaml:"seq-matches"`
	New bool `yaml:"seq-new"`
}

//This represents a ruleset section in the sys-log ng yaml file
type YRuleset struct{
	ID string
	Pubdate string
	Parser int
}

//This method takes the path to the file output by the analyzer as in and
//converts it to Yaml and saves in the out path.
func ConvertToYaml(pattern sequence.AnalyzerResult) string {
	//check if the pattern exists
	var rule YRule
	if !checkIfNew(pattern){
		rule = buildRule(pattern)
	}
	// turn the rule into YAML format
	y, _ := yaml.Marshal(rule)
	//add the id field
	x := AddIdField(string(y), rule.Details.ID)
	return x
}

//for syslog-ng we need to customise how the rule id
//is represented, easier to modify this small part than
//to build a complete custom Marshal function
func AddIdField(y string, id string) string{
	//s := strings.Split(y,"\n")
	//remove the id: qualifier
	//remove the details header
	y = strings.Replace(y, "details", id, 1)
	return y
}

func buildRule (result sequence.AnalyzerResult) YRule {
	var err error
	rule := YRule{}
	rule.Details.Values.Seqmatches = result.ExampleCount
	if err != nil {
		log.Fatal(err)
	}
	//get the ruleset from the example (first string)
	s := strings.Fields(result.Example)
	rule.Details.Ruleset =	s[0]
	rule.Details.Patterns = append(rule.Details.Patterns, replaceTags(result.Pattern))
	rule.Details.Examples = append(rule.Details.Examples, result.Example)
	rule.Details.Values.New = true
	//create a new UUID
	rule.Details.ID = generateIDFromPattern(result.Pattern)
	return rule
}



//convert each pattern, check if it exists, ignore if yes, add if no
//do a formatting check
//if ok save a new file, else rename _old and send alert
//auto check in to repo ?

