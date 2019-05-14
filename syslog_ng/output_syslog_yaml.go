package syslog_ng

import (
	"gopkg.in/yaml.v3"
	"log"
	"sequence"
	"time"
)

type YPatternDB struct{
	Rules map[string]YRule `yaml:"coloss::patterndb::simple::rule"`
	Rulesets map[string]YRuleset `yaml:"coloss::patterndb::simple::ruleset"`
}

//This represents a rule section in the sys-log ng yaml file
type YRule struct{
	Ruleset  string      		`yaml:"ruleset"`
	Patterns []string    		`yaml:"patterns"`
	Examples []YRuleExample   	`yaml:"examples"`
	Values   YRuleValues 		`yaml:"values"`
	ID       string      		`yaml:"id,omitempty"`
}

type YRuleValues struct {
	Seqmatches int 				`yaml:"seq-matches"`
	New bool 					`yaml:"seq-new"`
	DateCreated string 			`yaml:"seq-created"`
	DateLastMatched string 		`yaml:"seq-last-match"`
}

//This represents a ruleset section in the sys-log ng yaml file
type YRuleset struct{
	Pubdate string
	ID string					`yaml:"id,omitempty"`
	Parser string
	Patterns []string    		`yaml:"patterns"`
}

type YRuleExample struct {
	Program string 				`yaml:"program"`
	TestMessage string 			`yaml:"test-message"`
}

func ConvertToYaml(db YPatternDB) string {
	//check if the pattern exists
	// turn the rule into YAML format
	y, _ := yaml.Marshal(db)
	return string(y)
}

func AddToYaml(pattern sequence.AnalyzerResult, db YPatternDB) YPatternDB{
	//every pattern should be unique
	r := buildRule(pattern)
	db.Rules[r.ID] = r

	//look in the ruleset if it exists already
	rsName := pattern.Examples[0].Service
	_, ok := db.Rulesets[rsName]
	if !ok {
		rs := buildRuleset(pattern)
		db.Rulesets[rsName] = rs
	}
	return db
}

func buildRule (result sequence.AnalyzerResult) YRule {
	var err error
	rule := YRule{}
	rule.Values.Seqmatches = result.ExampleCount
	if err != nil {
		log.Fatal(err)
	}
	//get the ruleset from the example (service)
	rule.Ruleset =	result.Examples[0].Service
	rule.Patterns = append(rule.Patterns, replaceTags(result.Pattern))
	for _, ex := range result.Examples {
		example := YRuleExample{ex.Service, ex.Message}
		rule.Examples = append(rule.Examples, example)
	}
	rule.Values.New = true
	rule.Values.DateCreated = result.DateCreated.Format("2006-01-02")
	//TODO: Update when date last matched is logging
	rule.Values.DateLastMatched = time.Now().Format("2006-01-02")
	//create a new UUID
	rule.ID = result.PatternId
	return rule
}

func buildRuleset (result sequence.AnalyzerResult) YRuleset {
	rs := YRuleset{}
	rs.Pubdate = time.Now().Format("2006-01-02")
	//get the ruleset from the example (service)
	rs.Parser =	"sequence"
	rsName := result.Examples[0].Service
	rs.Patterns = append(rs.Patterns, rsName)
	//create a new UUID
	rs.ID = sequence.GenerateIDFromService(rsName)
	return rs
}


