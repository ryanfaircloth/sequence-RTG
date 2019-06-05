package syslog_ng

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
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
	Program string 				 `yaml:"program"`
	TestMessage string 			 `yaml:"test_message"`
	TextValues map[string]string `yaml:"test_values"`
}

func SaveAsYaml(oFile *os.File, db YPatternDB) error {
	//check if the pattern exists
	// turn the rule into YAML format
	en := yaml.NewEncoder(oFile)
	en.SetIndent(2)
	y := en.Encode(db)
	return y
}

func AddToYaml(pattern sequence.AnalyzerResult, db YPatternDB) YPatternDB{
	//do we have a special case where it belongs to more that one service
	rsName := pattern.Services[0].Name
	rsID := pattern.Services[0].ID
	if len(pattern.Services) > 1{
		rsName, rsID = CreateRulesetName(pattern.Services)
	}
	//look in the ruleset if it exists already
	_, ok := db.Rulesets[rsName]
	if !ok {
		rs := buildRuleset(pattern,rsID)
		db.Rulesets[rsName] = rs
	}

	//every pattern should be unique
	r := buildRule(pattern, rsName)
	db.Rules[r.ID] = r


	return db
}

func buildRule (result sequence.AnalyzerResult, rsName string) YRule {
	rule := YRule{}
	rule.Values.Seqmatches = result.ExampleCount
	//get the ruleset from the example (service)
	rule.Ruleset = rsName
	rule.Patterns = append(rule.Patterns, replaceTags(result.Pattern))
	for _, ex := range result.Examples {
		m, err := ExtractTestValuesForTokens(ex.Message, result)
		if err != nil{
			//make an empty map, log an error and continue
			m = make(map[string]string)
			logger.HandleError(fmt.Sprintf("Unable to make test_values map for examples for pattern %s", result.PatternId))
		}
		example := YRuleExample{ex.Service, ex.Message, m}
		rule.Examples = append(rule.Examples, example)
	}
	rule.Values.New = true
	rule.Values.DateCreated = result.DateCreated.Format("2006-01-02")
	rule.Values.DateLastMatched = result.DateLastMatched.Format("2006-01-02")
	//create a new UUID
	rule.ID = result.PatternId
	return rule
}

func buildRuleset (result sequence.AnalyzerResult, rsID string) YRuleset {
	rs := YRuleset{}
	rs.Pubdate = time.Now().Format("2006-01-02")
	//get the ruleset from the example (service)
	rs.Parser =	"sequence"
	for _, s := range result.Services{
		rs.Patterns = append(rs.Patterns, s.Name)
	}
	//create a new UUID
	rs.ID = rsID
	return rs
}


