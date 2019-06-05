package syslog_ng

import (
	"encoding/xml"
	"fmt"
	"sequence"
	"sequence/models"
	"strconv"
)

//This represents a ruleset section in the sys-log ng yaml file
type XPatternDB struct{
	XMLName  xml.Name `xml:"patterndb"`
	Version string `xml:"version,attr"`
	Pubdate string `xml:"pub_date,attr"`
	Rulesets []XRuleset `xml:"ruleset"`
}

//This represents a ruleset section in the sys-log ng yaml file
type XRuleset struct{
	ID string `xml:"id,attr"`
	Name string `xml:"name,attr"`
	Patterns XPatterns  `xml:"patterns"`
	Rules XRules `xml:"rules"`
}

//this is needed for the xml to format properly
type XRules struct {
	Rules []XRule `xml:"rule"`
}

//This represents a rule section in the sys-log ng yaml file
type XRule struct{
	XMLName  xml.Name `xml:"rule"`
	Patterns []XPattern  `xml:"patterns"`
	Examples XExamples  `xml:"examples"`
	Values   XRuleValues `xml:"values"`
	ID       string      `xml:"id,attr"`
}

//this is needed for the xml to format properly
type XPatterns struct {
	Patterns []string `xml:"pattern"`
}

type XPattern struct {
	Pattern string `xml:"pattern"`
}

//this is needed for the xml to format properly
type XExamples struct {
	Examples []XExample `xml:"example"`
}

type XExample struct {
	XMLName  xml.Name `xml:"example"`
	TestMessage XTestMessage `xml:"test_message"`
	TestValues XTestValues `xml:"test_values"`
}

type XTestValues struct{
	Values []XTestValue `xml:"test_values"`
}

type XTestMessage struct {
	XMLName  xml.Name `xml:"test_message"`
	TestMessage string `xml:",chardata"`
	Program string `xml:"program,attr"`
}

type XTestValue struct {
	XMLName  xml.Name `xml:"test_value"`
	Value string `xml:",chardata"`
	Key	string `xml:"name,attr"`
}

type XRuleValues struct {
	Values [] XRuleValue `xml:"values"`
}

type XRuleValue struct {
	XMLName  xml.Name `xml:"value"`
	Name string `xml:"name,attr"`
	Value string `xml:",chardata"`
}


//This method takes the path to the file output by the analyzer as in and
//converts it to Yaml and saves in the out path.
func ConvertToXml(document XPatternDB) string {
	// turn the document into XML format
	y, _ := xml.MarshalIndent(document, "  ", "   ")
	return string(y)
}

func AddToRuleset(pattern sequence.AnalyzerResult, document XPatternDB) XPatternDB {
	//build the rule as XML
	rule := buildRuleXML(pattern)
	//get the ruleset name for the example
	//it will be the service value
	rs := pattern.Services[0].Name
	rsID := pattern.Services[0].ID
	if len(pattern.Services) > 1{
		rs, rsID = CreateRulesetName(pattern.Services)
	}
	found := false
	//look in the ruleset if it exists already
	for i, rls := range document.Rulesets {
		if rls.Name == rs {
			// found, so add the new rule
			rls.Rules.Rules = append(rls.Rules.Rules, rule)
			//remove the old ruleset
			document.Rulesets = append(document.Rulesets[:i], document.Rulesets[i+1:]...)
			//re-add the updated ruleset
			document.Rulesets = append(document.Rulesets, rls)
			found = true
			break
		}
	}
	//if not found make a new ruleset
	if !found {
		//create the ruleset
		rs := buildRulesetXML(rsID, rs, pattern.Services)
		//add the rule
		rs.Rules.Rules = append(rs.Rules.Rules, rule)
		//add the ruleset
		document.Rulesets = append(document.Rulesets, rs)
	}
	return document
}

func buildRuleXML (result sequence.AnalyzerResult) XRule {
	rule := XRule{}
	count := XRuleValue{Name:"seq-matches", Value: strconv.Itoa(result.ExampleCount)}
	rule.Values.Values = append(rule.Values.Values, count)
	new := XRuleValue{Name:"seq-new", Value: "true"}
	rule.Values.Values = append(rule.Values.Values, new)
	dc := XRuleValue{Name:"seq-created", Value: result.DateCreated.Format("2006-01-02")}
	rule.Values.Values = append(rule.Values.Values, dc)
	dlm := XRuleValue{Name:"seq-last-match", Value: result.DateLastMatched.Format("2006-01-02")}
	rule.Values.Values = append(rule.Values.Values, dlm)
	var p XPattern
	var e XExample
	var t XTestMessage
	for _, ex := range result.Examples{
		e = XExample{}
		t.TestMessage = ex.Message
		t.Program = ex.Service
		e.TestMessage = t
		m, err := ExtractTestValuesForTokens(ex.Message, result)
		if err != nil{
			logger.HandleError(fmt.Sprintf("Unable to make test_values map for examples for pattern %s", result.PatternId))
		}else{
			for key, val := range m{
				e.TestValues.Values = append(e.TestValues.Values, XTestValue{Key:key, Value:val})
			}
		}
		rule.Examples.Examples = append(rule.Examples.Examples, e)
	}
	p.Pattern = replaceTags(result.Pattern)
	rule.Patterns = append(rule.Patterns, p)

	//create a new UUID
	rule.ID = result.PatternId
	return rule
}

func buildRulesetXML (rsID string, rsName string, slice models.ServiceSlice) XRuleset {
	rs := XRuleset{Name:rsName, ID:rsID}
	for _, s := range slice{
		rs.Patterns.Patterns = append(rs.Patterns.Patterns, s.Name)
	}
	return rs
}



