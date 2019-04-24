package syslog_ng

import (
	"encoding/xml"
	"log"
	"sequence"
	"strconv"
)

//This represents a ruleset section in the sys-log ng yaml file
type PatternDB struct{
	XMLName  xml.Name `xml:"patterndb"`
	Version string `xml:"version,attr"`
	Pubdate string `xml:"pub_date,attr"`
	Rulesets []XRuleset `xml:"ruleset"`
}

//This represents a ruleset section in the sys-log ng yaml file
type XRuleset struct{
	ID string `xml:"id,attr"`
	Name string `xml:"name,attr"`
	Patterns []XPattern  `xml:"patterns"`
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
	TestValues []string `xml:"test_values"`
}

type XTestMessage struct {
	XMLName  xml.Name `xml:"test_message"`
	TestMessage string `xml:",chardata"`
	Program string `xml:"program,attr"`
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
func ConvertToXml(document PatternDB) string {
	// turn the document into XML format
	y, _ := xml.MarshalIndent(document, "  ", "   ")
	return string(y)
}

func AddToRuleset(pattern sequence.AnalyzerResult, document PatternDB) PatternDB {
	//build the rule as XML
	rule := buildRuleXML(pattern)
	//get the ruleset name for the example
	//it will be the service value
	rsName := pattern.Service
	found := false
	//look in the ruleset if it exists already
	for i, rls := range document.Rulesets {
		if rls.Name == rsName {
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
		rs := buildRulesetXML(rsName)
		//add the rule
		rs.Rules.Rules = append(rs.Rules.Rules, rule)
		//add the ruleset
		document.Rulesets = append(document.Rulesets, rs)
	}
	return document
}

func buildRuleXML (result sequence.AnalyzerResult) XRule {
	var err error
	rule := XRule{}
	count := XRuleValue{Name:"seq-matches", Value: strconv.Itoa(result.ExampleCount)}
	rule.Values.Values = append(rule.Values.Values, count)
	new := XRuleValue{Name:"seq-new", Value: "true"}
	rule.Values.Values = append(rule.Values.Values, new)
	if err != nil {
		log.Fatal(err)
	}
	var p XPattern
	var e XExample
	var t XTestMessage
	t.TestMessage = result.Example
	t.Program = result.Service
	p.Pattern = replaceTags(result.Pattern)
	e.TestMessage = t
	rule.Patterns = append(rule.Patterns, p)
	rule.Examples.Examples = append(rule.Examples.Examples, e)
	//create a new UUID
	rule.ID = generateIDFromPattern(result.Pattern)
	return rule
}

func buildRulesetXML (rsName string) XRuleset {
	rs := XRuleset{Name:rsName}
	rs.ID = generateIDFromPattern(rsName)
	var p = XPattern{Pattern:rsName}
	rs.Patterns = append(rs.Patterns, p)
	return rs
}



