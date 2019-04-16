package sequence

import (
	"encoding/xml"
	"fmt"
	"github.com/google/uuid"
	"log"
	"strconv"
)

//This represents a ruleset section in the sys-log ng yaml file
type XRuleset struct{
	ID string `xml:"id"`
	Name string `xml:"name"`
	Rules []XRule `xml:"rules"`
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
	TestMessage string `xml:"test_message"`
	TestValues []string `xml:"test_values"`
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
func ConvertToXml(pattern AnalyzerResult) string {
	//check if the pattern exists
	var rule XRule
	if !checkIfNew(pattern){
		rule = buildRuleXML(pattern)
	}
	// turn the rule into YAML format
	y, _ := xml.Marshal(rule)
	//add the id field
	fmt.Println(string(y))
	return string(y)
}

func buildRuleXML (result AnalyzerResult) XRule {
	var err error
	rule := XRule{}
	count := XRuleValue{Name:"seq-matches", Value: strconv.Itoa(result.ExampleCount)}
	rule.Values.Values = append(rule.Values.Values, count)
	new := XRuleValue{Name:"seq-new", Value: "true"}
	rule.Values.Values = append(rule.Values.Values, new)
	if err != nil {
		log.Fatal(err)
	}
	//remove the first two chars, TODO try to prevent them in the source file.
	if result.Example[0:2] == "# "{
		result.Example = result.Example[2:len(result.Example)]
	}
	var p XPattern
	var e XExample
	p.Pattern = replaceTags(result.Pattern)
	e.TestMessage = result.Example
	rule.Patterns = append(rule.Patterns, p)
	rule.Examples.Examples = append(rule.Examples.Examples, e)
	//create a new UUID
	rule.ID = uuid.Must(uuid.NewRandom()).String()
	return rule
}

