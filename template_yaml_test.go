package sequence

import(
	"testing"
)

var pattern1 = Pattern{"%string% %string% : %integer% : message has been queued for %integer% %srcuser%",
	1010,"#postfix/pickup warning: 635541320: message has been queued for 20 days"}


func TestYAMLConversion(t *testing.T){
//read the pattern text into the struct
//parse to the YAML converter
//

}

//need tests for a newly found pattern
//and matching an existing one