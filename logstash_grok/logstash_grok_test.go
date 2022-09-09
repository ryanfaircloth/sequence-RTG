package logstash_grok

import (
	"testing"

	"github.com/ryanfaircloth/sequence-RTG/sequence"
	"github.com/stretchr/testify/require"
)

var (
	tagtests = []struct {
		data   string
		result string
	}{
		{"%object% ", "%{DATA:object}"},
		{"%object%,", "%{DATA:object},"},
		{"%object%:", "%{DATA:object}:"},
		{"%object%:%string% ", "%{DATA:object}:%{DATA:string}"},
		{"%srcip%,", "%{IP:srcip},"},
		{"%srcip%", "%{IP:srcip}"},
		{"%ipv6%:", "%{IP:ipv6}:"},
		{"%integer% ", "%{INT:integer}"},
		{"%string%,%string%", "%{DATA:string},%{DATA:string1}"},
		{"%srcmac%", "%{MAC:srcmac}"},
		{"%srchost% ", "%{HOSTNAME:srchost}"},
		{"<%string%>,", "<%{DATA:string}>,"},
		{"%multiline%", "%{GREEDYDATA:multiline}"},
	}
)

func loadConfigs() {
	file := "../sequence.toml"
	readConfig(file)
	sequence.ReadConfig(file)
}

func TestTagTransformation(t *testing.T) {
	loadConfigs()
	for _, tc := range tagtests {
		tag := replaceTags(tc.data)
		require.Equal(t, tc.result, tag, tc.data)
	}
}
