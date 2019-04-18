package syslog_ng

import (
	"github.com/stretchr/testify/require"
	"testing"
)


func TestIDCreation(t *testing.T){
	//test that the same string creates the same id in SHA1
	str1 := "this is a short string that is has some @ # ! // chars, [] and other THINGS 345% that should always generate the same sha1"
	sha := generateIDFromPattern(str1)
	require.Equal(t, "6759b5871e72c8881997d35416142ab3ef4083f5", sha)

}

//need tests for a newly found pattern
//and matching an existing one
