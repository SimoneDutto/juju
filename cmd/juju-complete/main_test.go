package main

import (
	"testing"

	"github.com/juju/tc"
)

type mainSuite struct{}

func TestMainSuite(t *testing.T) {
	tc.Run(t, &mainSuite{})
}

func (s *mainSuite) TestDescribeInvocation(c *tc.C) {
	got := describeInvocation("bash", 3, "", 120, []string{"juju", "status", "--model"}, []string{"--shell", "bash", "--", "juju", "status", "--model"})
	want := "juju-complete debug input\n" +
		"shell=\"bash\"\n" +
		"position=3\n" +
		"dump_script=\"\"\n" +
		"ttl=120\n" +
		"raw_args=[\"--shell\" \"bash\" \"--\" \"juju\" \"status\" \"--model\"]\n" +
		"words=[\"juju\" \"status\" \"--model\"]\n"

	c.Assert(got, tc.Equals, want)
}
