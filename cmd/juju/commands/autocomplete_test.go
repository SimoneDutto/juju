// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package commands

import (
	"bytes"
	"testing"

	"github.com/juju/tc"

	"github.com/juju/juju/cmd/cmd/cmdtesting"
	"github.com/juju/juju/internal/testhelpers"
)

type AutocompleteSuite struct {
	testhelpers.IsolationSuite
}

func TestAutocompleteSuite(t *testing.T) {
	tc.Run(t, &AutocompleteSuite{})
}

func (s *AutocompleteSuite) TestBash(c *tc.C) {
	command := newAutocompleteCommand()
	cctx, err := cmdtesting.RunCommand(c, command, "bash")
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(cctx.Stdout.(*bytes.Buffer).String(), tc.Equals, bashAutocompleteScript)
	c.Assert(cctx.Stderr.(*bytes.Buffer).String(), tc.Equals, "")
}

func (s *AutocompleteSuite) TestMissingShell(c *tc.C) {
	command := newAutocompleteCommand()
	_, err := cmdtesting.RunCommand(c, command)
	c.Assert(err, tc.ErrorMatches, "missing shell argument")
}

func (s *AutocompleteSuite) TestUnsupportedShell(c *tc.C) {
	command := newAutocompleteCommand()
	_, err := cmdtesting.RunCommand(c, command, "zsh")
	c.Assert(err, tc.ErrorMatches, "unsupported shell \"zsh\"")
}
