// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package docker_test

import (
	"testing"

	"github.com/juju/tc"

	"github.com/juju/juju/core/docker"
)

type importSuite struct{}

func TestImportSuite(t *testing.T) {
	tc.Run(t, &importSuite{})
}

func (*importSuite) TestImports(c *tc.C) {
	// Ensure the package compiles and its public API is accessible.
	_ = docker.NewToken
}
