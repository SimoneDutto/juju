// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

import (
	stdtesting "testing"

	"github.com/juju/juju/testing"
)

//go:generate go run go.uber.org/mock/mockgen -package sshserver_test -destination context_mocks_test.go github.com/juju/juju/apiserver/facade Authorizer,Context,Resources
//go:generate go run go.uber.org/mock/mockgen -package sshserver_test -destination mocks_test.go github.com/juju/juju/apiserver/facades/controller/sshserver SystemState,StatePool

func TestAll(t *stdtesting.T) {
	testing.MgoTestPackage(t)
}
