// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

import (
	"reflect"

	"github.com/juju/errors"

	apiservererrors "github.com/juju/juju/apiserver/errors"
	"github.com/juju/juju/apiserver/facade"
)

// Register is called to expose a package of facades onto a given registry.
func Register(registry facade.FacadeRegistry) {
	registry.MustRegister("SSHServer", 1, func(ctx facade.Context) (facade.Facade, error) {
		return NewExternalFacade(ctx)
	}, reflect.TypeOf((*Facade)(nil)))
}

// NewExternalFacade creates a new authorized Facade.
func NewExternalFacade(ctx facade.Context) (*Facade, error) {
	authorizer := ctx.Auth()
	if !authorizer.AuthController() {
		return nil, apiservererrors.ErrPerm
	}
	statePool := ctx.StatePool()
	systemState, err := statePool.SystemState()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return NewFacade(ctx, statePool, systemState), nil
}
