// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshhelper

import (
	"github.com/juju/errors"
	"github.com/juju/juju/state"
	"github.com/juju/names/v5"
	"github.com/juju/utils/v3/ssh"
)

// Authorizer is the struct to authorize users' ssh connection.
type Authorizer struct {
	statePool *state.StatePool
}

// NewAuthorizer create an Authorizer. It takes as an argument the StatePool.
func NewAuthorizer(sp *state.StatePool) (Authorizer, error) {
	if sp == nil {
		return Authorizer{}, errors.Errorf("StatePool is nil.")
	}
	return Authorizer{
		statePool: sp,
	}, nil
}

// AuthorizedKeysPerUser collects the model uuids the user has permission on, and get the authorized keys
// from each. Since ssh authorized keys are associated to models and not user, each user with an access to a model
// is
func (sm Authorizer) AuthorizedKeysPerUser(userTag names.UserTag) ([]string, error) {
	systemState, err := sm.statePool.SystemState()
	if err != nil {
		return nil, errors.Trace(err)
	}
	modelUUIDs, err := systemState.ModelUUIDsForUser(userTag)
	if err != nil {
		return nil, errors.Trace(err)
	}
	var authorizedKeys []string
	for _, uuid := range modelUUIDs {
		model, p, err := sm.statePool.GetModel(uuid)
		if err != nil {
			return nil, errors.Trace(err)
		}
		defer p.Release()
		cfg, err := model.Config()
		if err != nil {
			return nil, errors.Trace(err)
		}
		keys := ssh.SplitAuthorisedKeys(cfg.AuthorizedKeys())
		if err != nil {
			return nil, errors.Trace(err)
		}
		authorizedKeys = append(authorizedKeys, keys...)
	}
	return authorizedKeys, nil
}
