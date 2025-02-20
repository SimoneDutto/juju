// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

import (
	"github.com/gliderlabs/ssh"
	"github.com/juju/errors"
	"github.com/juju/names/v5"
	jujussh "github.com/juju/utils/v3/ssh"
	gossh "golang.org/x/crypto/ssh"

	apiservererrors "github.com/juju/juju/apiserver/errors"
	"github.com/juju/juju/apiserver/facade"
	"github.com/juju/juju/controller"
	"github.com/juju/juju/rpc/params"
	"github.com/juju/juju/state"
	"github.com/juju/juju/state/watcher"
)

// SystemState provides required state for the Facade.
type SystemState interface {
	ModelUUIDsForUser(user names.UserTag) ([]string, error)
	ControllerConfig() (controller.Config, error)
	WatchControllerConfig() state.NotifyWatcher
	SSHServerHostKey() (string, error)
}

// StatePool provides a way to get a model by UUID.
type StatePool interface {
	GetModel(modelUUID string) (*state.Model, state.PoolHelper, error)
}

// Facade allows model config manager clients to watch controller config changes and fetch controller config.
type Facade struct {
	resources facade.Resources

	systemState SystemState
	statePool   StatePool
}

// NewFacade returns a new SSHServer facade to be registered for use within
// the worker.
func NewFacade(ctx facade.Context, statePool StatePool, systemState SystemState) *Facade {
	return &Facade{
		resources:   ctx.Resources(),
		systemState: systemState,
		statePool:   statePool,
	}
}

// ControllerConfig returns the current controller config.
func (f *Facade) ControllerConfig() (params.ControllerConfigResult, error) {
	result := params.ControllerConfigResult{}
	config, err := f.systemState.ControllerConfig()
	if err != nil {
		return result, err
	}
	result.Config = params.ControllerConfig(config)
	return result, nil
}

// WatchControllerConfig creates a watcher and returns it's ID for watching upon.
func (f *Facade) WatchControllerConfig() (params.NotifyWatchResult, error) {
	result := params.NotifyWatchResult{}
	w := f.systemState.WatchControllerConfig()
	if _, ok := <-w.Changes(); ok {
		result.NotifyWatcherId = f.resources.Register(w)
	} else {
		return result, watcher.EnsureErr(w)
	}
	return result, nil
}

// SSHServerHostKey returns the controller's SSH server host key.
func (f *Facade) SSHServerHostKey() (params.StringResult, error) {
	result := params.StringResult{}
	key, err := f.systemState.SSHServerHostKey()
	if err != nil {
		result.Error = apiservererrors.ServerError(err)
	}
	result.Result = key
	return result, nil
}

// authorizedKeysPerModel collects the authorized keys given a model uuid.
func (f *Facade) authorizedKeysPerModel(uuid string) ([]string, error) {
	model, p, err := f.statePool.GetModel(uuid)
	if err != nil {
		return nil, errors.Trace(err)
	}
	defer p.Release()
	cfg, err := model.Config()
	if err != nil {
		return nil, errors.Trace(err)
	}
	keys := jujussh.SplitAuthorisedKeys(cfg.AuthorizedKeys())
	return keys, nil
}

// PublicKeyAuthentication extracts the models a user has access to, get all the authorized keys and search for a match.
// If it's found it returns nil error, in case of errors or no-match returns the error.
// It is expected that a key available on one model allows the user to authenticate to any model,
// but later one where we can check the destination model, we will restrict access to the specific model
// the user is trying to SSH into.
func (f *Facade) PublicKeyAuthentication(sshPKIAuthArgs params.SSHPKIAuthArgs) error {
	userTag, err := names.ParseUserTag(sshPKIAuthArgs.UserTag)
	if err != nil {
		return errors.Errorf("failed to parse user tag: %v", err)
	}
	publicKey, err := gossh.ParsePublicKey(sshPKIAuthArgs.PublicKey)
	if err != nil {
		return errors.Errorf("failed to parse public key: %v", err)
	}
	modelUUIDs, err := f.systemState.ModelUUIDsForUser(userTag)
	if err != nil {
		return errors.Errorf("failed to get model uuids for user: %v", err)
	}
	for _, uuid := range modelUUIDs {
		authKeys, err := f.authorizedKeysPerModel(uuid)
		if err != nil {
			return errors.Errorf("failed to get authorized key for model: %v", err)
		}
		for _, authKey := range authKeys {
			pubKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(authKey))
			if err != nil {
				continue
			}
			if ssh.KeysEqual(publicKey, pubKey) {
				return nil
			}
		}
	}
	return errors.NotFoundf("matching public key not found")
}
