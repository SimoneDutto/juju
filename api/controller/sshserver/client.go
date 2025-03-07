// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

import (
	"github.com/juju/juju/api/base"
	"github.com/juju/juju/api/common"
	apiwatcher "github.com/juju/juju/api/watcher"
	"github.com/juju/juju/core/watcher"
	"github.com/juju/juju/rpc/params"
)

// Client holds the SSH server client for it's respective worker.
type Client struct {
	facade base.FacadeCaller
	*common.ControllerConfigAPI
}

// NewClient returns an SSH server facade client.
func NewClient(caller base.APICaller) (*Client, error) {
	facadeCaller := base.NewFacadeCaller(caller, "SSHServer")
	return &Client{
		facade:              facadeCaller,
		ControllerConfigAPI: common.NewControllerConfig(facadeCaller),
	}, nil
}

// WatchControllerConfig provides a watcher for changes on controller config.
func (c *Client) WatchControllerConfig() (watcher.NotifyWatcher, error) {
	var result params.NotifyWatchResult
	if err := c.facade.FacadeCall("WatchControllerConfig", nil, &result); err != nil {
		return nil, err
	}
	if result.Error != nil {
		return nil, result.Error
	}
	return apiwatcher.NewNotifyWatcher(c.facade.RawAPICaller(), result), nil
}

// SSHServerHostKey returns the private host key for the controller's SSH server.
func (c *Client) SSHServerHostKey() (string, error) {
	var result params.StringResult
	err := c.facade.FacadeCall("SSHServerHostKey", nil, &result)
	if err != nil {
		return "", err
	}
	if err := result.Error; err != nil {
		return "", err
	}
	return result.Result, nil
}

// PublicKeyAuthentication tries to verify that a public key belongs to a user,
// and it returns no error in case of success, otherwise it return an error.
func (c *Client) PublicKeyAuthentication(sshPKIAuthArgs params.SSHPKIAuthArgs) error {
	var result params.ErrorResult
	err := c.facade.FacadeCall("PublicKeyAuthentication", sshPKIAuthArgs, &result)
	if err != nil {
		return err
	}
	if err := result.Error; err != nil {
		return err
	}
	return nil
}
