// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package k8s

import (
	"github.com/juju/errors"

	k8sexec "github.com/juju/juju/caas/kubernetes/provider/exec"
	"github.com/juju/juju/core/virtualhostname"
	"github.com/juju/juju/rpc/params"
)

type Resolver interface {
	ResolveK8sExecInfo(arg params.SSHK8sExecArg) (params.SSHK8sExecResult, error)
}

type Logger interface {
	Errorf(string, ...interface{})
	Debugf(string, ...interface{})
}

type Handlers struct {
	resolver    Resolver
	logger      Logger
	getExecutor func(string) (k8sexec.Executor, error)
	destination virtualhostname.Info
}

func NewHandler(destination virtualhostname.Info, resolver Resolver, logger Logger, getExecutor func(string) (k8sexec.Executor, error)) (*Handlers, error) {
	if resolver == nil {
		return nil, errors.NotValidf("k8s resolver is required")
	}
	if logger == nil {
		return nil, errors.NotValidf("logger is required")
	}
	if getExecutor == nil {
		return nil, errors.NotValidf("executor is required")
	}
	return &Handlers{
		resolver:    resolver,
		logger:      logger,
		getExecutor: getExecutor,
		destination: destination,
	}, nil
}
