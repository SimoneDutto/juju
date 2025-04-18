// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

import (
	"time"

	"github.com/juju/errors"

	k8sexec "github.com/juju/juju/caas/kubernetes/provider/exec"
	"github.com/juju/juju/core/virtualhostname"
	"github.com/juju/juju/internal/worker/sshserver/k8s"
	"github.com/juju/juju/internal/worker/sshserver/machine"
)

type proxyFactory struct {
	k8sResolver k8s.Resolver
	logger      Logger
	connector   machine.SSHConnector
}

type connectionInfo struct {
	startTime   time.Time
	destination virtualhostname.Info
}

func (b proxyFactory) New(info connectionInfo) (ProxyHandlers, error) {
	switch info.destination.Target() {
	case virtualhostname.ContainerTarget:
		k8sHandlers, err := k8s.NewHandler(info.destination, b.k8sResolver, b.logger, k8sexec.NewInCluster)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return k8sHandlers, nil
	case virtualhostname.MachineTarget, virtualhostname.UnitTarget:
		// Since we've validated the hostname prior, we've verified
		// that unit targets are machines.
		machineHandlers, err := machine.NewHandlers(info.destination, b.connector, b.logger)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return machineHandlers, nil
	default:
		return nil, errors.NotValidf("unknown virtualhostname target: %s", info.destination.Target())
	}
}
