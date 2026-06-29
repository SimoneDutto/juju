// Copyright 2023 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package docker

import (
	coredocker "github.com/juju/juju/core/docker"
)

// Function re-exports for the serialization helpers.
var (
	// ValidateDockerRegistryPath ensures the registry path is valid.
	ValidateDockerRegistryPath = coredocker.ValidateDockerRegistryPath

	// CheckDockerDetails validates the provided resource is suitable for use.
	CheckDockerDetails = coredocker.CheckDockerDetails

	// UnmarshalDockerResource unmarshals the docker resource file from data.
	UnmarshalDockerResource = coredocker.UnmarshalDockerResource

	// ConvertToResourceImageDetails converts the provided DockerImageDetails to a
	// resources.ImageRepoDetails.
	ConvertToResourceImageDetails = coredocker.ConvertToResourceImageDetails
)

