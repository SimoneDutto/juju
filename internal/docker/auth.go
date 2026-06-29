// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package docker re-exports the OCI image and registry credential types from
// github.com/juju/juju/core/docker. The canonical definitions live in
// core/docker so that external clients (e.g. the Terraform Juju provider) can
// import them; this package remains as a compatibility shim for existing
// internal callers.
package docker

import (
	coredocker "github.com/juju/juju/core/docker"
)

// Type aliases. These keep internal/docker.Token and core/docker.Token (and
// friends) as identical types, so all existing call sites and method sets are
// preserved.
type (
	// Token defines a token value with expiration time.
	Token = coredocker.Token

	// TokenAuthConfig contains authorization information for token auth.
	TokenAuthConfig = coredocker.TokenAuthConfig

	// BasicAuthConfig contains authorization information for basic auth.
	BasicAuthConfig = coredocker.BasicAuthConfig

	// DockerImageDetails holds the details for a Docker resource type.
	DockerImageDetails = coredocker.DockerImageDetails

	// ImageRepoDetails contains authorization information for connecting to a Registry.
	ImageRepoDetails = coredocker.ImageRepoDetails
)

// Function re-exports.
var (
	// NewToken creates a Token.
	NewToken = coredocker.NewToken

	// NewImageRepoDetails tries to parse as json or basic repository path and
	// returns an instance of ImageRepoDetails.
	NewImageRepoDetails = coredocker.NewImageRepoDetails

	// LoadImageRepoDetails tries to parse a file path or file content and
	// returns an instance of ImageRepoDetails.
	LoadImageRepoDetails = coredocker.LoadImageRepoDetails
)

