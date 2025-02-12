// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshhelper_test

import (
	"slices"

	"github.com/juju/juju/core/permission"
	"github.com/juju/juju/state"
	statetesting "github.com/juju/juju/state/testing"
	"github.com/juju/juju/storage"
	"github.com/juju/juju/testing"
	"github.com/juju/juju/testing/factory"
	"github.com/juju/juju/worker/sshserver/sshhelper"
	"github.com/juju/names/v5"
	"github.com/juju/utils/v3/ssh"
	gc "gopkg.in/check.v1"
)

type authorizerSuite struct {
	statetesting.StateSuite

	authorizer sshhelper.Authorizer
}

var _ = gc.Suite(&authorizerSuite{})

func (s *authorizerSuite) SetUpTest(c *gc.C) {
	s.StateSuite.SetUpTest(c)
	var err error
	s.authorizer, err = sshhelper.NewAuthorizer(s.StatePool)
	c.Assert(err, gc.IsNil)
}

func (s *authorizerSuite) TestAuthorizedKeysPerUser(c *gc.C) {
	m, st, err := s.Controller.NewModel(state.ModelArgs{
		Type:        state.ModelTypeIAAS,
		CloudName:   "dummy",
		CloudRegion: "dummy-region",
		Config: testing.CustomModelConfig(c, testing.Attrs{
			"name":            "testing",
			"authorized-keys": "key_alice\nkey_bob",
		}),
		Owner:                   s.Owner,
		StorageProviderRegistry: storage.StaticProviderRegistry{},
	})
	c.Assert(err, gc.IsNil)
	s.AddCleanup(func(c *gc.C) {
		st.Close()
	})

	cfgM1, err := s.Model.Config()
	c.Assert(err, gc.IsNil)
	authKeysM1 := ssh.SplitAuthorisedKeys(cfgM1.AuthorizedKeys())
	cfgM2, err := m.Config()
	c.Assert(err, gc.IsNil)
	authKeysM2 := ssh.SplitAuthorisedKeys(cfgM2.AuthorizedKeys())

	authKeyBoth := append(authKeysM1, authKeysM2...)
	user := s.Factory.MakeUser(c,
		&factory.UserParams{
			Name:        "bob",
			NoModelUser: true,
		},
	)
	_, err = s.Model.AddUser(
		state.UserAccessSpec{
			User:      user.UserTag(),
			CreatedBy: s.Owner,
			Access:    permission.ReadAccess,
		},
	)
	c.Assert(err, gc.IsNil)

	testCases := []struct {
		name         string
		userTag      names.UserTag
		expectedKeys []string
	}{
		{
			name:         "test for owner of both models",
			userTag:      s.Model.Owner(),
			expectedKeys: authKeyBoth,
		},
		{
			name:         "test for owner of no model",
			userTag:      names.NewUserTag("nomodel"),
			expectedKeys: nil,
		},
		{
			name:         "test for user with read access to a single model",
			userTag:      user.UserTag(),
			expectedKeys: authKeysM1,
		},
	}

	for _, tc := range testCases {
		c.Logf("test: %s", tc.name)
		authKeys, err := s.authorizer.AuthorizedKeysPerUser(tc.userTag)
		slices.Sort(authKeys) // sort to avoid orders' issues in comparison
		slices.Sort(tc.expectedKeys)
		c.Assert(err, gc.IsNil)
		c.Assert(authKeys, gc.DeepEquals, tc.expectedKeys)
	}
}
