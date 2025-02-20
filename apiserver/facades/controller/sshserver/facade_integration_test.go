// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver_test

import (
	"github.com/gliderlabs/ssh"
	"github.com/juju/names/v5"
	jujussh "github.com/juju/utils/v3/ssh"
	"go.uber.org/mock/gomock"
	gc "gopkg.in/check.v1"

	"github.com/juju/juju/apiserver/facades/controller/sshserver"
	"github.com/juju/juju/core/permission"
	"github.com/juju/juju/rpc/params"
	"github.com/juju/juju/state"
	statetesting "github.com/juju/juju/state/testing"
	"github.com/juju/juju/testing/factory"
)

type facadeSuite struct {
	statetesting.StateSuite

	facade *sshserver.Facade
}

var _ = gc.Suite(&facadeSuite{})

func (f *facadeSuite) SetUpTest(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()
	ctx := NewMockContext(ctrl)
	ctx.EXPECT().Resources().AnyTimes()
	f.StateSuite.SetUpTest(c)
	var err error

	systemState, err := f.StatePool.SystemState()
	c.Assert(err, gc.IsNil)

	f.facade = sshserver.NewFacade(ctx, f.StatePool, systemState)
	c.Assert(err, gc.IsNil)
}

func (f *facadeSuite) TestAuthorizedKeysPerUser(c *gc.C) {
	cfgM1, err := f.Model.Config()
	c.Assert(err, gc.IsNil)
	authKeysM1 := jujussh.SplitAuthorisedKeys(cfgM1.AuthorizedKeys())
	c.Assert(authKeysM1, gc.HasLen, 1)
	defaultPublicKeyM1, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authKeysM1[0]))
	c.Assert(err, gc.IsNil)
	user := f.Factory.MakeUser(c,
		&factory.UserParams{
			Name:        "bob",
			NoModelUser: true,
		},
	)
	_, err = f.Model.AddUser(
		state.UserAccessSpec{
			User:      user.UserTag(),
			CreatedBy: f.Owner,
			Access:    permission.ReadAccess,
		},
	)
	c.Assert(err, gc.IsNil)

	testCases := []struct {
		name            string
		userTag         names.UserTag
		userKey         ssh.PublicKey
		expectedSuccess bool
		expectedError   string
	}{
		{
			name:            "test for owner of both models",
			userTag:         f.Model.Owner(),
			userKey:         defaultPublicKeyM1,
			expectedSuccess: true,
		},
		{
			name:            "test for owner of no model",
			userTag:         names.NewUserTag("nomodel"),
			userKey:         defaultPublicKeyM1,
			expectedSuccess: false,
			expectedError:   "matching public key not found not found",
		},
		{
			name:            "test for user with read access to a single model",
			userTag:         user.UserTag(),
			userKey:         defaultPublicKeyM1,
			expectedSuccess: true,
		},
	}

	for _, tc := range testCases {
		c.Logf("test: %s", tc.name)
		publicKeyToVerify := params.SSHPKIAuthArgs{
			UserTag:   tc.userTag.String(),
			PublicKey: tc.userKey.Marshal(),
		}
		err := f.facade.PublicKeyAuthentication(publicKeyToVerify)
		if tc.expectedSuccess {
			c.Assert(err, gc.IsNil)
		} else {
			c.Assert(err, gc.ErrorMatches, tc.expectedError)
		}
	}
}
