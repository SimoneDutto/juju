// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/juju/errors"
	"github.com/juju/loggo"
	"github.com/juju/names/v5"
	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/worker/v3/workertest"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/test/bufconn"
	gc "gopkg.in/check.v1"

	"github.com/juju/juju/internal/worker/sshserver"
	params "github.com/juju/juju/rpc/params"
	jujutesting "github.com/juju/juju/testing"
)

type sshServerSuite struct {
	testing.IsolationSuite

	userSigner ssh.Signer
}

var _ = gc.Suite(&sshServerSuite{})

func (s *sshServerSuite) SetUpSuite(c *gc.C) {
	s.IsolationSuite.SetUpSuite(c)

	// Setup user signer
	userKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, jc.ErrorIsNil)

	userSigner, err := ssh.NewSignerFromKey(userKey)
	c.Assert(err, jc.ErrorIsNil)

	s.userSigner = userSigner
}

func newServerWorkerConfig(
	l sshserver.Logger,
	j string,
	modifier func(*sshserver.ServerWorkerConfig),
) *sshserver.ServerWorkerConfig {
	cfg := &sshserver.ServerWorkerConfig{
		Logger:      l,
		JumpHostKey: j,
	}

	modifier(cfg)

	return cfg
}

func (s *sshServerSuite) TestValidate(c *gc.C) {
	cfg := &sshserver.ServerWorkerConfig{}
	l := loggo.GetLogger("test")

	c.Assert(cfg.Validate(), jc.ErrorIs, errors.NotValid)

	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	// Test no Logger.
	cfg = newServerWorkerConfig(l, "jumpHostKey", func(cfg *sshserver.ServerWorkerConfig) {
		cfg.Logger = nil
	})
	c.Assert(cfg.Validate(), jc.ErrorIs, errors.NotValid)

	// Test no JumpHostKey.
	cfg = newServerWorkerConfig(l, "jumpHostKey", func(cfg *sshserver.ServerWorkerConfig) {
		cfg.JumpHostKey = ""
	})
	c.Assert(cfg.Validate(), jc.ErrorIs, errors.NotValid)

	// Test no FacadeClient.
	cfg = newServerWorkerConfig(l, "jumpHostKey", func(cfg *sshserver.ServerWorkerConfig) {
		cfg.FacadeClient = nil
	})
	c.Assert(cfg.Validate(), jc.ErrorIs, errors.NotValid)
}

func (s *sshServerSuite) TestSSHServer(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	// Firstly, start the server on an in-memory listener
	listener := bufconn.Listen(8 * 1024)
	facadeClient := NewMockFacadeClient(ctrl)

	server, err := sshserver.NewServerWorker(sshserver.ServerWorkerConfig{
		Logger:       loggo.GetLogger("test"),
		Listener:     listener,
		JumpHostKey:  jujutesting.SSHServerHostKey,
		FacadeClient: facadeClient,
	})
	c.Assert(err, jc.ErrorIsNil)
	defer workertest.DirtyKill(c, server)
	workertest.CheckAlive(c, server)

	// Dial the in-memory listener
	conn, err := listener.Dial()
	c.Assert(err, jc.ErrorIsNil)

	// Open a client connection
	jumpConn, chans, terminatingReqs, err := ssh.NewClientConn(
		conn,
		"",
		&ssh.ClientConfig{
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Auth: []ssh.AuthMethod{
				ssh.Password(""), // No password needed
			},
		},
	)
	c.Assert(err, jc.ErrorIsNil)

	// Open jump connection
	client := ssh.NewClient(jumpConn, chans, terminatingReqs)
	tunnel, err := client.Dial("tcp", "1.postgresql.8419cd78-4993-4c3a-928e-c646226beeee.juju.local:20")
	c.Assert(err, jc.ErrorIsNil)

	// Now with this opened direct-tcpip channel, open a session connection
	terminatingClientConn, terminatingClientChan, terminatingReqs, err := ssh.NewClientConn(
		tunnel,
		"",
		&ssh.ClientConfig{
			User:            "ubuntu",
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(s.userSigner),
			},
		})
	c.Assert(err, jc.ErrorIsNil)

	terminatingClient := ssh.NewClient(terminatingClientConn, terminatingClientChan, terminatingReqs)
	terminatingSession, err := terminatingClient.NewSession()
	c.Assert(err, jc.ErrorIsNil)

	output, err := terminatingSession.CombinedOutput("")
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(string(output), gc.Equals, "Your final destination is: 1.postgresql.8419cd78-4993-4c3a-928e-c646226beeee.juju.local as user: ubuntu\n")

	// Server isn't gracefully closed, it's forcefully closed. All connections ended
	// from server side.
	workertest.CleanKill(c, server)
}

func (s *sshServerSuite) TestSSHPublicKeyHandler(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	listener := bufconn.Listen(8 * 1024)
	facadeClient := NewMockFacadeClient(ctrl)

	facadeClient.EXPECT().PublicKeyAuthentication(gomock.Any()).DoAndReturn(func(sshPKIAuthArgs params.SSHPKIAuthArgs) error {
		if strings.Contains(sshPKIAuthArgs.UserTag, "alice") {
			return nil
		}
		return errors.NotFound
	}).AnyTimes()

	server, err := sshserver.NewServerWorker(sshserver.ServerWorkerConfig{
		Logger:       loggo.GetLogger("test"),
		Listener:     listener,
		JumpHostKey:  jujutesting.SSHServerHostKey,
		FacadeClient: facadeClient,
	})
	c.Assert(err, gc.IsNil)
	defer workertest.DirtyKill(c, server)

	userKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, gc.IsNil)

	notValidSigner, err := ssh.NewSignerFromKey(userKey)
	c.Assert(err, gc.IsNil)

	tests := []struct {
		name          string
		user          names.UserTag
		key           ssh.Signer
		expectSuccess bool
	}{
		{
			name:          "valid user and public key",
			user:          names.NewUserTag("alice"),
			key:           s.userSigner,
			expectSuccess: true,
		},
		{
			name:          "user not found",
			user:          names.NewUserTag("notfound"),
			key:           notValidSigner,
			expectSuccess: false,
		},
	}

	for _, test := range tests {
		c.Log(test.name)
		conn, err := listener.Dial()
		c.Assert(err, gc.IsNil)
		_, _, _, err = ssh.NewClientConn(
			conn,
			"",
			&ssh.ClientConfig{
				User:            test.user.Name(),
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Auth: []ssh.AuthMethod{
					ssh.PublicKeys(test.key),
				},
			},
		)
		if !test.expectSuccess {
			c.Assert(err, gc.ErrorMatches, fmt.Sprintf(".*ssh: handshake failed: ssh: unable to authenticate.*"))
		} else {
			c.Assert(err, gc.IsNil)
		}
	}
}
