package k8s

import (
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

func (Handlers) DirectTCPIPHandler() ssh.ChannelHandler {
	return func(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
		_ = newChan.Reject(gossh.Prohibited, "not implemented")
		return
	}
}
