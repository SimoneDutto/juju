// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package commands

import (
	"fmt"

	jujucmd "github.com/juju/juju/cmd"
	"github.com/juju/juju/cmd/cmd"
)

const autocompleteDoc = `
Generate shell completion setup for Juju.

The generated script delegates completion requests to the standalone
juju-autocomplete binary.
`

const autocompleteExamples = `
Enable completion for the current shell session:

    source <(juju autocomplete bash)

Install completion system-wide (example path):

    juju autocomplete bash | sudo tee /usr/share/bash-completion/completions/juju >/dev/null
`

type autocompleteCommand struct {
	cmd.CommandBase

	shell string
}

func newAutocompleteCommand() cmd.Command {
	return &autocompleteCommand{}
}

func (c *autocompleteCommand) Info() *cmd.Info {
	return jujucmd.Info(&cmd.Info{
		Name:     "autocomplete",
		Args:     "<shell>",
		Purpose:  "Generate shell completion setup for Juju.",
		Doc:      autocompleteDoc,
		Examples: autocompleteExamples,
		SeeAlso:  []string{"help"},
	})
}

func (c *autocompleteCommand) Init(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing shell argument")
	}
	c.shell = args[0]
	if err := cmd.CheckEmpty(args[1:]); err != nil {
		return err
	}
	if c.shell != "bash" {
		return fmt.Errorf("unsupported shell %q", c.shell)
	}
	return nil
}

func (c *autocompleteCommand) Run(ctx *cmd.Context) error {
	_, err := fmt.Fprint(ctx.Stdout, bashAutocompleteScript)
	return err
}

const bashAutocompleteScript = `# bash completion for juju via juju-autocomplete
complete -o default -o bashdefault -C juju-autocomplete juju
complete -o default -o bashdefault -C juju-autocomplete juju-2
`
