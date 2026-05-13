// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package commands

import (
	"fmt"
	"strings"

	"github.com/juju/errors"
	"github.com/juju/gnuflag"

	jujucmd "github.com/juju/juju/cmd"
	"github.com/juju/juju/cmd/cmd"
	"github.com/juju/juju/cmd/juju/completion"
)

func newAutocompleteCommand() cmd.Command {
	return &autocompleteCommand{cword: -1}
}

type autocompleteCommand struct {
	cmd.CommandBase

	words   stringSliceFlag
	current string
	cword   int
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func (c *autocompleteCommand) Info() *cmd.Info {
	return jujucmd.Info(&cmd.Info{
		Name:    "autocomplete",
		Purpose: "Return shell completion candidates.",
		Doc: `The autocomplete command returns completion candidates for shell integrations.

It is intended to be called by Juju completion scripts rather than directly by
users.`,
		SeeAlso: []string{"help"},
	})
}

func (c *autocompleteCommand) SetFlags(f *gnuflag.FlagSet) {
	f.Var(&c.words, "word", "Shell word passed to completion. Repeat once per word.")
	f.StringVar(&c.current, "current", "", "Current shell word being completed.")
	f.IntVar(&c.cword, "cword", -1, "Index of the current shell word.")
}

func (c *autocompleteCommand) Init(args []string) error {
	if err := cmd.CheckEmpty(args); err != nil {
		return err
	}
	if c.cword < 0 {
		return errors.New("missing --cword")
	}
	return nil
}

func (c *autocompleteCommand) Run(ctx *cmd.Context) error {
	backend := completion.NewBackend()
	snapshot := completion.Describe(func(r completion.Registry) {
		registerCommands(completionRegistryAdapter{registry: r})
	})

	candidates, err := backend.Complete(snapshot, completion.Request{
		Words:   append([]string(nil), c.words...),
		Current: c.current,
		Cword:   c.cword,
	})
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		return nil
	}
	_, err = fmt.Fprintln(ctx.Stdout, strings.Join(candidates, "\n"))
	return err
}

type completionRegistryAdapter struct {
	registry completion.Registry
}

func (a completionRegistryAdapter) Register(command cmd.Command) {
	a.registry.Register(command)
}

func (a completionRegistryAdapter) RegisterSuperAlias(name, super, forName string, check cmd.DeprecationCheck) {
	a.registry.RegisterSuperAlias(name, super, forName, check)
}

func (a completionRegistryAdapter) RegisterDeprecated(command cmd.Command, check cmd.DeprecationCheck) {
	a.registry.RegisterDeprecated(command, check)
}
