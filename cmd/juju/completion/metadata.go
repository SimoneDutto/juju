package completion

import (
	"io"
	"sort"

	"github.com/juju/cmd/v3"
	"github.com/juju/gnuflag"

	"github.com/juju/juju/cmd/juju/commands"
)

// Snapshot describes the static command metadata exported by the completion backend.
type Snapshot struct {
	Commands []Command `json:"commands"`
}

// Command describes a single Juju command and its flags.
type Command struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
	Args    string   `json:"args,omitempty"`
	Purpose string   `json:"purpose,omitempty"`
	Flags   []Flag   `json:"flags,omitempty"`
}

// Flag describes a command-line flag that can be completed.
type Flag struct {
	Name      string `json:"name"`
	Usage     string `json:"usage,omitempty"`
	Default   string `json:"default,omitempty"`
	IsBoolean bool   `json:"isBoolean,omitempty"`
}

type registry struct {
	commands []Command
}

type boolFlag interface {
	IsBoolFlag() bool
}

// Describe returns a stable snapshot of the registered Juju commands.
func Describe() Snapshot {
	r := &registry{}
	commands.RegisterCommands(r)
	sort.Slice(r.commands, func(i, j int) bool {
		return r.commands[i].Name < r.commands[j].Name
	})
	return Snapshot{Commands: r.commands}
}

// CommandNames returns the registered command names and aliases.
func (s Snapshot) CommandNames() []string {
	names := make([]string, 0, len(s.Commands))
	for _, command := range s.Commands {
		names = append(names, command.Name)
		names = append(names, command.Aliases...)
	}
	sort.Strings(names)
	return names
}

// FlagsFor returns the formatted flags for the named command or alias.
func (s Snapshot) FlagsFor(name string) []string {
	command, ok := s.Lookup(name)
	if !ok {
		return nil
	}
	flags := make([]string, 0, len(command.Flags))
	for _, flag := range command.Flags {
		prefix := "--"
		if len(flag.Name) == 1 {
			prefix = "-"
		}
		flags = append(flags, prefix+flag.Name)
	}
	sort.Strings(flags)
	return flags
}

// Lookup returns the command metadata for the named command or alias.
func (s Snapshot) Lookup(name string) (Command, bool) {
	for _, command := range s.Commands {
		if command.Name == name {
			return command, true
		}
		for _, alias := range command.Aliases {
			if alias == name {
				return command, true
			}
		}
	}
	return Command{}, false
}

func (r *registry) Register(command cmd.Command) {
	r.commands = append(r.commands, describeCommand(command))
}

func (r *registry) RegisterSuperAlias(name, super, forName string, check cmd.DeprecationCheck) {
	// Super aliases map onto existing commands and do not add new flag metadata.
}

func (r *registry) RegisterDeprecated(command cmd.Command, check cmd.DeprecationCheck) {
	if check.Obsolete() {
		return
	}
	r.commands = append(r.commands, describeCommand(command))
}

func describeCommand(command cmd.Command) Command {
	info := command.Info()
	return Command{
		Name:    info.Name,
		Aliases: append([]string(nil), info.Aliases...),
		Args:    info.Args,
		Purpose: info.Purpose,
		Flags:   describeFlags(command, info.Name),
	}
}

func describeFlags(command cmd.Command, name string) []Flag {
	flagSet := gnuflag.NewFlagSetWithFlagKnownAs(name, gnuflag.ContinueOnError, cmd.FlagAlias(command, "option"))
	flagSet.SetOutput(io.Discard)
	command.SetFlags(flagSet)

	flags := make([]Flag, 0)
	flagSet.VisitAll(func(flag *gnuflag.Flag) {
		_, isBool := flag.Value.(boolFlag)
		flags = append(flags, Flag{
			Name:      flag.Name,
			Usage:     flag.Usage,
			Default:   flag.DefValue,
			IsBoolean: isBool,
		})
	})
	return flags
}

var _ commands.Registry = (*registry)(nil)