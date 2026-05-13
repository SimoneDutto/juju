package completion

import (
	"io"
	"sort"

	"github.com/juju/gnuflag"

	"github.com/juju/juju/cmd/cmd"
)

// Snapshot describes the static command metadata exported by the completion backend.
type Snapshot struct {
	Commands []Command `json:"commands"`
}

// Command describes a single Juju command and its flags.
type Command struct {
	Name        string                 `json:"name"`
	Aliases     []string               `json:"aliases,omitempty"`
	Args        string                 `json:"args,omitempty"`
	Purpose     string                 `json:"purpose,omitempty"`
	Flags       []Flag                 `json:"flags,omitempty"`
	Positionals []PositionalCompletion `json:"positionals,omitempty"`
}

// Flag describes a command-line flag that can be completed.
type Flag struct {
	Name            string `json:"name"`
	Usage           string `json:"usage,omitempty"`
	Default         string `json:"default,omitempty"`
	IsBoolean       bool   `json:"isBoolean,omitempty"`
	ValueCompletion string `json:"valueCompletion,omitempty"`
}

// PositionalCompletion describes how to complete a command positional argument.
type PositionalCompletion struct {
	Index   int      `json:"index"`
	Targets []string `json:"targets,omitempty"`
	Repeat  bool     `json:"repeat,omitempty"`
}

// Registry records Juju commands as they are registered.
type Registry interface {
	Register(cmd.Command)
	RegisterSuperAlias(name, super, forName string, check cmd.DeprecationCheck)
	RegisterDeprecated(subcmd cmd.Command, check cmd.DeprecationCheck)
}

type registry struct {
	commands []Command
}

type boolFlag interface {
	IsBoolFlag() bool
}

// Describe returns a stable snapshot of the registered Juju commands.
func Describe(register func(Registry)) Snapshot {
	r := &registry{}
	register(r)
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
		Name:        info.Name,
		Aliases:     append([]string(nil), info.Aliases...),
		Args:        info.Args,
		Purpose:     info.Purpose,
		Flags:       describeFlags(command, info.Name),
		Positionals: positionalCompletions(info.Name),
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
			Name:            flag.Name,
			Usage:           flag.Usage,
			Default:         flag.DefValue,
			IsBoolean:       isBool,
			ValueCompletion: flagValueCompletion(flag.Name),
		})
	})
	return flags
}

var _ Registry = (*registry)(nil)

const (
	CompletionApplications  = "applications"
	CompletionControllers   = "controllers"
	CompletionMachines      = "machines"
	CompletionModels        = "models"
	CompletionStatusTargets = "status-targets"
	CompletionUnits         = "units"
	CompletionSSHTargets    = "ssh-targets"
	CompletionSwitchTargets = "switch-targets"
)

var positionalCompletionByCommand = map[string][]PositionalCompletion{
	"application-storage":  repeatedPositionals(CompletionApplications),
	"config":               repeatedPositionals(CompletionApplications),
	"constraints":          repeatedPositionals(CompletionApplications),
	"debug-code":           repeatedPositionals(CompletionSSHTargets),
	"debug-hooks":          repeatedPositionals(CompletionSSHTargets),
	"expose":               repeatedPositionals(CompletionApplications),
	"refresh":              repeatedPositionals(CompletionApplications),
	"remove-application":   repeatedPositionals(CompletionApplications),
	"remove-machine":       repeatedPositionals(CompletionMachines),
	"remove-unit":          repeatedPositionals(CompletionUnits),
	"resolved":             repeatedPositionals(CompletionUnits),
	"scp":                  repeatedPositionals(CompletionSSHTargets),
	"set-application-base": repeatedPositionals(CompletionApplications),
	"set-constraints":      repeatedPositionals(CompletionApplications),
	"show-machine":         repeatedPositionals(CompletionMachines),
	"ssh":                  repeatedPositionals(CompletionSSHTargets),
	"status":               repeatedPositionals(CompletionStatusTargets),
	"switch":               repeatedPositionals(CompletionSwitchTargets),
	"unexpose":             repeatedPositionals(CompletionApplications),
	"upgrade-machine":      repeatedPositionals(CompletionMachines),
}

func positionalCompletions(commandName string) []PositionalCompletion {
	completions := positionalCompletionByCommand[commandName]
	if len(completions) == 0 {
		return nil
	}
	return append([]PositionalCompletion(nil), completions...)
}

func repeatedPositionals(targets ...string) []PositionalCompletion {
	return []PositionalCompletion{{
		Index:   0,
		Targets: append([]string(nil), targets...),
		Repeat:  true,
	}}
}

func flagValueCompletion(name string) string {
	switch name {
	case "application":
		return CompletionApplications
	case "controller":
		return CompletionControllers
	case "machine":
		return CompletionMachines
	case "model":
		return CompletionModels
	case "unit":
		return CompletionUnits
	default:
		return ""
	}
}
