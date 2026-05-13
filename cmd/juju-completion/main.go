package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/juju/loggo/v2"

	jujucmd "github.com/juju/juju/cmd/cmd"
	"github.com/juju/juju/cmd/juju/commands"
	"github.com/juju/juju/cmd/juju/completion"
	"github.com/juju/juju/internal/debug/coveruploader"
	_ "github.com/juju/juju/internal/provider/all"
	"github.com/juju/juju/juju"
)

func main() {
	coveruploader.Enable()
	_, err := loggo.ReplaceDefaultWriter(jujucmd.NewWarningWriter(os.Stderr))
	if err != nil {
		panic(err)
	}
	os.Exit(Main(os.Args))
}

// Main is the entrypoint for the juju-completion executable.
func Main(args []string) int {
	if err := juju.InitJujuXDGDataHome(); err != nil {
		jujucmd.WriteError(os.Stderr, err)
		return 2
	}

	backend := completion.NewBackend()
	snapshot := completion.Describe(func(r completion.Registry) {
		commands.RegisterCommands(commandRegistryAdapter{registry: r})
	})
	subcommand := "describe"
	if len(args) > 1 {
		subcommand = args[1]
	}

	switch subcommand {
	case "describe":
		if len(args) > 2 {
			fmt.Fprintf(os.Stderr, "usage: %s [describe]\n", args[0])
			return 2
		}
		if err := json.NewEncoder(os.Stdout).Encode(snapshot); err != nil {
			jujucmd.WriteError(os.Stderr, err)
			return 1
		}
	case "commands":
		if len(args) != 2 {
			fmt.Fprintf(os.Stderr, "usage: %s commands\n", args[0])
			return 2
		}
		printLines(snapshot.CommandNames())
	case "flags":
		if len(args) != 3 {
			fmt.Fprintf(os.Stderr, "usage: %s flags <command>\n", args[0])
			return 2
		}
		printLines(snapshot.FlagsFor(args[2]))
	case "controllers":
		if len(args) != 2 {
			fmt.Fprintf(os.Stderr, "usage: %s controllers\n", args[0])
			return 2
		}
		return printBackendLines(backend.Controllers())
	case "models":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "usage: %s models\n", args[0])
			return 2
		}
		return printBackendLines(backend.Models())
	case "applications":
		command, err := parseEntityCommand(args[2:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 2
		}
		return printBackendLines(backend.Applications(command.model))
	case "units":
		command, err := parseEntityCommand(args[2:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 2
		}
		return printBackendLines(backend.Units(command.model, command.suffix))
	case "machines":
		command, err := parseEntityCommand(args[2:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 2
		}
		return printBackendLines(backend.Machines(command.model))
	case "complete":
		request, err := parseCompleteCommand(args[2:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 2
		}
		return printBackendLines(backend.Complete(snapshot, request))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", subcommand)
		return 2
	}
	return 0
}

type commandRegistryAdapter struct {
	registry completion.Registry
}

func (a commandRegistryAdapter) Register(command jujucmd.Command) {
	a.registry.Register(command)
}

func (a commandRegistryAdapter) RegisterSuperAlias(name, super, forName string, check jujucmd.DeprecationCheck) {
	a.registry.RegisterSuperAlias(name, super, forName, check)
}

func (a commandRegistryAdapter) RegisterDeprecated(command jujucmd.Command, check jujucmd.DeprecationCheck) {
	a.registry.RegisterDeprecated(command, check)
}

type entityCommand struct {
	model  string
	suffix string
}

type completeCommand struct {
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

func parseEntityCommand(args []string) (entityCommand, error) {
	flagSet := flag.NewFlagSet("juju-completion", flag.ContinueOnError)
	flagSet.SetOutput(new(strings.Builder))
	command := entityCommand{}
	flagSet.StringVar(&command.model, "model", "", "")
	flagSet.StringVar(&command.suffix, "suffix", "", "")
	if err := flagSet.Parse(args); err != nil {
		return entityCommand{}, err
	}
	if flagSet.NArg() != 0 {
		return entityCommand{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flagSet.Args(), " "))
	}
	return command, nil
}

func parseCompleteCommand(args []string) (completion.Request, error) {
	flagSet := flag.NewFlagSet("juju-completion", flag.ContinueOnError)
	flagSet.SetOutput(new(strings.Builder))
	command := completeCommand{cword: -1}
	flagSet.Var(&command.words, "word", "")
	flagSet.StringVar(&command.current, "current", "", "")
	flagSet.IntVar(&command.cword, "cword", -1, "")
	if err := flagSet.Parse(args); err != nil {
		return completion.Request{}, err
	}
	if flagSet.NArg() != 0 {
		return completion.Request{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flagSet.Args(), " "))
	}
	if command.cword < 0 {
		return completion.Request{}, fmt.Errorf("missing --cword")
	}
	return completion.Request{
		Words:   append([]string(nil), command.words...),
		Cword:   command.cword,
		Current: command.current,
	}, nil
}

func printLines(values []string) {
	if len(values) == 0 {
		return
	}
	_, _ = fmt.Fprintln(os.Stdout, strings.Join(values, "\n"))
}

func printBackendLines(values []string, err error) int {
	if err != nil {
		jujucmd.WriteError(os.Stderr, err)
		return 1
	}
	printLines(values)
	return 0
}
