package completion_test

import (
	"os"
	"testing"

	basecmd "github.com/juju/juju/cmd/cmd"
	jujucmd "github.com/juju/juju/cmd/cmd"
	"github.com/juju/juju/cmd/juju/commands"
	"github.com/juju/juju/cmd/juju/completion"
	"github.com/juju/juju/juju/osenv"
)

func TestDescribeIncludesDeployAndItsFlags(t *testing.T) {
	dir, err := os.MkdirTemp("", "juju-completion-test-")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	oldHome := osenv.SetJujuXDGDataHome(dir)
	defer osenv.SetJujuXDGDataHome(oldHome)

	snapshot := describeSnapshot()
	deploy, found := findCommand(snapshot, "deploy")
	if !found {
		t.Fatalf("deploy command not found")
	}
	if deploy.Purpose == "" {
		t.Fatalf("deploy command purpose is empty")
	}
	if _, found := findFlag(deploy, "channel"); !found {
		t.Fatalf("deploy flag %q not found", "channel")
	}
	if _, found := findFlag(deploy, "base"); !found {
		t.Fatalf("deploy flag %q not found", "base")
	}
	if _, found := findFlag(deploy, "trust"); !found {
		t.Fatalf("deploy flag %q not found", "trust")
	}
	if len(snapshot.Commands) == 0 {
		t.Fatalf("no commands returned")
	}
}

func TestCommandNamesIncludeAliases(t *testing.T) {
	snapshot := describeSnapshot()
	names := snapshot.CommandNames()
	if !contains(names, "actions") {
		t.Fatalf("command name %q not found", "actions")
	}
	if !contains(names, "list-actions") {
		t.Fatalf("command alias %q not found", "list-actions")
	}
}

func TestFlagsForResolvesAliases(t *testing.T) {
	snapshot := describeSnapshot()
	flags := snapshot.FlagsFor("list-actions")
	if !contains(flags, "--schema") {
		t.Fatalf("expected flag %q for alias-backed lookup", "--schema")
	}
}

func TestDescribeIncludesAutocompleteMetadata(t *testing.T) {
	snapshot := describeSnapshot()
	config, found := findCommand(snapshot, "config")
	if !found {
		t.Fatalf("config command not found")
	}
	if config.Autocomplete == nil {
		t.Fatalf("config command autocomplete metadata is empty")
	}
	if len(config.Autocomplete.Positionals) != 2 {
		t.Fatalf("unexpected positional metadata: %#v", config.Autocomplete.Positionals)
	}
	if config.Autocomplete.Positionals[0].Resources[0].Kind != basecmd.AutocompleteApplications {
		t.Fatalf("unexpected first positional resource: %#v", config.Autocomplete.Positionals[0].Resources)
	}
	second := config.Autocomplete.Positionals[1]
	if len(second.Resources) != 1 || second.Resources[0].Kind != basecmd.AutocompleteApplicationConfig {
		t.Fatalf("unexpected second positional resource: %#v", second.Resources)
	}
	if second.Resources[0].FromPositional == nil || *second.Resources[0].FromPositional != 0 {
		t.Fatalf("unexpected positional dependency: %#v", second.Resources[0].FromPositional)
	}

	deploy, found := findCommand(snapshot, "deploy")
	if !found {
		t.Fatalf("deploy command not found")
	}
	if deploy.Autocomplete == nil {
		t.Fatalf("deploy command autocomplete metadata is empty")
	}
	if len(deploy.Autocomplete.Positionals) != 1 {
		t.Fatalf("unexpected deploy positional metadata: %#v", deploy.Autocomplete.Positionals)
	}
	if deploy.Autocomplete.Positionals[0].Resources[0].Kind != basecmd.AutocompleteCharms {
		t.Fatalf("unexpected deploy positional resource: %#v", deploy.Autocomplete.Positionals[0].Resources)
	}
}

func findCommand(snapshot completion.Snapshot, name string) (completion.Command, bool) {
	for _, command := range snapshot.Commands {
		if command.Name == name {
			return command, true
		}
	}
	return completion.Command{}, false
}

func findFlag(command completion.Command, name string) (completion.Flag, bool) {
	for _, flag := range command.Flags {
		if flag.Name == name {
			return flag, true
		}
	}
	return completion.Flag{}, false
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func describeSnapshot() completion.Snapshot {
	return completion.Describe(func(r completion.Registry) {
		commands.RegisterCommands(commandRegistryAdapter{registry: r})
	})
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
