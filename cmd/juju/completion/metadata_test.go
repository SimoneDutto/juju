package completion_test

import (
	"os"
	"testing"

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

	snapshot := completion.Describe()
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
	snapshot := completion.Describe()
	names := snapshot.CommandNames()
	if !contains(names, "actions") {
		t.Fatalf("command name %q not found", "actions")
	}
	if !contains(names, "list-actions") {
		t.Fatalf("command alias %q not found", "list-actions")
	}
}

func TestFlagsForResolvesAliases(t *testing.T) {
	snapshot := completion.Describe()
	flags := snapshot.FlagsFor("list-actions")
	if !contains(flags, "--schema") {
		t.Fatalf("expected flag %q for alias-backed lookup", "--schema")
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