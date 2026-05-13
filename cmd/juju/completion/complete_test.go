package completion

import (
	"testing"

	"github.com/juju/juju/api/jujuclient"
	basecmd "github.com/juju/juju/cmd/cmd"
	"github.com/juju/juju/rpc/params"
)

func TestCompleteHelpReturnsCommands(t *testing.T) {
	backend := &Backend{
		Store:         jujuclient.NewMemStore(),
		currentModel:  unreachableCurrentModel,
		statusFetcher: unreachableStatusFetcher,
	}

	candidates, err := backend.Complete(testSnapshot(), Request{
		Words:   []string{"juju", "help", "co"},
		Cword:   2,
		Current: "co",
	})
	if err != nil {
		t.Fatalf("completing help: %v", err)
	}
	if len(candidates) == 0 {
		t.Fatalf("expected command candidates")
	}
	if candidates[0] != "config" {
		t.Fatalf("unexpected first candidate: %v", candidates)
	}
}

func TestCompleteFlagsForCommand(t *testing.T) {
	backend := &Backend{
		Store:         jujuclient.NewMemStore(),
		currentModel:  unreachableCurrentModel,
		statusFetcher: unreachableStatusFetcher,
	}

	candidates, err := backend.Complete(testSnapshot(), Request{
		Words:   []string{"juju", "deploy", "--c"},
		Cword:   2,
		Current: "--c",
	})
	if err != nil {
		t.Fatalf("completing flags: %v", err)
	}
	assertEqualStrings(t, candidates, []string{"--channel", "--config", "--constraints"})
}

func TestCompleteCommandNamesUsePrefixMatching(t *testing.T) {
	backend := &Backend{
		Store:         jujuclient.NewMemStore(),
		currentModel:  unreachableCurrentModel,
		statusFetcher: unreachableStatusFetcher,
	}

	candidates, err := backend.Complete(testSnapshot(), Request{
		Words:   []string{"juju", "status"},
		Cword:   1,
		Current: "status",
	})
	if err != nil {
		t.Fatalf("completing exact command name: %v", err)
	}
	assertEqualStrings(t, candidates, []string{"status", "status-history"})
}

func TestCompleteApplicationsFromCommandPosition(t *testing.T) {
	backend := &Backend{
		Store:        jujuclient.NewMemStore(),
		currentModel: func(_ jujuclient.ClientStore) (string, error) { return "test-36:admin/example", nil },
		statusFetcher: func(_ jujuclient.ClientStore, modelIdentifier string) (*params.FullStatus, error) {
			if modelIdentifier != "test-36:admin/example" {
				t.Fatalf("unexpected model identifier: %s", modelIdentifier)
			}
			return &params.FullStatus{Applications: map[string]params.ApplicationStatus{
				"api":     {},
				"backend": {},
			}}, nil
		},
	}

	candidates, err := backend.Complete(testSnapshot(), Request{
		Words:   []string{"juju", "config", "b"},
		Cword:   2,
		Current: "b",
	})
	if err != nil {
		t.Fatalf("completing applications: %v", err)
	}
	assertEqualStrings(t, candidates, []string{"backend"})
}

func TestCompleteApplicationConfigKeysFromSecondPositional(t *testing.T) {
	backend := &Backend{
		Store:         jujuclient.NewMemStore(),
		currentModel:  func(_ jujuclient.ClientStore) (string, error) { return "test-36:admin/example", nil },
		statusFetcher: unreachableStatusFetcher,
		applicationConfigFetcher: func(_ jujuclient.ClientStore, modelIdentifier, application string) (*params.ApplicationGetResults, error) {
			if modelIdentifier != "test-36:admin/example" {
				t.Fatalf("unexpected model identifier: %s", modelIdentifier)
			}
			if application != "api" {
				t.Fatalf("unexpected application: %s", application)
			}
			return &params.ApplicationGetResults{CharmConfig: map[string]any{"port": map[string]any{}, "timeout": map[string]any{}}}, nil
		},
	}

	candidates, err := backend.Complete(testSnapshot(), Request{
		Words:   []string{"juju", "config", "api", "po"},
		Cword:   3,
		Current: "po",
	})
	if err != nil {
		t.Fatalf("completing config keys: %v", err)
	}
	assertEqualStrings(t, candidates, []string{"port"})
}

func TestCompleteApplicationsIgnoresFlagValuesWhenFindingPosition(t *testing.T) {
	backend := &Backend{
		Store:        jujuclient.NewMemStore(),
		currentModel: unreachableCurrentModel,
		statusFetcher: func(_ jujuclient.ClientStore, modelIdentifier string) (*params.FullStatus, error) {
			if modelIdentifier != "test-36:admin/example" {
				t.Fatalf("unexpected model identifier: %s", modelIdentifier)
			}
			return &params.FullStatus{Applications: map[string]params.ApplicationStatus{
				"api":     {},
				"backend": {},
			}}, nil
		},
	}

	candidates, err := backend.Complete(testSnapshot(), Request{
		Words:   []string{"juju", "config", "--model", "test-36:admin/example", "b"},
		Cword:   4,
		Current: "b",
	})
	if err != nil {
		t.Fatalf("completing applications with model flag: %v", err)
	}
	assertEqualStrings(t, candidates, []string{"backend"})
}

func TestCompleteSwitchMergesControllersAndModels(t *testing.T) {
	store := jujuclient.NewMemStore()
	store.Controllers["test-36"] = jujuclient.ControllerDetails{}
	store.Controllers["other"] = jujuclient.ControllerDetails{}
	store.Models["test-36"] = &jujuclient.ControllerModels{
		Models: map[string]jujuclient.ModelDetails{
			"admin/example": {},
		},
	}

	backend := &Backend{
		Store:         store,
		currentModel:  unreachableCurrentModel,
		statusFetcher: unreachableStatusFetcher,
	}

	candidates, err := backend.Complete(testSnapshot(), Request{
		Words:   []string{"juju", "switch", "test"},
		Cword:   2,
		Current: "test",
	})
	if err != nil {
		t.Fatalf("completing switch targets: %v", err)
	}
	assertEqualStrings(t, candidates, []string{"test-36", "test-36:admin/example"})
}

func testSnapshot() Snapshot {
	return Snapshot{Commands: []Command{
		{
			Name:  "config",
			Flags: []Flag{{Name: "model"}, {Name: "m"}},
			Autocomplete: &basecmd.Autocomplete{Positionals: []basecmd.AutocompleteArg{
				{Resources: []basecmd.AutocompleteResource{{Kind: basecmd.AutocompleteApplications}}},
				{Resources: []basecmd.AutocompleteResource{{Kind: basecmd.AutocompleteApplicationConfig, FromPositional: basecmd.AutocompleteReference(0)}}, Repeat: true},
			}},
		},
		{Name: "controllers"},
		{Name: "deploy", Flags: []Flag{{Name: "channel"}, {Name: "config"}, {Name: "constraints"}}},
		{Name: "show-status-log"},
		{Name: "status"},
		{Name: "status-history"},
		{Name: "switch", Autocomplete: &basecmd.Autocomplete{Positionals: []basecmd.AutocompleteArg{{Resources: []basecmd.AutocompleteResource{{Kind: basecmd.AutocompleteControllers}, {Kind: basecmd.AutocompleteModels}}}}}},
	}}
}
