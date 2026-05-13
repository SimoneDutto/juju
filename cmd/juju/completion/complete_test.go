package completion

import (
	"testing"

	"github.com/juju/juju/jujuclient"
	"github.com/juju/juju/rpc/params"
)

func TestCompleteHelpReturnsCommands(t *testing.T) {
	backend := &Backend{
		Store:             jujuclient.NewMemStore(),
		currentController: defaultCurrentController,
		currentModel:      unreachableCurrentModel,
		statusFetcher:     unreachableStatusFetcher,
	}

	candidates, err := backend.Complete(Describe(), Request{
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
		Store:             jujuclient.NewMemStore(),
		currentController: defaultCurrentController,
		currentModel:      unreachableCurrentModel,
		statusFetcher:     unreachableStatusFetcher,
	}

	candidates, err := backend.Complete(Describe(), Request{
		Words:   []string{"juju", "deploy", "--c"},
		Cword:   2,
		Current: "--c",
	})
	if err != nil {
		t.Fatalf("completing flags: %v", err)
	}
	assertEqualStrings(t, candidates, []string{"--channel", "--config", "--constraints"})
}

func TestCompleteApplicationsFromCommandPosition(t *testing.T) {
	backend := &Backend{
		Store:             jujuclient.NewMemStore(),
		currentController: defaultCurrentController,
		currentModel:      func() (string, error) { return "test-36:admin/example", nil },
		statusFetcher: func(modelIdentifier string) (*params.FullStatus, error) {
			if modelIdentifier != "test-36:admin/example" {
				t.Fatalf("unexpected model identifier: %s", modelIdentifier)
			}
			return &params.FullStatus{Applications: map[string]params.ApplicationStatus{
				"api":     {},
				"backend": {},
			}}, nil
		},
	}

	candidates, err := backend.Complete(Describe(), Request{
		Words:   []string{"juju", "config", "b"},
		Cword:   2,
		Current: "b",
	})
	if err != nil {
		t.Fatalf("completing applications: %v", err)
	}
	assertEqualStrings(t, candidates, []string{"backend"})
}

func TestCompleteSwitchMergesControllersAndModels(t *testing.T) {
	store := jujuclient.NewMemStore()
	store.Controllers["test-36"] = jujuclient.ControllerDetails{}
	store.Controllers["other"] = jujuclient.ControllerDetails{}
	store.CurrentControllerName = "test-36"
	store.Models["test-36"] = &jujuclient.ControllerModels{
		Models: map[string]jujuclient.ModelDetails{
			"admin/example": {},
		},
	}

	backend := &Backend{
		Store:             store,
		currentController: defaultCurrentController,
		currentModel:      unreachableCurrentModel,
		statusFetcher:     unreachableStatusFetcher,
	}

	candidates, err := backend.Complete(Describe(), Request{
		Words:   []string{"juju", "switch", "test"},
		Cword:   2,
		Current: "test",
	})
	if err != nil {
		t.Fatalf("completing switch targets: %v", err)
	}
	assertEqualStrings(t, candidates, []string{"test-36", "test-36:admin/example"})
}
