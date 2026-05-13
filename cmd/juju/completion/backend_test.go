package completion

import (
	"context"
	"testing"

	"github.com/juju/juju/api/jujuclient"
	"github.com/juju/juju/rpc/params"
)

func TestControllersReturnsSortedNames(t *testing.T) {
	store := jujuclient.NewMemStore()
	store.Controllers["zeta"] = jujuclient.ControllerDetails{}
	store.Controllers["alpha"] = jujuclient.ControllerDetails{}

	backend := &Backend{Store: store, currentModel: unreachableCurrentModel, statusFetcher: unreachableStatusFetcher}
	controllers, err := backend.Controllers()
	if err != nil {
		t.Fatalf("listing controllers: %v", err)
	}
	assertEqualStrings(t, controllers, []string{"alpha", "zeta"})
}

func TestModelsReturnsControllerQualifiedModels(t *testing.T) {
	store := jujuclient.NewMemStore()
	store.Controllers["alpha"] = jujuclient.ControllerDetails{}
	store.Controllers["beta"] = jujuclient.ControllerDetails{}
	store.Models["alpha"] = &jujuclient.ControllerModels{
		Models: map[string]jujuclient.ModelDetails{
			"admin/first":  {},
			"admin/second": {},
		},
		CurrentModel: "admin/first",
	}
	store.Models["beta"] = &jujuclient.ControllerModels{
		Models: map[string]jujuclient.ModelDetails{
			"admin/other": {},
		},
	}

	backend := &Backend{Store: store, currentModel: unreachableCurrentModel, statusFetcher: unreachableStatusFetcher}
	models, err := backend.Models()
	if err != nil {
		t.Fatalf("listing models: %v", err)
	}
	assertEqualStrings(t, models, []string{
		"alpha:admin/first",
		"alpha:admin/second",
		"beta:admin/other",
	})
}

func TestApplicationsUnitsAndMachinesUseResolvedModel(t *testing.T) {
	store := jujuclient.NewMemStore()
	store.Controllers["alpha"] = jujuclient.ControllerDetails{}
	store.CurrentControllerName = "alpha"
	store.Accounts["alpha"] = jujuclient.AccountDetails{User: "admin"}
	store.Models["alpha"] = &jujuclient.ControllerModels{
		Models: map[string]jujuclient.ModelDetails{
			"admin/first": {},
		},
		CurrentModel: "admin/first",
	}

	backend := &Backend{
		Store:        store,
		currentModel: func(_ jujuclient.ClientStore) (string, error) { return "alpha:first", nil },
		statusFetcher: func(_ jujuclient.ClientStore, modelIdentifier string) (*params.FullStatus, error) {
			if modelIdentifier != "alpha:first" {
				t.Fatalf("unexpected model resolution: %s", modelIdentifier)
			}
			return &params.FullStatus{
				Machines: map[string]params.MachineStatus{
					"0": {},
					"1": {},
				},
				Applications: map[string]params.ApplicationStatus{
					"api": {
						Units: map[string]params.UnitStatus{
							"api/0": {},
						},
					},
					"web": {
						Units: map[string]params.UnitStatus{
							"web/0": {},
							"web/1": {},
						},
					},
				},
			}, nil
		},
	}

	applications, err := backend.Applications("")
	if err != nil {
		t.Fatalf("listing applications: %v", err)
	}
	assertEqualStrings(t, applications, []string{"api", "web"})

	units, err := backend.Units("alpha:first", ":")
	if err != nil {
		t.Fatalf("listing units: %v", err)
	}
	assertEqualStrings(t, units, []string{"api/0:", "web/0:", "web/1:"})

	machines, err := backend.Machines("")
	if err != nil {
		t.Fatalf("listing machines: %v", err)
	}
	assertEqualStrings(t, machines, []string{"0", "1"})
}

func TestApplicationsPassExplicitModelThrough(t *testing.T) {
	backend := &Backend{
		Store:        jujuclient.NewMemStore(),
		currentModel: unreachableCurrentModel,
		statusFetcher: func(_ jujuclient.ClientStore, modelIdentifier string) (*params.FullStatus, error) {
			if modelIdentifier != "test-36:admin/example" {
				t.Fatalf("unexpected explicit model identifier: %s", modelIdentifier)
			}
			return &params.FullStatus{Applications: map[string]params.ApplicationStatus{"api": {}}}, nil
		},
	}

	applications, err := backend.Applications("test-36:admin/example")
	if err != nil {
		t.Fatalf("listing applications for explicit model: %v", err)
	}
	assertEqualStrings(t, applications, []string{"api"})
}

func TestApplicationConfigKeysPassApplicationAndModelThrough(t *testing.T) {
	backend := &Backend{
		Store:         jujuclient.NewMemStore(),
		currentModel:  unreachableCurrentModel,
		statusFetcher: unreachableStatusFetcher,
		applicationConfigFetcher: func(_ jujuclient.ClientStore, modelIdentifier, application string) (*params.ApplicationGetResults, error) {
			if modelIdentifier != "test-36:admin/example" {
				t.Fatalf("unexpected explicit model identifier: %s", modelIdentifier)
			}
			if application != "api" {
				t.Fatalf("unexpected application: %s", application)
			}
			return &params.ApplicationGetResults{
				CharmConfig:       map[string]any{"port": map[string]any{}},
				ApplicationConfig: map[string]any{"trust": map[string]any{}},
			}, nil
		},
	}

	keys, err := backend.ApplicationConfigKeys("test-36:admin/example", "api")
	if err != nil {
		t.Fatalf("listing application config keys: %v", err)
	}
	assertEqualStrings(t, keys, []string{"port", "trust"})
}

func TestCharmsPassPrefixThrough(t *testing.T) {
	backend := &Backend{
		Store:                    jujuclient.NewMemStore(),
		currentModel:             unreachableCurrentModel,
		statusFetcher:            unreachableStatusFetcher,
		applicationConfigFetcher: unreachableApplicationConfigFetcher,
		charmFinder: func(_ context.Context, prefix string) ([]string, error) {
			if prefix != "post" {
				t.Fatalf("unexpected charm prefix: %s", prefix)
			}
			return []string{"postgresql", "postgresql-k8s"}, nil
		},
	}

	charms, err := backend.Charms("post")
	if err != nil {
		t.Fatalf("listing charms: %v", err)
	}
	assertEqualStrings(t, charms, []string{"postgresql", "postgresql-k8s"})
}

func TestCharmsIgnoresEmptyPrefix(t *testing.T) {
	backend := &Backend{
		Store:                    jujuclient.NewMemStore(),
		currentModel:             unreachableCurrentModel,
		statusFetcher:            unreachableStatusFetcher,
		applicationConfigFetcher: unreachableApplicationConfigFetcher,
		charmFinder: func(context.Context, string) ([]string, error) {
			t.Fatalf("charm finder should not be called")
			return nil, nil
		},
	}

	charms, err := backend.Charms("")
	if err != nil {
		t.Fatalf("listing charms: %v", err)
	}
	assertEqualStrings(t, charms, nil)
}

func TestCharmsSupportsCharmhubURLPrefix(t *testing.T) {
	backend := &Backend{
		Store:                    jujuclient.NewMemStore(),
		currentModel:             unreachableCurrentModel,
		statusFetcher:            unreachableStatusFetcher,
		applicationConfigFetcher: unreachableApplicationConfigFetcher,
		charmFinder: func(_ context.Context, prefix string) ([]string, error) {
			if prefix != "post" {
				t.Fatalf("unexpected charm prefix: %s", prefix)
			}
			return []string{"postgresql"}, nil
		},
	}

	charms, err := backend.Charms("ch:post")
	if err != nil {
		t.Fatalf("listing charms: %v", err)
	}
	assertEqualStrings(t, charms, []string{"ch:postgresql"})
}

func assertEqualStrings(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("unexpected length: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected values: got %v want %v", got, want)
		}
	}
}

func unreachableCurrentModel(_ jujuclient.ClientStore) (string, error) {
	panic("current model should not be called")
}

func unreachableStatusFetcher(jujuclient.ClientStore, string) (*params.FullStatus, error) {
	panic("status fetcher should not be called")
}

func unreachableApplicationConfigFetcher(jujuclient.ClientStore, string, string) (*params.ApplicationGetResults, error) {
	panic("application config fetcher should not be called")
}
