package completion

import (
	"encoding/json"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/juju/errors"

	"github.com/juju/juju/cmd/modelcmd"
	"github.com/juju/juju/juju/osenv"
	"github.com/juju/juju/jujuclient"
	"github.com/juju/juju/rpc/params"
)

type currentControllerFunc func(jujuclient.ClientStore) (string, error)
type currentModelFunc func() (string, error)
type statusFetcherFunc func(string) (*params.FullStatus, error)

// Backend serves shell completion candidates backed by Juju client state.
type Backend struct {
	Store             jujuclient.ClientStore
	currentController currentControllerFunc
	currentModel      currentModelFunc
	statusFetcher     statusFetcherFunc
}

// NewBackend returns a completion backend using the local Juju client store.
func NewBackend() *Backend {
	return &Backend{
		Store:             jujuclient.NewFileClientStore(),
		currentController: modelcmd.DetermineCurrentController,
		currentModel:      determineCurrentModel,
		statusFetcher:     fetchStatus,
	}
}

// Controllers returns controller names from the local client store.
func (b *Backend) Controllers() ([]string, error) {
	controllers, err := b.Store.AllControllers()
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(controllers))
	for name := range controllers {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

// Models returns model names suitable for `--model` completion.
// It emits `controller:model` for all known controllers, and bare model names
// for the current controller to match existing shell behavior.
func (b *Backend) Models() ([]string, error) {
	currentController, err := b.currentController(b.Store)
	if err != nil {
		return nil, err
	}
	controllers, err := b.Controllers()
	if err != nil {
		return nil, err
	}

	result := make([]string, 0)
	for _, controllerName := range controllers {
		models, err := b.Store.AllModels(controllerName)
		if err != nil {
			if errors.Is(err, errors.NotFound) {
				continue
			}
			return nil, err
		}
		modelNames := mapKeys(models)
		for _, modelName := range modelNames {
			result = append(result, controllerName+":"+modelName)
		}
		if controllerName == currentController {
			result = append(result, modelNames...)
		}
	}
	sort.Strings(result)
	return result, nil
}

// Applications returns application names for the resolved model.
func (b *Backend) Applications(model string) ([]string, error) {
	status, err := b.status(model)
	if err != nil {
		return nil, err
	}
	return mapKeys(status.Applications), nil
}

// Units returns unit names for the resolved model.
func (b *Backend) Units(model, suffix string) ([]string, error) {
	status, err := b.status(model)
	if err != nil {
		return nil, err
	}
	units := make([]string, 0)
	applications := mapKeys(status.Applications)
	for _, applicationName := range applications {
		application := status.Applications[applicationName]
		for _, unitName := range mapKeys(application.Units) {
			units = append(units, unitName+suffix)
		}
	}
	sort.Strings(units)
	return units, nil
}

// Machines returns machine identifiers for the resolved model.
func (b *Backend) Machines(model string) ([]string, error) {
	status, err := b.status(model)
	if err != nil {
		return nil, err
	}
	return mapKeys(status.Machines), nil
}

func (b *Backend) status(model string) (*params.FullStatus, error) {
	modelIdentifier, err := b.resolveModel(model)
	if err != nil {
		return nil, err
	}
	return b.statusFetcher(modelIdentifier)
}

func (b *Backend) resolveModel(model string) (string, error) {
	if model != "" {
		return model, nil
	}
	return b.currentModel()
}


func determineCurrentModel() (string, error) {
	if model := os.Getenv(osenv.JujuModelEnvKey); model != "" {
		return model, nil
	}
	binary, err := jujuBinary()
	if err != nil {
		return "", err
	}
	output, err := exec.Command(binary, "switch").Output()
	if err != nil {
		return "", commandError(err)
	}
	model := strings.TrimSpace(string(output))
	if model == "" {
		return "", errors.NotFoundf("current model")
	}
	return model, nil
}

func fetchStatus(modelIdentifier string) (*params.FullStatus, error) {
	binary, err := jujuBinary()
	if err != nil {
		return nil, err
	}
	output, err := exec.Command(binary, "status", "--model", modelIdentifier, "--format", "json").Output()
	if err != nil {
		return nil, commandError(err)
	}
	var status params.FullStatus
	if err := json.Unmarshal(output, &status); err != nil {
		return nil, errors.Annotate(err, "decoding juju status output")
	}
	return &status, nil
}

func mapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func jujuBinary() (string, error) {
	for _, candidate := range []string{"juju", "juju-2"} {
		path, err := exec.LookPath(candidate)
		if err == nil {
			return path, nil
		}
	}
	return "", errors.NotFoundf("juju binary")
}

func commandError(err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		stderr := strings.TrimSpace(string(exitErr.Stderr))
		if stderr != "" {
			return errors.New(stderr)
		}
	}
	return errors.Annotate(err, "running juju command")
}