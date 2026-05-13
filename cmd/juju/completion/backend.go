package completion

import (
	"context"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/juju/errors"

	apiclient "github.com/juju/juju/api/client/client"
	"github.com/juju/juju/api/connector"
	"github.com/juju/juju/api/jujuclient"
	internallogger "github.com/juju/juju/internal/logger"
	"github.com/juju/juju/juju/osenv"
	"github.com/juju/juju/rpc/params"
)

type currentModelFunc func(jujuclient.ClientStore) (string, error)
type statusFetcherFunc func(jujuclient.ClientStore, string) (*params.FullStatus, error)

// Backend serves shell completion candidates backed by Juju client state.
type Backend struct {
	Store         jujuclient.ClientStore
	currentModel  currentModelFunc
	statusFetcher statusFetcherFunc
}

// NewBackend returns a completion backend using the local Juju client store.
func NewBackend() *Backend {
	return &Backend{
		Store:         jujuclient.NewFileClientStore(),
		currentModel:  determineCurrentModel,
		statusFetcher: fetchStatus,
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
// Every model is emitted as `controller:model` for consistency.
func (b *Backend) Models() ([]string, error) {
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
		for _, modelName := range mapKeys(models) {
			result = append(result, controllerName+":"+modelName)
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
	return b.statusFetcher(b.Store, modelIdentifier)
}

func (b *Backend) resolveModel(model string) (string, error) {
	if model != "" {
		return model, nil
	}
	return b.currentModel(b.Store)
}

// determineCurrentModel reads the current model from the local client store.
// It checks JUJU_MODEL first, then falls back to the store's current
// controller and current model — no subprocess is required.
func determineCurrentModel(store jujuclient.ClientStore) (string, error) {
	if model := os.Getenv(osenv.JujuModelEnvKey); model != "" {
		return model, nil
	}
	controller, err := store.CurrentController()
	if err != nil {
		return "", err
	}
	model, err := store.CurrentModel(controller)
	if err != nil {
		return "", err
	}
	return controller + ":" + model, nil
}

// fetchStatus opens a direct API connection to the resolved model and calls
// the Client.Status facade. Dial timeout is 3 s; on any error the empty
// status is returned so completion never blocks the shell.
func fetchStatus(store jujuclient.ClientStore, modelIdentifier string) (*params.FullStatus, error) {
	controllerName, modelUUID, err := resolveModelUUID(store, modelIdentifier)
	if err != nil {
		return nil, err
	}

	conn, err := connector.NewClientStore(connector.ClientStoreConfig{
		ControllerName: controllerName,
		ModelUUID:      modelUUID,
		ClientStore:    store,
	})
	if err != nil {
		return nil, err
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	apiConn, err := conn.Connect(dialCtx)
	if err != nil {
		return nil, err
	}
	defer apiConn.Close()

	logger := internallogger.GetLogger("juju.completion")
	return apiclient.NewClient(apiConn, logger).Status(dialCtx, nil)
}

// resolveModelUUID parses a "controller:model" or bare "model" identifier and
// returns the controller name and model UUID from the local store.
func resolveModelUUID(store jujuclient.ClientStore, modelIdentifier string) (string, string, error) {
	var controllerName, modelName string
	if idx := strings.Index(modelIdentifier, ":"); idx >= 0 {
		controllerName = modelIdentifier[:idx]
		modelName = modelIdentifier[idx+1:]
	} else {
		var err error
		controllerName, err = store.CurrentController()
		if err != nil {
			return "", "", err
		}
		modelName = modelIdentifier
	}

	models, err := store.AllModels(controllerName)
	if err != nil {
		return "", "", err
	}
	details, ok := models[modelName]
	if !ok {
		return "", "", errors.NotFoundf("model %q on controller %q", modelName, controllerName)
	}
	return controllerName, details.ModelUUID, nil
}

func mapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
