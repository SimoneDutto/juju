package completion

import (
	"context"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/juju/errors"

	applicationclient "github.com/juju/juju/api/client/application"
	apiclient "github.com/juju/juju/api/client/client"
	"github.com/juju/juju/api/connector"
	"github.com/juju/juju/api/jujuclient"
	"github.com/juju/juju/internal/charmhub"
	internallogger "github.com/juju/juju/internal/logger"
	"github.com/juju/juju/juju/osenv"
	"github.com/juju/juju/rpc/params"
)

type currentModelFunc func(jujuclient.ClientStore) (string, error)
type statusFetcherFunc func(jujuclient.ClientStore, string) (*params.FullStatus, error)
type applicationConfigFetcherFunc func(jujuclient.ClientStore, string, string) (*params.ApplicationGetResults, error)
type charmFinderFunc func(context.Context, string) ([]string, error)

// Backend serves shell completion candidates backed by Juju client state.
type Backend struct {
	Store                    jujuclient.ClientStore
	currentModel             currentModelFunc
	statusFetcher            statusFetcherFunc
	applicationConfigFetcher applicationConfigFetcherFunc
	charmFinder              charmFinderFunc
}

// NewBackend returns a completion backend using the local Juju client store.
func NewBackend() *Backend {
	return &Backend{
		Store:                    jujuclient.NewFileClientStore(),
		currentModel:             determineCurrentModel,
		statusFetcher:            fetchStatus,
		applicationConfigFetcher: fetchApplicationConfig,
		charmFinder:              fetchCharmNames,
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

// ApplicationConfigKeys returns config keys for the supplied application.
func (b *Backend) ApplicationConfigKeys(model, application string) ([]string, error) {
	if application == "" {
		return nil, nil
	}
	modelIdentifier, err := b.resolveModel(model)
	if err != nil {
		return nil, err
	}
	result, err := b.applicationConfigFetcher(b.Store, modelIdentifier, application)
	if err != nil {
		return nil, err
	}
	return mergeCandidates(mapKeys(result.CharmConfig), mapKeys(result.ApplicationConfig)), nil
}

// Charms returns Charmhub charm names matching the supplied prefix.
func (b *Backend) Charms(prefix string) ([]string, error) {
	if strings.TrimSpace(prefix) == "" {
		return nil, nil
	}
	query := prefix
	candidatePrefix := ""
	if strings.HasPrefix(prefix, "ch:") {
		query = strings.TrimPrefix(prefix, "ch:")
		candidatePrefix = "ch:"
		if query == "" {
			return nil, nil
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	finder := b.charmFinder
	if finder == nil {
		finder = fetchCharmNames
	}
	names, err := finder(ctx, query)
	if err != nil {
		return nil, nil
	}
	if candidatePrefix != "" {
		for i, name := range names {
			names[i] = candidatePrefix + name
		}
	}
	return names, nil
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
// the Client.Status facade.
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

// fetchApplicationConfig opens a direct API connection to the resolved model
// and fetches config metadata for the named application.
func fetchApplicationConfig(store jujuclient.ClientStore, modelIdentifier, applicationName string) (*params.ApplicationGetResults, error) {
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

	return applicationclient.NewClient(apiConn).Get(dialCtx, applicationName)
}

func fetchCharmNames(ctx context.Context, prefix string) ([]string, error) {
	serverURL := os.Getenv("CHARMHUB_URL")
	if serverURL == "" {
		serverURL = charmhub.DefaultServerURL
	}
	client, err := charmhub.NewClient(charmhub.Config{
		URL:    serverURL,
		Logger: internallogger.GetLogger("juju.completion.charmhub"),
	})
	if err != nil {
		return nil, err
	}
	results, err := client.Find(ctx, prefix, charmhub.WithFindType("charm"))
	if errors.Is(err, errors.NotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(results))
	for _, result := range results {
		if result.Name != "" {
			names = append(names, result.Name)
		}
	}
	return names, nil
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
