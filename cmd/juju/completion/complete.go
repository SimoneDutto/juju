package completion

import (
	"sort"
	"strings"

	basecmd "github.com/juju/juju/cmd/cmd"
)

// Request describes a single shell completion request.
type Request struct {
	Words   []string
	Cword   int
	Current string
}

type positionalArg struct {
	Value string
}

type positionalContext struct {
	Args    []positionalArg
	Current int
}

// Complete returns completion candidates for the supplied shell context.
func (b *Backend) Complete(snapshot Snapshot, request Request) ([]string, error) {
	if len(request.Words) == 0 || request.Cword < 0 || request.Cword >= len(request.Words) {
		return nil, nil
	}

	current := request.Current
	if current == "" {
		current = request.word(request.Cword)
	}

	action := request.action()

	switch {
	case request.Cword <= 1:
		return filterCandidates(snapshot.CommandNames(), current), nil
	case action == "help":
		return filterCandidates(snapshot.CommandNames(), current), nil
	}

	command, ok := snapshot.Lookup(action)
	if !ok {
		return nil, nil
	}

	if isFlagLike(current) {
		return filterCandidates(snapshot.FlagsFor(action), current), nil
	}

	model := request.model()
	if resources, ok := command.resourcesForFlagValue(request); ok {
		candidates, err := b.completeResources(resources, model, positionalContext{})
		if err != nil {
			return nil, err
		}
		return filterCandidates(candidates, current), nil
	}

	context := request.positionalContext(command)
	resources, ok := command.resourcesForPositional(context.Current)
	if !ok {
		return nil, nil
	}
	candidates, err := b.completeResources(resources, model, context)
	if err != nil {
		return nil, err
	}
	return filterCandidates(candidates, current), nil
}

func (r Request) word(index int) string {
	if index < 0 || index >= len(r.Words) {
		return ""
	}
	return r.Words[index]
}

func (r Request) action() string {
	if len(r.Words) < 2 {
		return ""
	}
	return r.Words[1]
}

func (r Request) model() string {
	upper := r.Cword
	if upper >= len(r.Words) {
		upper = len(r.Words) - 1
	}
	for i := 1; i <= upper; i++ {
		token := r.Words[i]
		switch {
		case token == "--model" || token == "-m":
			if i+1 < len(r.Words) {
				return r.Words[i+1]
			}
		case strings.HasPrefix(token, "--model="):
			return strings.TrimPrefix(token, "--model=")
		}
	}
	return ""
}

func (r Request) positionalContext(command Command) positionalContext {
	upper := r.Cword
	if upper >= len(r.Words) {
		upper = len(r.Words) - 1
	}

	result := positionalContext{Current: -1}
	endOfOptions := false
	expectingValue := false
	for i := 2; i <= upper; i++ {
		token := r.Words[i]
		if expectingValue {
			expectingValue = false
			continue
		}
		if !endOfOptions {
			if token == "--" {
				endOfOptions = true
				continue
			}
			if name, hasValue, ok := parseFlagToken(token); ok {
				if !hasValue {
					if flag, found := command.lookupFlag(name); found && !flag.IsBoolean {
						expectingValue = true
					}
				}
				continue
			}
		}
		result.Args = append(result.Args, positionalArg{Value: token})
		if i == r.Cword {
			result.Current = len(result.Args) - 1
		}
	}
	return result
}

func (c Command) resourcesForFlagValue(request Request) ([]basecmd.AutocompleteResource, bool) {
	name, ok := request.flagExpectingValue()
	if !ok {
		return nil, false
	}
	return c.lookupFlagResources(name)
}

func (c Command) resourcesForPositional(index int) ([]basecmd.AutocompleteResource, bool) {
	if c.Autocomplete == nil || index < 0 {
		return nil, false
	}
	for i, positional := range c.Autocomplete.Positionals {
		if i == index || positional.Repeat && i <= index {
			if len(positional.Resources) == 0 {
				return nil, false
			}
			return positional.Resources, true
		}
	}
	return nil, false
}

func (c Command) lookupFlag(name string) (Flag, bool) {
	for _, flag := range c.Flags {
		if flag.Name == name {
			return flag, true
		}
	}
	return Flag{}, false
}

func (c Command) lookupFlagResources(name string) ([]basecmd.AutocompleteResource, bool) {
	if c.Autocomplete != nil {
		for _, flag := range c.Autocomplete.Flags {
			for _, candidate := range flag.Names {
				if candidate == name {
					return flag.Resources, len(flag.Resources) > 0
				}
			}
		}
	}
	switch name {
	case "controller", "c":
		return []basecmd.AutocompleteResource{{Kind: basecmd.AutocompleteControllers}}, true
	case "model", "m":
		return []basecmd.AutocompleteResource{{Kind: basecmd.AutocompleteModels}}, true
	case "application":
		return []basecmd.AutocompleteResource{{Kind: basecmd.AutocompleteApplications}}, true
	case "unit":
		return []basecmd.AutocompleteResource{{Kind: basecmd.AutocompleteUnits}}, true
	case "machine":
		return []basecmd.AutocompleteResource{{Kind: basecmd.AutocompleteMachines}}, true
	default:
		return nil, false
	}
}

func (r Request) flagExpectingValue() (string, bool) {
	previous := r.word(r.Cword - 1)
	name, hasValue, ok := parseFlagToken(previous)
	if !ok || hasValue {
		return "", false
	}
	return name, true
}

func parseFlagToken(token string) (string, bool, bool) {
	if !strings.HasPrefix(token, "-") || token == "-" || token == "--" {
		return "", false, false
	}
	if strings.HasPrefix(token, "--") {
		name := strings.TrimPrefix(token, "--")
		if name == "" {
			return "", false, false
		}
		if index := strings.IndexRune(name, '='); index >= 0 {
			return name[:index], true, true
		}
		return name, false, true
	}
	name := strings.TrimPrefix(token, "-")
	if name == "" {
		return "", false, false
	}
	return name, false, true
}

func isFlagLike(token string) bool {
	_, hasValue, ok := parseFlagToken(token)
	return ok && !hasValue
}

func (b *Backend) completeResources(resources []basecmd.AutocompleteResource, model string, context positionalContext) ([]string, error) {
	groups := make([][]string, 0, len(resources))
	for _, resource := range resources {
		candidates, err := b.completeResource(resource, model, context)
		if err != nil {
			return nil, err
		}
		groups = append(groups, candidates)
	}
	return mergeCandidates(groups...), nil
}

func (b *Backend) completeResource(resource basecmd.AutocompleteResource, model string, context positionalContext) ([]string, error) {
	switch resource.Kind {
	case basecmd.AutocompleteControllers:
		return b.Controllers()
	case basecmd.AutocompleteModels:
		return b.Models()
	case basecmd.AutocompleteApplications:
		return b.Applications(model)
	case basecmd.AutocompleteUnits:
		return b.Units(model, "")
	case basecmd.AutocompleteMachines:
		return b.Machines(model)
	case basecmd.AutocompleteApplicationConfig:
		if resource.FromPositional == nil {
			return nil, nil
		}
		index := *resource.FromPositional
		if index < 0 || index >= len(context.Args) {
			return nil, nil
		}
		return b.ApplicationConfigKeys(model, context.Args[index].Value)
	case basecmd.AutocompleteCharms:
		if context.Current < 0 || context.Current >= len(context.Args) {
			return nil, nil
		}
		return b.Charms(context.Args[context.Current].Value)
	default:
		return nil, nil
	}
}

func filterCandidates(candidates []string, current string) []string {
	if current == "" {
		return candidates
	}
	filtered := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if strings.HasPrefix(candidate, current) {
			filtered = append(filtered, candidate)
		}
	}
	return filtered
}

func mergeCandidates(groups ...[]string) []string {
	seen := make(map[string]struct{})
	merged := make([]string, 0)
	for _, group := range groups {
		for _, candidate := range group {
			if _, ok := seen[candidate]; ok {
				continue
			}
			seen[candidate] = struct{}{}
			merged = append(merged, candidate)
		}
	}
	sort.Strings(merged)
	return merged
}
