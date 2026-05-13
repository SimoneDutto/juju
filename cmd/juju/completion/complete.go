package completion

import (
	"sort"
	"strings"
)

// Request describes a single shell completion request.
type Request struct {
	Words   []string
	Cword   int
	Current string
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
	previous := request.word(request.Cword - 1)
	model := request.model()
	command, hasCommand := snapshot.Lookup(action)
	previousFlagCompletion := completionForFlag(command, previous)

	switch {
	case request.Cword <= 1:
		return filterCandidates(snapshot.CommandNames(), current), nil
	case action == "help":
		return filterCandidates(snapshot.CommandNames(), current), nil
	case previousFlagCompletion != "":
		candidates, err := b.candidatesForTargets(model, []string{previousFlagCompletion})
		if err != nil {
			return nil, err
		}
		return filterCandidates(candidates, current), nil
	case strings.HasPrefix(current, "-") && hasCommand:
		return filterCandidates(snapshot.FlagsFor(action), current), nil
	default:
		candidates, err := b.completePositional(command, request.positionalIndex(command), model)
		if err != nil {
			return nil, err
		}
		return filterCandidates(candidates, current), nil
	}
}

func (b *Backend) completePositional(command Command, index int, model string) ([]string, error) {
	for _, positional := range command.Positionals {
		if positional.Index != index && !(positional.Repeat && index >= positional.Index) {
			continue
		}
		return b.candidatesForTargets(model, positional.Targets)
	}
	return nil, nil
}

func (b *Backend) candidatesForTargets(model string, targets []string) ([]string, error) {
	groups := make([][]string, 0, len(targets))
	for _, target := range targets {
		candidates, err := b.candidatesForTarget(model, target)
		if err != nil {
			return nil, err
		}
		groups = append(groups, candidates)
	}
	return mergeCandidates(groups...), nil
}

func (b *Backend) candidatesForTarget(model, target string) ([]string, error) {
	switch target {
	case CompletionApplications:
		return b.Applications(model)
	case CompletionControllers:
		return b.Controllers()
	case CompletionMachines:
		return b.Machines(model)
	case CompletionModels:
		return b.Models()
	case CompletionStatusTargets:
		applications, err := b.Applications(model)
		if err != nil {
			return nil, err
		}
		units, err := b.Units(model, "")
		if err != nil {
			return nil, err
		}
		return mergeCandidates(applications, units), nil
	case CompletionSSHTargets:
		units, err := b.Units(model, "")
		if err != nil {
			return nil, err
		}
		machines, err := b.Machines(model)
		if err != nil {
			return nil, err
		}
		return mergeCandidates(units, machines), nil
	case CompletionSwitchTargets:
		controllers, err := b.Controllers()
		if err != nil {
			return nil, err
		}
		models, err := b.Models()
		if err != nil {
			return nil, err
		}
		return mergeCandidates(controllers, models), nil
	default:
		return nil, nil
	}
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

func (r Request) positionalIndex(command Command) int {
	index := 0
	for i := 2; i < r.Cword && i < len(r.Words); i++ {
		token := r.Words[i]
		if strings.HasPrefix(token, "-") {
			if flagConsumesValue(command, token) && i+1 < r.Cword {
				i++
			}
			continue
		}
		index++
	}
	return index
}

func completionForFlag(command Command, token string) string {
	name := flagName(token)
	if name == "" {
		return ""
	}
	switch token {
	case "-c":
		return CompletionControllers
	case "-m":
		return CompletionModels
	}
	for _, flag := range command.Flags {
		if flag.Name == name {
			return flag.ValueCompletion
		}
	}
	return flagValueCompletion(name)
}

func flagConsumesValue(command Command, token string) bool {
	name := flagName(token)
	if name == "" || strings.Contains(token, "=") {
		return false
	}
	for _, flag := range command.Flags {
		if flag.Name == name {
			return !flag.IsBoolean
		}
	}
	return token == "-c" || token == "-m" || strings.HasPrefix(token, "--")
}

func flagName(token string) string {
	switch {
	case strings.HasPrefix(token, "--"):
		name := strings.TrimPrefix(token, "--")
		if idx := strings.Index(name, "="); idx >= 0 {
			name = name[:idx]
		}
		return name
	case strings.HasPrefix(token, "-") && len(token) == 2:
		return strings.TrimPrefix(token, "-")
	default:
		return ""
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
