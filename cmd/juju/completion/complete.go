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

	switch {
	case request.Cword <= 1:
		return filterCandidates(snapshot.CommandNames(), current), nil
	case action == "help":
		return filterCandidates(snapshot.CommandNames(), current), nil
	case previous == "--controller" || previous == "-c":
		controllers, err := b.Controllers()
		if err != nil {
			return nil, err
		}
		return filterCandidates(controllers, current), nil
	case previous == "--model" || previous == "-m":
		models, err := b.Models()
		if err != nil {
			return nil, err
		}
		return filterCandidates(models, current), nil
	case previous == "--application":
		applications, err := b.Applications(model)
		if err != nil {
			return nil, err
		}
		return filterCandidates(applications, current), nil
	case previous == "--unit":
		units, err := b.Units(model, "")
		if err != nil {
			return nil, err
		}
		return filterCandidates(units, current), nil
	case previous == "--machine":
		machines, err := b.Machines(model)
		if err != nil {
			return nil, err
		}
		return filterCandidates(machines, current), nil
	case strings.HasPrefix(current, "-") && action != "":
		return filterCandidates(snapshot.FlagsFor(action), current), nil
	default:
		candidates, err := b.completePositional(action, model)
		if err != nil {
			return nil, err
		}
		return filterCandidates(candidates, current), nil
	}
}

func (b *Backend) completePositional(action, model string) ([]string, error) {
	switch action {
	case "switch":
		controllers, err := b.Controllers()
		if err != nil {
			return nil, err
		}
		models, err := b.Models()
		if err != nil {
			return nil, err
		}
		return mergeCandidates(controllers, models), nil
	case "config", "refresh", "expose", "unexpose", "remove-application", "application-storage", "constraints", "set-constraints", "set-application-base":
		return b.Applications(model)
	case "status":
		applications, err := b.Applications(model)
		if err != nil {
			return nil, err
		}
		units, err := b.Units(model, "")
		if err != nil {
			return nil, err
		}
		return mergeCandidates(applications, units), nil
	case "ssh", "scp", "debug-hooks", "debug-code":
		units, err := b.Units(model, "")
		if err != nil {
			return nil, err
		}
		machines, err := b.Machines(model)
		if err != nil {
			return nil, err
		}
		return mergeCandidates(units, machines), nil
	case "resolved", "remove-unit":
		return b.Units(model, "")
	case "show-machine", "remove-machine", "upgrade-machine":
		return b.Machines(model)
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

func filterCandidates(candidates []string, current string) []string {
	if current == "" {
		return candidates
	}
	filtered := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if strings.Contains(candidate, current) {
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
