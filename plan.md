# Juju Shell Completion

Completion is embedded in the `juju` binary as `juju autocomplete`. Shell
wrappers call it and feed the output to the shell's completion machinery.
Dynamic entities (applications, units, machines) are resolved via a direct
API connection — no subprocess calls to `juju`.

## Architecture

```
shell tab-press
  └─ etc/bash_completion.d/juju  (or etc/zsh/completions/_juju)
       └─ juju autocomplete --cword N --current W --word W ...
            ├─ completion.Describe(registerCommands)   → static snapshot
            └─ completion.Backend.Complete(snapshot, req)
                 ├─ offline: controllers, models       → local client store
                 └─ online:  applications, units,      → api/connector +
                             machines                    api/client/client
```

## Key files

| File | Role |
|---|---|
| `cmd/juju/commands/autocomplete.go` | `juju autocomplete` subcommand |
| `cmd/juju/completion/metadata.go` | Builds static snapshot of all commands and flags |
| `cmd/juju/completion/complete.go` | Routes a shell request to candidate sets |
| `cmd/juju/completion/backend.go` | Provides controllers/models/apps/units/machines |
| `cmd/juju-completion/main.go` | Standalone binary (retained, shares the same library) |
| `etc/bash_completion.d/juju` | Bash wrapper — `source` to activate |
| `etc/zsh/completions/_juju` | Zsh wrapper — `source` or add dir to `fpath` |

## Static snapshot

`completion.Describe(func(Registry))` accepts an injected registrar to avoid
an import cycle between `completion` and `commands`. Both `autocomplete.go`
and `juju-completion/main.go` pass `commands.RegisterCommands` through a small
local adapter struct.

## Dynamic backend

`Backend` in `backend.go` has two tiers:

**Offline (~0 ms)** — reads the local YAML client store directly:
- `Controllers()` — `store.AllControllers()`
- `Models()` — `store.AllModels(controller)` for every controller
- `currentModel(store)` — `JUJU_MODEL` env var → `store.CurrentController()` +
  `store.CurrentModel(controller)`; no subprocess

**Online (≤3 s dial timeout)** — opens a direct API connection:
- `Applications`, `Units`, `Machines` — `resolveModelUUID` looks up the UUID
  in `store.AllModels`, opens `connector.NewClientStore(ClientStoreConfig{…})`,
  calls `apiclient.NewClient(conn, logger).Status(ctx, nil)`, closes the
  connection; on any error returns empty so completion never blocks

## Shell activation

```bash
# bash
source etc/bash_completion.d/juju

# zsh
source etc/zsh/completions/_juju
# or add to fpath:
fpath=(etc/zsh/completions $fpath) && autoload -Uz compinit && compinit
```

## Deferred

- snap packaging
- fish completion
- cache layer for status-backed completion

- fish completion
- REPL completion
- cache layer for status-backed completion
- benchmark documentation

## TL;DR

The implementation moved Juju bash completion to a separate `juju-completion` Go binary plus a
thin shell wrapper.

The shell layer now only forwards Bash completion state to the backend. The backend builds static
command and flag metadata directly from Juju's registered commands at runtime, and resolves dynamic
controller, model, application, unit, and machine completions from local client state and `juju`
command output.

This replaced the previous large bash/Python completion script and superseded the earlier
`juju-complete` prototype package.

## Final decisions

- **Binary**: use a separate `juju-completion` binary rather than embedding completion in `juju`
- **Shell**: keep Bash as a thin adapter only; move Juju-specific logic into Go
- **Static metadata**: generate command and flag metadata at runtime from `commands.RegisterCommands`
  rather than from a committed JSON artifact
- **Dynamic metadata**: use the Juju client store for controllers and models, and use `juju switch`
  plus `juju status --format json` for model-scoped entities
- **Tests**: add focused Go tests for metadata extraction, backend providers, and completion routing
- **Documentation**: add installation and developer testing documentation for the new flow
- **Scope**: Bash is implemented; zsh, fish, REPL completion, snap packaging changes, and caching
  remain deferred

---

## What was implemented

### 1. Separate backend binary

A new backend binary lives in `cmd/juju-completion/`.

Implemented entrypoints:

- `describe`
- `commands`
- `flags <command>`
- `controllers`
- `models`
- `applications --model <model>`
- `units --model <model> [--suffix value]`
- `machines --model <model>`
- `complete --cword N --current VALUE --word ...`

The `complete` subcommand is the shell-facing protocol used by the Bash wrapper.

### 2. Runtime static metadata snapshot

Static command and flag completion is implemented in `cmd/juju/completion/metadata.go`.

The backend does not scrape help output and does not load a generated JSON file. Instead it:

- calls `commands.RegisterCommands`
- records command names, aliases, args, and purpose
- builds a fresh `gnuflag.FlagSet` per command
- captures registered flags directly from `SetFlags`

To support that, `cmd/juju/commands/main.go` exports the registration hook used by completion.

### 3. Backend providers for dynamic entities

Dynamic completion is implemented in `cmd/juju/completion/backend.go`.

Current providers:

- **Controllers**: from `jujuclient.NewFileClientStore().AllControllers()`
- **Models**: from `AllModels(controller)`, returning `controller:model` entries for every
  controller and bare model names for the current controller
- **Current model resolution**:
  - use `JUJU_MODEL` when present
  - otherwise run `juju switch`
- **Applications / units / machines**:
  - resolve the target model
  - run `juju status --model <model> --format json`
  - parse `params.FullStatus`
  - extract entities from the returned status document

This deliberately avoids the older direct API connection approach and the original local YAML / API
cache split proposed in the first draft of the plan.

### 4. Shell completion routing in Go

Completion request routing lives in `cmd/juju/completion/complete.go`.

The current behavior is:

- first command position completes Juju commands and aliases
- `juju help ...` completes commands
- current token starting with `-` completes flags for the selected command
- `--controller` / `-c` completes controllers
- `--model` / `-m` completes models
- `--application` completes applications
- `--unit` completes units
- `--machine` completes machines
- selected positional commands complete dynamic entities in a small explicit routing table

Implemented positional routing includes:

- `switch` → controllers and models
- `config`, `refresh`, `expose`, `unexpose`, `remove-application`, `application-storage`,
  `constraints`, `set-constraints`, `set-application-base` → applications
- `status` → applications and units
- `ssh`, `scp`, `debug-hooks`, `debug-code` → units and machines
- `resolved`, `remove-unit` → units
- `show-machine`, `remove-machine`, `upgrade-machine` → machines

### 5. Thin Bash wrapper

`etc/bash_completion.d/juju` was reduced to a thin Bash adapter.

The wrapper now:

- finds the `juju-completion` binary
- reads `COMP_WORDS` and `COMP_CWORD`
- calls `juju-completion complete ...`
- loads newline-separated results into `COMPREPLY`

The previous large Bash script and its Bash/Python heuristics were removed.

### 6. Documentation and tests

Documentation was added in `docs/howto/manage-bash-auto-completion.md` and linked from
`docs/howto/index.md`.

Focused tests were added for:

- static metadata extraction
- backend controller/model/application/unit/machine providers
- shell completion routing

The previous draft plan said not to add tests while the protocol was exploratory. The implemented
version did add tests because the request/response shape settled quickly and the routing logic was
small enough to lock down safely.

### 7. Old prototype removal

The previous `cmd/juju-complete/` package was removed in favor of the final
`cmd/juju-completion/` backend.

---

## What changed from the original proposal

The final implementation differs from the original plan in a few important ways.

### Implemented instead of planned

- `juju-completion` was used as the final binary name instead of `juju-complete`
- runtime metadata extraction replaced the planned generated static JSON file
- direct shelling to `juju switch` and `juju status --format json` replaced the planned local YAML
  parser plus API cache split
- focused Go tests were added instead of keeping the implementation test-free
- Bash support and documentation landed; zsh support and broader packaging work did not

### Not implemented from the original draft

- generated `internal/completion/static.json`
- `cmd/juju-complete/generate/`
- zsh completion script
- Makefile completion helper targets
- snap packaging changes for the new backend
- benchmark script and benchmark documentation
- REPL completion support
- stale-cache / background-refresh behavior for dynamic completions

---

## Current limitations

- The current thin wrapper only targets Bash.
- Live completion for applications, units, and machines depends on `juju status` succeeding
  non-interactively for the selected model.
- There is no cache layer yet for status-backed completion.
- Completion routing is intentionally explicit and currently covers the command set implemented in
  `complete.go`; it is not yet a generic positional completion framework.

---

## Key files

- `cmd/juju-completion/main.go` — backend entrypoint and shell-facing `complete` command
- `cmd/juju/completion/metadata.go` — runtime command and flag snapshot generation
- `cmd/juju/completion/backend.go` — controller, model, application, unit, and machine providers
- `cmd/juju/completion/complete.go` — routing from shell context to candidate sets
- `cmd/juju/commands/main.go` — exported command registration hook for completion metadata
- `etc/bash_completion.d/juju` — thin Bash wrapper
- `docs/howto/manage-bash-auto-completion.md` — install and developer testing instructions

## Validation performed

Focused validation for the implemented approach is:

1. `go test ./cmd/juju/completion`
2. `go build ./cmd/juju-completion`
3. `bash -n ./etc/bash_completion.d/juju`
4. shell simulation of command completion:
   - `juju help c`
5. shell simulation of flag completion:
   - `juju deploy --c`

Live model-backed completion was only partially validated because the environment can still prompt
for interactive Juju credentials when `juju status` is invoked.

## Follow-up work

If this work continues, the next logical slices are:

1. add zsh support with the same backend protocol
2. decide whether model-backed completion needs caching to avoid repeated `juju status` calls
3. expand positional completion coverage command by command
4. wire the backend and wrapper into packaging and snap installation flows
5. benchmark the backend path against the removed legacy shell script
