# Plan: Juju Autocompletion — New `juju-complete` Binary

## TL;DR

Replace the slow bash/Python completion script with a standalone `juju-complete` Go binary. It
builds the full command/flag tree in-process at startup from a committed static JSON artifact
(generated at build time), handles dynamic entities via local YAML parsing (Mode A) or direct
API + TTL cache (Mode B), and ships thin bash/zsh shell scripts. Snap support is included by
bundling the binary and scripts into the snap.

## Decisions

- **Binary**: separate `juju-complete` binary (not embedded in `juju`); avoids slow CLI init on
  every tab press
- **Static JSON**: build-time artifact — generated during `make generate-completion-json`,
  committed to the repo
- **Shells**: bash + zsh for MVP; fish deferred
- **REPL completion**: explicitly out of scope
- **Snap support**: in scope — bundle binary + updated shell scripts in snap

---

## Current State

- `etc/bash_completion.d/juju` — ~500-line bash/Python script; calls `juju help commands` on
  every tab, `juju help <cmd>` for flags, `juju status --format json` for entities (cached 2 min).
  Minimal zsh shims, no fish, no REPL.
- `cmd/juju/commands/repl.go` — readline REPL has a `// TODO: add auto complete support` stub,
  never implemented (out of scope).
- CLI framework: custom (`cmd/cmd` + `github.com/juju/gnuflag`). `SuperCommand` holds
  `subcmds map[string]commandReference`. Reference pattern: `documentationCommand` in
  `cmd/cmd/documentation.go` walks `c.super.subcmds`, calls `cmd.Info()` + `SetFlags()` per
  command.
- Snap: `snap/snapcraft.yaml` already bundles `etc/bash_completion.d/juju` into
  `usr/share/bash-completion/completions/juju` and registers it via `completer:`.

---

## Steps

### Phase 1 — Benchmark Current System

1. Write `scripts/bench-completion.sh`:
   - Cold: `time juju help commands` (no cache)
   - Warm: repeat 10×, measure p50/p99
   - Flag: `time juju help deploy 2>/dev/null`
   - Entity (API): `time juju status --format json`
2. Document which completions work today and which are missing (native zsh, fish, REPL).
3. Record baseline numbers in `docs/contributor/reference/autocompletion-benchmark.md`.

### Phase 2 — Static JSON Generator

**New tool**: `cmd/juju-complete/generate/main.go`

- Instantiate the juju command tree via `commands.NewJujuCommandWithStore(...)`.
- Walk `SuperCommand.subcmds` (same pattern as `documentationCommand` in
  `cmd/cmd/documentation.go`): for each command call `cmd.Info()` and `SetFlags()` on a fresh
  `gnuflag.FlagSet`.
- Output `internal/completion/static.json` with shape:
  ```json
  {
    "commands": {
      "<name>": {
        "aliases": ["..."],
        "args_hint": "<string>",
        "flags": {
          "<flag>": { "type": "<string>", "description": "<string>", "short": "<char>" }
        }
      }
    }
  }
  ```
- Add `make generate-completion-json` Makefile target; commit the generated file.

### Phase 3 — `juju-complete` Binary (`cmd/juju-complete/`)

**Depends on Phase 2.**

For the exploratory/debugging version, do not write tests. Keep the binary small and inspectable
while the shell input shape is still being discovered. Validate manually by enabling completion
and observing the debug output from real shell invocations.

**3a — `tree.go`** — load `internal/completion/static.json` at binary init; no subprocess, no
API connection.

**3b — `complete.go`** — given `[]string` words and cursor position:
1. `len(words) == 1` → return all command names + aliases.
2. `len(words) >= 2`, word[1] is known, current word starts with `-` → return that command's
   flags.
3. Detect flag-value context:
   - `--model`/`-m`, `--controller`/`-c` → Mode A (local store)
   - `--unit`, `--machine`, `--application` → Mode B (API cache)
4. Positional arg hints from `args_hint` (documented; not auto-completed in this version).

**3c — `localstore.go` (Mode A, offline)** — read `~/.local/share/juju/` directly (no
subprocess):
- Controllers: parse `controllers.yaml`
- Models: parse `models/<controller>-<user>-models.yaml`
- Active model: read `current-controller` + models file for current model name
- ~1ms, works offline

**3d — `apicache.go` (Mode B, direct API + cache)** — connect via `api/connector` using
existing auth providers (session token → `SessionTokenLoginProvider`; password →
`LegacyLoginProvider`; macaroons via cookie jar):
- Units, apps, machines: `client.NewClient(conn).Status(ctx, nil)` → `*params.FullStatus`
- Models: `modelmanager.NewClient(conn).ListModels(ctx, user)` (controller-scoped connection)
- Cache to `~/.cache/juju/complete-<controller>-<model>-<entity>.json`, TTL 120s (configurable)
- Serve stale cache immediately + background goroutine refresh
- On cache miss: attempt API with 3s dial timeout; return empty on timeout — never block shell

**3e — `main.go`**:
```
juju-complete [flags] -- word1 word2 ... wordN
  --shell bash|zsh        output format (default: bash)
  --position N            cursor word index (default: last)
  --dump-script bash|zsh  print shell integration snippet and exit
  --ttl N                 cache TTL override in seconds
```
- Outputs newline-separated candidates to stdout.
- Exit 0 always (shell completion must never error visibly).

### Phase 4 — Shell Integration Scripts *(parallel with Phase 3)*

**4a — Bash** (`etc/bash_completion.d/juju` — replace existing):
```bash
_juju() {
    local IFS=$'\n'
    COMPREPLY=($(juju-complete --shell bash -- "${COMP_WORDS[@]}"))
}
complete -F _juju juju
```

**4b — Zsh** (`etc/zsh/completions/_juju` — new file):
```zsh
#compdef juju
_juju() {
    local -a comps
    comps=(${(f)"$(juju-complete --shell zsh -- ${words[@]})"})
    _describe 'juju' comps
}
```

**4c — Makefile** — new targets:
- `make generate-completion-json` → regenerate `internal/completion/static.json`
- `make install-completion` → install binary + both shell scripts
- `make install-bash-completion`
- `make install-zsh-completion`
- Local exploratory targets:
  - `make enable-zsh-completion` → install local `juju`/`juju-complete`, write
    `${JUJU_DATA:-.juju}/zsh/site-functions/_juju`, then print the `fpath`/`compinit` command
    needed to enable it in the current zsh session.
  - `make enable-bash-completion` → install local `juju`/`juju-complete`, write
    `${JUJU_DATA:-.juju}/bash_completion.d/juju`, then print the `source` command needed to
    enable it in the current bash session.

Local enablement examples:

```zsh
make enable-zsh-completion
fpath=(${JUJU_DATA:-.juju}/zsh/site-functions $fpath)
autoload -Uz compinit && compinit
```

```bash
make enable-bash-completion
source ${JUJU_DATA:-.juju}/bash_completion.d/juju
```

### Phase 5 — Snap Support

- Add `go install ... github.com/juju/juju/cmd/juju-complete` to the snap build step in
  `snap/snapcraft.yaml` alongside the existing `cmd/juju` install.
- Extend the completion install loop to also copy `etc/zsh/completions/_juju` to
  `usr/share/zsh/vendor-completions/`.
- The existing `completer: usr/share/bash-completion/completions/juju` key in `snapcraft.yaml`
  already handles bash wiring; the thin wrapper calls `juju-complete` which is on `$PATH` inside
  the snap.

### Phase 6 — Benchmark New System

Repeat Phase 1 script against `juju-complete`:
- Static (commands, flags): expect <50ms
- Dynamic Mode A (controllers/models): expect <5ms
- Dynamic Mode B (units/apps, cache hit): expect <10ms; cache miss: same as today
- Correctness: diff outputs of old vs new for the same inputs

---

## Key Files

- [etc/bash_completion.d/juju](etc/bash_completion.d/juju) — replace with thin bash wrapper
- `etc/zsh/completions/_juju` — new zsh integration script
- [cmd/cmd/documentation.go](cmd/cmd/documentation.go) — reference pattern (walk subcmds +
  SetFlags)
- [cmd/cmd/supercommand.go](cmd/cmd/supercommand.go) — `SuperCommand.subcmds`,
  `commandReference` type
- [cmd/juju/commands/main.go](cmd/juju/commands/main.go) — `NewJujuCommandWithStore`,
  `registerCommands`
- [cmd/juju/commands/repl.go](cmd/juju/commands/repl.go) — REPL readline TODO stub (out of
  scope)
- `cmd/juju-complete/` — new package (all new files)
- `cmd/juju-complete/generate/` — static JSON generator tool
- `internal/completion/static.json` — generated command/flag tree (committed)
- [Makefile](Makefile) — new targets
- [snap/snapcraft.yaml](snap/snapcraft.yaml) — add `juju-complete` binary + zsh completion

## Verification

Do not add or require new tests while the completion protocol is still exploratory. Prefer
manual validation and benchmarks until the input/output contract is stable.

1. `go build ./cmd/juju-complete`
2. `make pre-check` (golangci-lint + gci) before submitting non-exploratory changes
3. Manual bash: source bash script, tab-complete `juju dep<TAB>`, `juju deploy --<TAB>`,
   `juju ssh -m <TAB>`
4. Manual zsh: `compinit`, same tests
5. Run benchmark script, compare Phase 1 vs Phase 6 numbers
