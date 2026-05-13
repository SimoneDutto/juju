---
myst:
  html_meta:
    description: "Install Juju bash auto-completion, enable the thin shell wrapper, and test the completion backend during development."
---

(manage-bash-auto-completion)=
# How to manage Juju bash auto-completion

## Install bash auto-completion

Juju bash completion now has two parts:

- the `juju-completion` backend binary
- the thin Bash wrapper script in `etc/bash_completion.d/juju`

The wrapper does not implement Juju-specific completion logic itself. It forwards Bash completion state to `juju-completion`, which returns the candidates.

### Install from a source tree

Build or install the backend binary first:

```text
go install ./cmd/juju-completion
```

This places `juju-completion` in `$(go env GOPATH)/bin`.

Install the Bash wrapper script into a standard completion location:

```text
sudo install -m 644 etc/bash_completion.d/juju /usr/share/bash-completion/completions/juju
```

Make sure the backend binary is on your `PATH` in shells where you want completion to work:

```text
export PATH="$(go env GOPATH)/bin:${PATH}"
```

Load the completion definition in your current shell:

```text
source /usr/share/bash-completion/completions/juju
```

### Install only for your current shell session

For quick local testing, you can avoid installing system-wide files:

```text
go build -o ./juju-completion ./cmd/juju-completion
export PATH="$PWD:${PATH}"
source ./etc/bash_completion.d/juju
```

## Test the completion backend as a developer

### Run focused automated checks

Build the backend and run the completion package tests:

```text
go build ./cmd/juju-completion
go test ./cmd/juju/completion
```

Validate the Bash wrapper syntax:

```text
bash -n ./etc/bash_completion.d/juju
```

### Exercise the backend directly

You can call the backend without Bash to inspect what it will return:

```text
./juju-completion commands
./juju-completion flags deploy
./juju-completion controllers
./juju-completion models
```

### Simulate Bash completion in a non-interactive shell

This is useful when iterating on the thin wrapper.

Load the wrapper, set completion variables, run the completion function, and print the results.

Example: complete Juju commands after `juju help c`:

```text
bash -lc 'export PATH="$PWD:${PATH}"; source ./etc/bash_completion.d/juju; COMP_WORDS=(juju help c); COMP_CWORD=2; _juju_complete; printf "%s\n" "${COMPREPLY[@]}"'
```

Example: complete deploy flags after `juju deploy --c`:

```text
bash -lc 'export PATH="$PWD:${PATH}"; source ./etc/bash_completion.d/juju; COMP_WORDS=(juju deploy --c); COMP_CWORD=2; _juju_complete; printf "%s\n" "${COMPREPLY[@]}"'
```

### Test live model-backed completions

Completions for applications, units, and machines require `juju status --format json` to work for the target model without prompting for interactive credentials.

If your local client is not already authenticated, the backend will fail the same way a direct `juju status` command would fail.

To verify that path manually, first confirm that the status command succeeds non-interactively:

```text
juju status --model "$(juju switch)" --format json >/dev/null
```

Then simulate completion for a model-backed command, for example:

```text
bash -lc 'export PATH="$PWD:${PATH}"; source ./etc/bash_completion.d/juju; COMP_WORDS=(juju config ""); COMP_CWORD=2; _juju_complete; printf "%s\n" "${COMPREPLY[@]}"'
```

## Current limitations

- The Bash layer is intentionally thin and no longer carries the legacy shell-specific heuristics from the old script.
- The backend currently focuses on command, flag, controller, model, application, unit, and machine completion.
- Status-backed completion depends on Juju being able to answer non-interactively for the current model context.