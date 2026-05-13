// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package main

import "os"

func main() {
	// The completion engine implementation is intentionally separate from wiring.
	// Exit success with no candidates for now.
	_ = os.Args
}
