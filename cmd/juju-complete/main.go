// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	if err := run(os.Stdout, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(output *os.File, args []string) error {
	flags := flag.NewFlagSet("juju-complete", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	var shell string
	var position int
	var dumpScript string
	var ttl int

	flags.StringVar(&shell, "shell", "bash", "completion shell")
	flags.IntVar(&position, "position", -1, "cursor word index")
	flags.StringVar(&dumpScript, "dump-script", "", "shell integration snippet")
	flags.IntVar(&ttl, "ttl", 0, "cache ttl override in seconds")

	if err := flags.Parse(args); err != nil {
		return err
	}

	message := describeInvocation(shell, position, dumpScript, ttl, flags.Args(), args)
	_, err := fmt.Fprint(output, message)
	return err
}

func describeInvocation(shell string, position int, dumpScript string, ttl int, words []string, rawArgs []string) string {
	var builder strings.Builder
	builder.WriteString("juju-complete debug input\n")
	builder.WriteString(fmt.Sprintf("shell=%q\n", shell))
	builder.WriteString(fmt.Sprintf("position=%d\n", position))
	builder.WriteString(fmt.Sprintf("dump_script=%q\n", dumpScript))
	builder.WriteString(fmt.Sprintf("ttl=%d\n", ttl))
	builder.WriteString(fmt.Sprintf("raw_args=%q\n", rawArgs))
	builder.WriteString(fmt.Sprintf("words=%q\n", words))
	return builder.String()
}
