// Command cli runs Prahari's offline tools: simulate, evaluate, bench,
// adversary, inspect, migrate and verify.
package main

import (
	"fmt"
	"os"
)

const usage = `prahari cli

  evaluate   [--seeds 1-10] [--window 2h] [--no-launder]   metrics vs ground truth, mean ± std
  inspect    [--seed 42] [--top 20]                        print the ranked queue for one seed
  simulate   [--seed 42] [--out dir]                       write a dataset as NDJSON + truth
  bench      [--sizes 3000,50000,300000]                   engine timing at scale
  adversary  --strategy S [--budgets 0,0.25,...] [--mitigated] [--seeds 1-5]
  migrate    [--dsn DSN]                                   apply migrations
  verify     [--dsn DSN]                                   verify the audit hash chain
  failures   [--seeds 1-10] [--adv-seeds 1-5]                measure every known miss; prints failure-analysis.md
  cmdb                                                     print the demo CMDB as JSON
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"evaluate": cmdEvaluate, "inspect": cmdInspect, "simulate": cmdSimulate, "bench": cmdBench,
		"adversary": cmdAdversary, "failures": cmdFailures, "migrate": cmdMigrate, "verify": cmdVerify, "cmdb": cmdCMDB,
	}
	f, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Print(usage)
		os.Exit(2)
	}
	if err := f(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
