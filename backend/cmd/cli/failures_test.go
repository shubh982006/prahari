package main

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

// docs/failure-analysis.md is generated. If the engine changes a number, this
// fails until the file is regenerated, so the document cannot drift from what
// the code actually measures.
func TestFailureAnalysisIsCurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the evaluation and the full adversary bench")
	}
	want, err := os.ReadFile("../../../docs/failure-analysis.md")
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperFailures$")
	cmd.Env = append(os.Environ(), "PRAHARI_FAILURES_HELPER=1")
	cmd.Stdout = &got
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatal("docs/failure-analysis.md is stale; regenerate it: cd backend && go run ./cmd/cli failures > ../docs/failure-analysis.md")
	}
}

// TestHelperFailures runs the command in a child process so its stdout is the
// document and nothing else.
func TestHelperFailures(t *testing.T) {
	if os.Getenv("PRAHARI_FAILURES_HELPER") != "1" {
		t.Skip("helper for TestFailureAnalysisIsCurrent")
	}
	if err := cmdFailures(nil); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}
