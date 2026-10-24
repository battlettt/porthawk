package main

import (
	"bytes"
	"testing"
)

func TestRunRateValidation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-t", "127.0.0.1", "-rate", "-5"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("exit %d, want usage error %d: %s", code, exitUsage, stderr.String())
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-version"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if got, want := stdout.String(), "porthawk v"+version+"\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}
