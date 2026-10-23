package main

import (
	"bytes"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-version"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if got, want := stdout.String(), "porthawk v"+version+"\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}
