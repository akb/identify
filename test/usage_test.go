package test

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/akb/go-cli"
)

var commands []string = []string{"", "new"}

func TestCommandUsage(t *testing.T) {
	for _, c := range commands {
		var stdout, stderr bytes.Buffer
		cmd := exec.Command(commandName, strings.Fields(c)...)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			if err.Error() != "exit status 1" {
				t.Fatal(err)
			}
		}

		cli.ExpectError(t, cmd.Run())
		cli.ExpectOutput(t, stdout)
		cli.ExpectMatch(t, stdout, fmt.Sprintf("Usage: identify %s", c))
	}
}
