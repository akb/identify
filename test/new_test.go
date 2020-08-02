package test

import (
	"bytes"
	"fmt"
	"os/exec"
	"testing"

	"github.com/akb/go-cli"
)

func TestNewCommand(t *testing.T) {
	if len(commandName) == 0 {
		fmt.Println("A path to an executable to test must be provided in the " +
			"environment variable IDENTIFY_COMMAND")
	}
	var stdout bytes.Buffer
	cmd := exec.Command(commandName, "new")
	cmd.Stdout = &stdout
	cli.ExpectError(t, cmd.Run())
	cli.ExpectOutput(t, stdout)
	cli.ExpectMatch(t, stdout, `Usage: identify new`)
}
