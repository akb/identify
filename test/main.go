package test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/Netflix/go-expect"

	"github.com/akb/go-cli"
)

var commandName string

func init() {
	commandName = os.Getenv("IDENTIFY_COMMAND")
	if len(commandName) == 0 {
		commandName = "identify"
	}
}

type InteractiveCommand interface {
	Command() string
	TestCommand(t *testing.T, c *expect.Console)
}

func testInteractiveCommand(t *testing.T, dbPath string, i InteractiveCommand) {
	c, err := expect.NewConsole()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	closer := make(chan struct{})
	go func() {
		i.TestCommand(t, c)
		closer <- struct{}{}
	}()

	cmd := exec.Command(commandName, strings.Fields(i.Command())...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("IDENTIFY_DB_PATH=%s", dbPath))
	cmd.Stdin = c.Tty()
	cmd.Stdout = c.Tty()
	cmd.Stderr = c.Tty()

	cli.ExpectSuccess(t, cmd.Run())

	c.Tty().Close()

	<-closer
}
