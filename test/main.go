package test

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/Netflix/go-expect"
	"github.com/brianvoe/gofakeit/v5"

	"github.com/akb/go-cli"
)

var commandName string

func init() {
	commandName = os.Getenv("IDENTIFY_COMMAND")
	if len(commandName) == 0 {
		commandName = "identify"
	}
	gofakeit.Seed(time.Now().UnixNano())
}

type AuthenticatedCommand struct {
	passphrase string
}

func (i AuthenticatedCommand) Authenticate(c *expect.Console) (string, error) {
	var err error
	_, err = c.Expectf("Enter passphrase:")
	if err != nil {
		return "", err
	}

	_, err = c.SendLine(i.passphrase)
	if err != nil {
		return "", err
	}

	output, err := c.ExpectEOF()
	if err != nil {
		return "", err
	}

	return output, nil
}

type InteractiveCommand interface {
	Command() []string
	Automate(c *expect.Console) (string, error)
	Test(t *testing.T, c *expect.Console)
}

func testInteractiveCommand(t *testing.T, dbPath string, i InteractiveCommand) {
	c, err := expect.NewConsole()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	closer := make(chan struct{})
	go func() {
		i.Test(t, c)
		closer <- struct{}{}
	}()

	cmd := exec.Command(commandName, i.Command()...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("IDENTIFY_DB_PATH=%s", dbPath))
	cmd.Stdin = c.Tty()
	cmd.Stdout = c.Tty()
	cmd.Stderr = c.Tty()

	cli.ExpectSuccess(t, cmd.Run())

	c.Tty().Close()

	<-closer
}

func automateInteractiveCommand(dbPath string, i InteractiveCommand) (string, error) {
	c, err := expect.NewConsole()
	if err != nil {
		return "", err
	}
	defer c.Close()

	result := make(chan interface{})
	go func() {
		out, err := i.Automate(c)
		if err != nil {
			result <- err
		} else {
			result <- out
		}
	}()

	cmd := exec.Command(commandName, i.Command()...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("IDENTIFY_DB_PATH=%s", dbPath))
	cmd.Stdin = c.Tty()
	cmd.Stdout = c.Tty()
	cmd.Stderr = c.Tty()

	if err = cmd.Run(); err != nil {
		return "", err
	}

	c.Tty().Close()

	out := <-result
	switch o := out.(type) {
	case string:
		return o, nil
	case error:
		return "", o
	default:
		panic("out has an unknown type")
	}
}
