package test

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/Netflix/go-expect"
	"github.com/google/uuid"
)

func TestNewIdentityCommand(t *testing.T) {
	if len(commandName) == 0 {
		fmt.Println("A path to an executable to test must be provided in the " +
			"environment variable IDENTIFY_COMMAND")
	}

	c, err := expect.NewConsole()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	cmd := exec.Command(commandName, "new", "identity")
	cmd.Stdin = c.Tty()
	cmd.Stdout = c.Tty()
	cmd.Stderr = c.Tty()

	var output string
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.Expectf("Enter passphrase:")
		c.SendLine("foobar") // TODO: generate pw
		output, err = c.ExpectEOF()
		if err != nil {
			t.Fatal(err)
		}
	}()

	err = cmd.Run()
	if err != nil {
		t.Fatal(err)
	}

	c.Tty().Close()

	wg.Wait()

	_, err = uuid.Parse(strings.TrimSpace(output))
	if err != nil {
		t.Fatal(err)
	}
}
