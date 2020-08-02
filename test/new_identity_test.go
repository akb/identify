package test

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Netflix/go-expect"
	"github.com/brianvoe/gofakeit/v5"
	"github.com/google/uuid"

	"github.com/akb/go-cli"
)

func TestNewIdentityCommand(t *testing.T) {
	var err error

	if len(commandName) == 0 {
		fmt.Println("A path to an executable to test must be provided in the " +
			"environment variable IDENTIFY_COMMAND")
	}

	dir, err := ioutil.TempDir("", "identify-testing")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	dbPath := filepath.Join(dir, "identity.db")

	c, err := expect.NewConsole()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var output string
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err = c.Expectf("Enter passphrase:")
		if err != nil {
			t.Fatal(err)
		}

		_, err = c.SendLine(gofakeit.Password(true, true, true, true, true, 33))
		if err != nil {
			t.Fatal(err)
		}

		output, err = c.ExpectEOF()
		if err != nil {
			t.Fatal(err)
		}
	}()

	cmd := exec.Command(commandName, "new", "identity")
	cmd.Env = append(os.Environ(), fmt.Sprintf("IDENTIFY_DB_PATH=%s", dbPath))
	cmd.Stdin = c.Tty()
	cmd.Stdout = c.Tty()
	cmd.Stderr = c.Tty()

	cli.ExpectSuccess(t, cmd.Run())

	c.Tty().Close()

	wg.Wait()

	_, err = uuid.Parse(strings.TrimSpace(output))
	if err != nil {
		t.Fatal(err)
	}
}
