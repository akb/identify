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
	"github.com/google/uuid"
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

	cmd := exec.Command(commandName, "new", "identity")
	cmd.Env = append(os.Environ(), fmt.Sprintf("IDENTIFY_DB_PATH=%s", dbPath))
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
