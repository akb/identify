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
	"time"

	"github.com/Netflix/go-expect"
	"github.com/brianvoe/gofakeit/v5"
)

var commandName string
var dbPath string

func init() {
	commandName = os.Getenv("IDENTIFY_COMMAND")
	if len(commandName) == 0 {
		commandName = "identify"
	}
	gofakeit.Seed(time.Now().UnixNano())
}

func TestMain(m *testing.M) {
	dir, err := ioutil.TempDir("", "identify-testing")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	dbPath = filepath.Join(dir, "identity.db")

	os.Exit(m.Run())
}

type CommandTest struct {
	*expect.Console
	*exec.Cmd

	Name string
	Args []string

	StatusCode int

	Output string

	wg *sync.WaitGroup
}

func NewCommandTest(args []string, env map[string]string) (*CommandTest, error) {
	c, err := expect.NewConsole()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(commandName, args...)

	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	cmd.Stdin = c.Tty()
	cmd.Stdout = c.Tty()
	cmd.Stderr = c.Tty()

	return &CommandTest{c, cmd, commandName, args, -1, "", &sync.WaitGroup{}}, nil
}

func (c *CommandTest) Close() {
	c.Console.Tty().Close()
	c.Console.Close()
}

func (c *CommandTest) Wait() error {
	err := c.Cmd.Wait()
	if err, ok := err.(*exec.ExitError); ok {
		c.StatusCode = err.ExitCode()
	}
	if err == nil {
		c.StatusCode = 0
	}
	c.wg.Wait()
	return err
}

func (c *CommandTest) Interact(fn func()) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		fn()
	}()
}

func (c CommandTest) Authenticate(passphrase string) error {
	var err error
	_, err = c.Expectf("Enter passphrase:")
	if err != nil {
		return err
	}

	_, err = c.SendLine(passphrase)
	if err != nil {
		return err
	}

	return nil
}

func (c *CommandTest) GetOutput() (string, error) {
	output, err := c.ExpectEOF()
	if err != nil {
		return "", err
	}

	trimmed := strings.TrimSpace(output)

	c.Output = trimmed

	return trimmed, nil
}
