package test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

var commands []string = []string{
	"",
	"new",
	"get",
	"delete",
	//"help new identity",
	//"help new secret",
	//"help get secret",
	//"help delete token",
	//"help listen",
}

func TestCommandUsage(t *testing.T) {
	for _, c := range commands {
		cmd, err := NewCommandTest(strings.Fields(c), map[string]string{})
		if err != nil {
			t.Fatalf("error initializing command \"identify %s\"\n%s\n", c, err)
		}

		cmd.Start()

		var output string
		cmd.Interact(func() {
			cmd.Tty().Close()
			output, err = cmd.GetOutput()
			if err != nil {
				t.Fatalf("error getting command output for \"identify %s\"\n%s\n", c, err)
			}
		})

		err = cmd.Wait()
		if err != nil && cmd.StatusCode == -1 {
			t.Fatal(err)
		}

		pattern := fmt.Sprintf("Usage: identify %s", c)
		_, err = regexp.Match(pattern, []byte(output))
		if err != nil {
			t.Fatalf("error matching command output for \"identify %s\"\n%s\n", c, err)
		}

		if cmd.StatusCode != 1 {
			t.Errorf("Expected status code 1, received %d.\n", cmd.StatusCode)
		}
	}
}
