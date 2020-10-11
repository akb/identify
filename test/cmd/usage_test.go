package test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/go-expect"
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
		arguments := strings.Fields(c)
		environment := map[string]string{}
		var output string
		var err error
		result := RunCommandTest(t, environment, arguments,
			func(c *expect.Console, cancel context.CancelFunc) {
				done := In(10*time.Millisecond, func() { c.Tty().Close() })

				t.Log("waiting for eof...")
				output, err = c.ExpectEOF()
				t.Log("waiting for tty to close...")
				<-done
			},
		)
		if err != nil {
			t.Fatal(err)
		}

		pattern := fmt.Sprintf("Usage: identify %s", c)
		_, err = regexp.Match(pattern, []byte(output))
		if err != nil {
			t.Fatalf("error matching command output for \"identify %s\"\n%s\n", c, err)
		}

		if result.Status != 0 {
			t.Errorf("Expected status code 0, received %d.\n", result.Status)
		}
	}
}
