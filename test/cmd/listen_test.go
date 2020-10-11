package test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/go-expect"
)

func TestListenCommand(t *testing.T) {
	ti, err := GenerateNewIdentity(t)
	if err != nil {
		t.Fatal(err)
	}

	environment := map[string]string{"IDENTIFY_DB_PATH": dbPath}

	arguments := []string{"listen", fmt.Sprintf("-id=%s", ti.ID)}

	var output string
	t.Logf("running '%s'", strings.Join(arguments, " "))
	result := RunCommandTest(t, environment, arguments,
		func(c *expect.Console, cancel context.CancelFunc) {
			t.Log("waiting for passphrase prompt...")
			_, err = c.Expectf("Passphrase: ")
			if err != nil {
				return
			}

			t.Logf("sending passphrase %s", ti.Passphrase)
			_, err = c.SendLine(ti.Passphrase)
			if err != nil {
				return
			}

			done := In(100*time.Millisecond, func() {
				c.Tty().Close()
				cancel()
			})

			t.Log("waiting for eof...")
			output, err = c.ExpectEOF()
			<-done
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.Status != 0 {
		t.Errorf("error: '%s' returned nonzero status %d", strings.Join(arguments, " "), result.Status)
		t.Fatal(result.String())
	}

	if strings.TrimSpace(output) != "Listening for HTTP requests on 0.0.0.0:8443..." {
		t.Fatalf("unexpected output: '%s'\n", output)
		t.Fatal(result.String())
	}
}
