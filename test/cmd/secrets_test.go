package test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/go-expect"
	"github.com/brianvoe/gofakeit/v5"
)

type ErrorNonZeroExit struct {
	status int
}

func (err ErrorNonZeroExit) Error() string {
	return fmt.Sprintf("expected zero exit status; received %d", err.status)
}

type TestSecret struct {
	Key   string
	Value string
}

func TestSecrets(t *testing.T) {
	var err error

	t.Log("generating identity...")
	ti, err := GenerateNewIdentity(t)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("generating secret...")
	ts, err := GenerateSecret(t, ti)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("key: '%s', value: '%s'\n", ts.Key, ts.Value)

	value, err := GetSecret(t, ti, ts.Key)
	if err != nil {
		t.Fatal(err)
	}

	if value != ts.Value {
		t.Fatalf("returned value '%s' does not match expected value '%s'", value, ts.Value)
	}
}

func TestSecretsBadPassphrase(t *testing.T) {
	var err error

	t.Log("generating identity...")
	ti, err := GenerateNewIdentity(t)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("generating impostor...")
	iti, err := GenerateNewIdentity(t)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("generating secret...")
	ts, err := GenerateSecret(t, ti)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("key: '%s', value: '%s'\n", ts.Key, ts.Value)

	value, err := GetSecret(t, iti, ts.Key)
	if err != nil {
		if _, ok := err.(ErrorNonZeroExit); !ok {
			t.Fatal(err)
		}
	}

	if value == ts.Value {
		t.Fatalf("command returned a value when it should not have")
	}
}

func GenerateSecret(t *testing.T, ti *TestIdentity) (*TestSecret, error) {
	ts := TestSecret{gofakeit.Word(), gofakeit.Word()}

	environment := map[string]string{"IDENTIFY_DB_PATH": dbPath}

	arguments := []string{"new", "secret", ts.Key, ts.Value, fmt.Sprintf("-id=%s", ti.ID)}

	var err error
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

			done := In(10*time.Millisecond, func() { c.Tty().Close() })

			t.Log("waiting for eof...")
			_, err = c.ExpectEOF()
			t.Log("waiting for tty to close...")
			<-done
		},
	)
	if err != nil {
		return nil, err
	}

	if result.Status != 0 {
		return nil, ErrorNonZeroExit{result.Status}
	}

	return &ts, err
}

func GetSecret(t *testing.T, ti *TestIdentity, key string) (string, error) {
	environment := map[string]string{"IDENTIFY_DB_PATH": dbPath}

	arguments := []string{"get", "secret", key, fmt.Sprintf("-id=%s", ti.ID)}

	t.Logf("running '%s'", strings.Join(arguments, " "))
	var value string
	var err error
	result := RunCommandTest(t, environment, arguments,
		func(c *expect.Console, cancel context.CancelFunc) {
			t.Log("waiting for passphrase prompt...")
			_, err = c.ExpectString("Passphrase: ")
			if err != nil {
				return
			}

			t.Log("sending passphrase")
			_, err = c.SendLine(ti.Passphrase)
			if err != nil {
				return
			}

			done := In(10*time.Millisecond, func() { c.Tty().Close() })

			t.Log("waiting for eof...")
			value, err = c.ExpectEOF()
			t.Log("waiting for tty to close...")
			<-done
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	value = strings.TrimSpace(value)

	if result.Status != 0 {
		return value, ErrorNonZeroExit{result.Status}
	}

	return value, err
}
