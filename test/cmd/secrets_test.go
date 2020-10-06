package test

import (
	"fmt"
	"testing"

	"github.com/Netflix/go-expect"
	"github.com/brianvoe/gofakeit/v5"
)

func TestSecrets(t *testing.T) {
	var err error

	passphrase := gofakeit.Password(true, true, true, true, true, 33)

	id, _, err := GenerateNewIdentity(t, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	key, value, err := GenerateSecret(t, id, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	environment := map[string]string{"IDENTIFY_DB_PATH": dbPath}
	arguments := []string{"get", "secret", key, fmt.Sprintf("-id=%s", id)}

	var stdout string
	status := RunCommandTest(t, environment, arguments, func(c *expect.Console) {
		_, err = c.Expectf("Passphrase: ")
		if err != nil {
			return
		}

		_, err = c.SendLine(passphrase)
		if err != nil {
			return
		}

		stdout, err = c.ExpectEOF()
	})
	if err != nil {
		t.Fatal(err)
	}

	if status != 0 {
		t.Fatal("expected zero exit status")
	}

	if stdout != value {
		t.Fatalf("output did not match value. output: %s, value %s\n", stdout, value)
	}
}

func TestSecretsBadPassphrase(t *testing.T) {
	var err error

	passphrase := gofakeit.Password(true, true, true, true, true, 33)

	id, _, err := GenerateNewIdentity(t, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	key, value, err := GenerateSecret(t, id, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	arguments := []string{"get", "secret", key, fmt.Sprintf("-id=%s", id)}
	environment := map[string]string{"IDENTIFY_DB_PATH": dbPath}

	var stdout string
	status := RunCommandTest(t, environment, arguments, func(c *expect.Console) {
		_, err = c.Expectf("Passphrase: ")
		if err != nil {
			return
		}

		_, err = c.SendLine("not-the-right-passphrase")
		if err != nil {
			return
		}

		stdout, err = c.ExpectEOF()
	})
	if err != nil {
		t.Fatal(err)
	}

	if status == 0 {
		t.Fatal("expected nonzero exit status")
	}

	if len(stdout) == 0 {
		t.Error("command with error status should print error text")
	}

	if stdout == value {
		t.Fatal("output contained value but should not have")
	}
}

func GenerateSecret(t *testing.T, id, passphrase string) (string, string, error) {
	key := gofakeit.Word()
	value := gofakeit.Word()

	environment := map[string]string{"IDENTIFY_DB_PATH": dbPath}
	arguments := []string{"new", "secret", key, value, fmt.Sprintf("-id=%s", id)}

	var stdout string
	var err error
	status := RunCommandTest(t, environment, arguments, func(c *expect.Console) {
		_, err = c.Expectf("Passphrase: ")
		if err != nil {
			return
		}

		_, err = c.SendLine(passphrase)
		if err != nil {
			return
		}

		stdout, err = c.ExpectEOF()
		if err != nil {
			return
		}
	})
	if err != nil {
		return "", "", err
	}

	if status != 0 {
		t.Errorf("expected zero exit status; received %d.\ncommand output:\n%s\n", status, stdout)
	}

	return key, value, nil
}
