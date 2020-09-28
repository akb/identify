package test

import (
	"fmt"
	"log"
	"testing"

	"github.com/brianvoe/gofakeit/v5"
)

func TestSecrets(t *testing.T) {
	passphrase := gofakeit.Password(true, true, true, true, true, 33)

	id, _, err := GenerateNewIdentity(passphrase)
	if err != nil {
		t.Fatal(err)
	}

	key, value, err := GenerateSecret(id, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	getSecret, err := NewCommandTest(
		[]string{"get", "secret", key, fmt.Sprintf("-id=%s", id)},
		map[string]string{"IDENTIFY_DB_PATH": dbPath},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer getSecret.Close()

	err = getSecret.Start()
	if err != nil {
		t.Fatal(err)
	}

	var output string
	getSecret.Interact(func() {
		err = getSecret.Authenticate(passphrase)
		getSecret.Tty().Close()
		if err != nil {
			return
		}

		output, err = getSecret.GetOutput()
	})

	getSecret.Wait()
	if err != nil {
		t.Fatal(err)
	}

	if getSecret.StatusCode != 0 {
		t.Fatal("expected zero exit status")
	}

	if output != value {
		t.Fatalf("output did not match value. output: %s, value %s\n", output, value)
	}
}

func TestSecretsBadPassphrase(t *testing.T) {
	passphrase := gofakeit.Password(true, true, true, true, true, 33)

	id, _, err := GenerateNewIdentity(passphrase)
	if err != nil {
		t.Fatal(err)
	}

	key, value, err := GenerateSecret(id, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	getSecret, err := NewCommandTest(
		[]string{"get", "secret", key, fmt.Sprintf("-id=%s", id)},
		map[string]string{"IDENTIFY_DB_PATH": dbPath},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer getSecret.Close()

	err = getSecret.Start()
	if err != nil {
		t.Fatal(err)
	}

	var output string
	getSecret.Interact(func() {
		err = getSecret.Authenticate("not-the-right-passphrase")
		getSecret.Tty().Close()
		if err != nil {
			return
		}

		output, err = getSecret.GetOutput()
	})

	getSecret.Wait()
	if err != nil {
		t.Fatal(err)
	}

	if getSecret.StatusCode == 0 {
		t.Fatal("expected nonzero exit status")
	}

	if output == value {
		t.Fatal("output contained value but should not have")
	}

	if len(output) == 0 {
		t.Error("command with error status should print error text")
	}
}

func GenerateSecret(id, passphrase string) (string, string, error) {
	key := gofakeit.Word()
	value := gofakeit.Word()

	newSecret, err := NewCommandTest(
		[]string{"new", "secret", key, value, fmt.Sprintf("-id=%s", id)},
		map[string]string{"IDENTIFY_DB_PATH": dbPath},
	)
	if err != nil {
		return "", "", err
	}
	defer newSecret.Close()

	err = newSecret.Start()
	if err != nil {
		return "", "", err
	}

	var output string
	newSecret.Interact(func() {
		err = newSecret.Authenticate(passphrase)
		newSecret.Tty().Close()
		if err != nil {
			log.Println(err)
			return
		}

		output, err = newSecret.GetOutput()
		if err != nil {
			log.Println(err)
		}
	})
	if err != nil {
		return "", "", err
	}

	newSecret.Wait()

	if newSecret.StatusCode != 0 {
		err := fmt.Errorf("expected zero exit status; received %d.\ncommand output:\n%s\n", newSecret.StatusCode, output)
		return "", "", err
	}

	return key, value, nil
}
