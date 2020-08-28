package test

import (
	"testing"

	"github.com/brianvoe/gofakeit/v5"
	"github.com/google/uuid"
)

func TestNewIdentityCommand(t *testing.T) {
	newIdentity, err := NewCommandTest(
		[]string{"new", "identity"},
		map[string]string{"IDENTIFY_DB_PATH": dbPath},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer newIdentity.Close()

	err = newIdentity.Start()
	if err != nil {
		t.Fatal(err)
	}

	newIdentity.Interact(func() {
		passphrase := gofakeit.Password(true, true, true, true, true, 33)

		err := newIdentity.Authenticate(passphrase)
		if err != nil {
			t.Fatal(err)
		}

		newIdentity.Tty().Close()

		output, err := newIdentity.GetOutput()
		if err != nil {
			t.Fatal(err)
		}

		_, err = uuid.Parse(output)
		if err != nil {
			t.Errorf("Failed to parse UUID from: %s\n", output)
			t.Fatal(err)
		}
	})

	newIdentity.Wait()
}

func GenerateNewIdentity(passphrase string) (id string, err error) {
	newIdentity, err := NewCommandTest(
		[]string{"new", "identity"},
		map[string]string{"IDENTIFY_DB_PATH": dbPath},
	)
	if err != nil {
		return
	}
	defer newIdentity.Close()

	err = newIdentity.Start()
	if err != nil {
		return
	}

	newIdentity.Interact(func() {
		err = newIdentity.Authenticate(passphrase)
		newIdentity.Tty().Close()
		if err != nil {
			return
		}

		id, err = newIdentity.GetOutput()
		if err != nil {
			return
		}
	})

	newIdentity.Wait()

	return
}
