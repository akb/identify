package test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Netflix/go-expect"
	"github.com/brianvoe/gofakeit/v5"
	"github.com/google/uuid"
)

func TestNewIdentityCommand(t *testing.T) {
	dir, err := ioutil.TempDir("", "identify-testing")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	dbPath := filepath.Join(dir, "identity.db")
	passphrase := gofakeit.Password(true, true, true, true, true, 33)
	cmd := newIdentity{AuthenticatedCommand{passphrase}}

	testInteractiveCommand(t, dbPath, cmd)
}

type newIdentity struct {
	auth AuthenticatedCommand
}

func (i newIdentity) Command() []string { return []string{"new", "identity"} }

func (i newIdentity) Automate(c *expect.Console) (string, error) {
	output, err := i.auth.Authenticate(c)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

func (i newIdentity) Test(t *testing.T, c *expect.Console) {
	id, err := i.Automate(c)
	if err != nil {
		t.Fatal(err)
	}

	_, err = uuid.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
}
