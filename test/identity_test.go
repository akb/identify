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

	testInteractiveCommand(t, dbPath, newIdentityTest{passphrase})
}

type newIdentityTest struct {
	passphrase string
}

func (i newIdentityTest) Command() string { return "new identity" }

func (i newIdentityTest) TestCommand(t *testing.T, c *expect.Console) {
	var err error
	_, err = c.Expectf("Enter passphrase:")
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.SendLine(i.passphrase)
	if err != nil {
		t.Fatal(err)
	}

	output, err := c.ExpectEOF()
	if err != nil {
		t.Fatal(err)
	}

	id := strings.TrimSpace(output)

	_, err = uuid.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
}
