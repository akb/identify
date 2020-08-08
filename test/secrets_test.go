package test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Netflix/go-expect"
	"github.com/brianvoe/gofakeit/v5"
)

func TestSecrets(t *testing.T) {
	dir, err := ioutil.TempDir("", "identify-testing")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	dbPath := filepath.Join(dir, "identity.db")
	passphrase := gofakeit.Password(true, true, true, true, true, 33)

	t.Log("generating new identity...")
	newIdentityCmd := newIdentity{AuthenticatedCommand{passphrase}}
	t.Logf("%% %s\n", strings.Join(newIdentityCmd.Command(), " "))
	id, err := automateInteractiveCommand(dbPath, newIdentityCmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("new identity created: %s\n", id)

	key := fmt.Sprintf("%s-%s", gofakeit.Word(), gofakeit.Word())
	value := gofakeit.Word()

	t.Log("storing secret...")
	newSecretCmd := newSecret{AuthenticatedCommand{passphrase}, id, key, value}
	t.Logf("%% %s\n", strings.Join(newSecretCmd.Command(), " "))
	testInteractiveCommand(t, dbPath, newSecretCmd)

	t.Log("retrieving secret...")
	getSecretCmd := getSecret{AuthenticatedCommand{passphrase}, id, key, value}
	t.Logf("%% %s\n", strings.Join(getSecretCmd.Command(), " "))
	testInteractiveCommand(t, dbPath, getSecretCmd)
}

type newSecret struct {
	auth AuthenticatedCommand

	id, key, value string
}

func (i newSecret) Command() []string {
	return []string{"new", "secret", i.key, i.value, fmt.Sprintf("-id=%s", i.id)}
}

func (i newSecret) Automate(c *expect.Console) (string, error) {
	output, err := i.auth.Authenticate(c)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

func (i newSecret) Test(t *testing.T, c *expect.Console) {
	output, err := i.Automate(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(output) > 0 {
		t.Fatal("'new secret' produced output when it should not have")
	}
}

type getSecret struct {
	auth AuthenticatedCommand

	id, key, value string
}

func (i getSecret) Command() []string {
	return []string{"get", "secret", i.key, fmt.Sprintf("-id=%s", i.id)}
}

func (i getSecret) Automate(c *expect.Console) (string, error) {
	output, err := i.auth.Authenticate(c)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

func (i getSecret) Test(t *testing.T, c *expect.Console) {
	output, err := i.Automate(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(output)
	if output != i.value {
		t.Fatalf("'get secret' returned incorrect value: %s != %s", output, i.value)
	}
}
