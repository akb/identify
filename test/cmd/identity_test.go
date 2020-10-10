// Identify authentication and authorization service
//
// Copyright (C) 2020 Alexei Broner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/Netflix/go-expect"
	"github.com/brianvoe/gofakeit/v5"
	"github.com/google/uuid"
)

var UUIDPattern *regexp.Regexp

func init() {
	UUIDPattern = regexp.MustCompile(
		`[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}`,
	)
}

type TestIdentity struct {
	ID         string
	Alias      string
	Passphrase string
}

func TestNewIdentityCommand(t *testing.T) {
	ti, err := GenerateNewIdentity(t)
	if err != nil {
		t.Fatal(err)
	}

	_, err = uuid.Parse(ti.ID)
	if err != nil {
		t.Fatalf("did not generate a valid uuid, instead received: '%s'\n", ti.ID)
	}
}

func GenerateNewIdentity(t *testing.T) (*TestIdentity, error) {
	ti := TestIdentity{
		ID:         "",
		Alias:      gofakeit.Username(),
		Passphrase: gofakeit.Password(true, true, true, true, true, 33),
	}

	environment := map[string]string{"IDENTIFY_DB_PATH": dbPath}

	arguments := []string{"new", "identity", fmt.Sprintf("-alias=%s", ti.Alias)}

	var err error
	t.Logf("running '%s'", strings.Join(arguments, " "))
	status := RunCommandTest(t, environment, arguments, func(c *expect.Console) {
		var id string
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

		t.Log("waiting for uuid...")
		id, err = c.Expect(expect.Regexp(UUIDPattern))
		if err != nil {
			return
		}

		done := CloseSoon(c.Tty())

		t.Log("waiting for eof...")
		_, err = c.ExpectEOF()
		t.Log("waiting for tty to close...")
		<-done

		id = strings.TrimSpace(id)

		_, err = uuid.Parse(id)
		if err != nil {
			return
		}

		ti.ID = id
	})
	if status != 0 {
		return nil, fmt.Errorf("error: '%s' returned nonzero status", strings.Join(arguments, " "))
	}

	return &ti, err
}
