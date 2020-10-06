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
	"strings"
	"testing"

	"github.com/Netflix/go-expect"
	"github.com/brianvoe/gofakeit/v5"
	"github.com/google/uuid"
)

func TestNewIdentityCommand(t *testing.T) {
	passphrase := gofakeit.Password(true, true, true, true, true, 33)

	environment := map[string]string{"IDENTIFY_DB_PATH": dbPath}

	arguments := []string{"new", "identity"}

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

		stdout, err := c.ExpectEOF()
		if err != nil {
			return
		}

		_, err = uuid.Parse(strings.TrimSpace(stdout))
		if err != nil {
			t.Errorf("Failed to parse UUID from: %s\n", strings.TrimSpace(stdout))
			return
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	if status != 0 {
		t.Fatal("\"new identity\" returned nonzero status")
	}
}

func GenerateNewIdentity(t *testing.T, passphrase string) (id, alias string, err error) {
	alias = gofakeit.Username()

	environment := map[string]string{"IDENTIFY_DB_PATH": dbPath}

	arguments := []string{"new", "identity"}
	RunCommandTest(t, environment, arguments, func(c *expect.Console) {
		_, err = c.Expectf("Passphrase: ")
		if err != nil {
			return
		}

		_, err = c.SendLine(passphrase)
		if err != nil {
			return
		}

		stdout, err := c.ExpectEOF()
		if err != nil {
			return
		}

		id = strings.TrimSpace(stdout)

		_, err = uuid.Parse(id)
		if err != nil {
			return
		}
	})

	return
}
