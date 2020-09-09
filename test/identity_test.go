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
