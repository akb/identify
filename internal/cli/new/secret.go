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

package newcmd

import (
	"context"
	"fmt"

	"github.com/akb/go-cli"

	"github.com/akb/identify"
	"github.com/akb/identify/internal/config"
	"github.com/akb/identify/internal/identity"
)

type NewSecretCommand struct{}

func (NewSecretCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify new secret <key> <value>")
	fmt.Println("")
	fmt.Println("Set the value of a secret")
}

func (c NewSecretCommand) Command(ctx context.Context, args []string, s cli.System) int {
	if len(args) < 4 {
		c.Help()
		return 1
	}

	key := args[0]
	value := args[1]

	i := identify.IdentityFromContext(ctx)
	if i == nil {
		s.Fatal("unauthorized")
	}

	dbPath, err := config.GetDBPath()
	if err != nil {
		s.Fatal(err)
	}

	store, err := identity.NewLocalStore(dbPath)
	if err != nil {
		s.Fatal(err)
	}
	defer store.Close()

	if err = store.PutSecret(i, key, value); err != nil {
		s.Fatal(err)
	}

	return 0
}
