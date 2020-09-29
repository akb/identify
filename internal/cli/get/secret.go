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

package get

import (
	"context"
	"fmt"

	"github.com/akb/go-cli"

	"github.com/akb/identify"
	"github.com/akb/identify/internal/config"
	"github.com/akb/identify/internal/identity"
)

type GetSecretCommand struct{}

func (GetSecretCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify get secret <key> <value>")
	fmt.Println("")
	fmt.Println("Set the value of a secret")
}

func (c GetSecretCommand) Command(ctx context.Context, args []string, s cli.System) int {
	if len(args) < 3 {
		c.Help()
		return 1
	}

	key := args[0]

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

	value, err := store.GetSecret(i, key)
	if err != nil {
		s.Fatal(err)
	}

	s.Println(value)
	return 0
}
