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
	fmt.Println("Usage: identify get secret <key>")
	fmt.Println("")
	fmt.Println("Get the value of a secret")
}

func (c GetSecretCommand) Command(ctx context.Context, args []string, s cli.System) error {
	if len(args) != 1 {
		c.Help()
		return &cli.ExitError{1, "get secret requires a the key of a secret to get"}
	}

	key := args[0]

	i := identify.IdentityFromContext(ctx)
	if i == nil {
		return identify.ErrorUnauthorized
	}

	dbPath, err := config.GetDBPath(s)
	if err != nil {
		return err
	}

	store, err := identity.NewLocalStore(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	value, err := store.GetSecret(i, key)
	if err != nil {
		return err
	}

	s.Println(value)

	return nil
}
