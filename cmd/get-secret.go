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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/akb/identify"
	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/identity"
)

type getSecretCommand struct{}

func (getSecretCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify get secret <key> <value>")
	fmt.Println("")
	fmt.Println("Set the value of a secret")
}

func (c getSecretCommand) Command(ctx context.Context, args []string) int {
	if len(os.Args) < 4 {
		c.Help()
		return 1
	}

	key := args[0]

	i := identify.IdentityFromContext(ctx)
	if i == nil {
		fmt.Println("unauthorized")
		return 1
	}

	dbPath, err := config.GetDBPath()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	store, err := identity.NewLocalStore(dbPath)
	if err != nil {
		fmt.Printf("An error occurred while opening identity database file:\n")
		fmt.Println(err.Error())
		return 1
	}
	defer store.Close()

	value, err := store.GetSecret(i, key)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	fmt.Println(value)

	return 0
}
