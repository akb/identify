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
	"fmt"
	"os"

	"github.com/akb/identify"
	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/identity"
)

type newSecretCommand struct{}

func (newSecretCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify new secret <key> <value>")
	fmt.Println("")
	fmt.Println("Set the value of a secret")
}

func (c newSecretCommand) Command(ctx context.Context, args []string) int {
	if len(os.Args) < 5 {
		c.Help()
		return 1
	}

	key := args[0]
	value := args[1]

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

	if err = store.PutSecret(i, key, value); err != nil {
		fmt.Println(err.Error())
		return 1
	}

	return 0
}
