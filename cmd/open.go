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

	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/identity"
)

type openCommand struct {
	from    *string
	message *string
}

func (openCommand) Help() {}

func (c *openCommand) Flags(f *flag.FlagSet) {
	c.from = f.String("from", "", "id of message sender")
	c.message = f.String("message", "", "sealed message to open")
}

func (c openCommand) Command(ctx context.Context) int {
	i := IdentityFromContext(ctx)
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
		fmt.Println(err.Error())
		return 1
	}
	defer store.Close()

	from, err := store.GetIdentity(*c.from)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	message, err := i.OpenMessage(from, []byte(*c.message))
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	fmt.Println(message)
	return 0
}
