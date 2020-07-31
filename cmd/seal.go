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
	"encoding/base64"
	"flag"
	"fmt"

	"github.com/akb/identify"
	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/identity"
)

type sealCommand struct {
	to      *string
	message *string
}

func (sealCommand) Help() {
	fmt.Println("identify seal - seal a message with a passphrase")
	fmt.Println("")
	fmt.Println("Usage: identify seal -message=\"message to seal\"")
	fmt.Println("")
}

func (c *sealCommand) Flags(f *flag.FlagSet) {
	c.to = f.String("to", "", "id of message recipient")
	c.message = f.String("message", "", "message to seal")
}

func (c sealCommand) Command(ctx context.Context) int {
	i := identify.IdentityFromContext(ctx)
	if i == nil {
		fmt.Println("unauthorized")
		return 1
	}

	if len(*c.to) == 0 || len(*c.message) == 0 {
		c.Help()
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

	to, err := store.GetIdentity(*c.to)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	sealedBytes, err := i.SealMessage(to, *c.message)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	sealed := base64.RawStdEncoding.EncodeToString(sealedBytes)
	fmt.Println(sealed)
	return 0
}
