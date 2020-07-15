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

	"github.com/akb/go-cli"

	"github.com/akb/identify"
	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/identity"
)

type sealCommand struct {
	message *string
}

func (sealCommand) Help() {}

func (c *sealCommand) Flags(f *flag.FlagSet) {
	c.message = f.String("message", "", "message to seal")
}

func (c sealCommand) Command(ctx context.Context) int {
	token := identify.TokenFromContext(ctx)
	if token == nil {
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

	i, err := store.Get(token.Identity())
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	nonceBytes, sealedBytes, err := i.EncryptString(*c.message)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	sealed := base64.StdEncoding.EncodeToString(sealedBytes)

	fmt.Printf("%s.%s", nonce, sealed)
	return 0
}

func (sealCommand) Subcommands() cli.CLI {
	return nil
}
