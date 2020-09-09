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
	"encoding/json"
	"flag"
	"fmt"

	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/token"
)

type newTokenCommand struct {
	id *string
}

func (newTokenCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify")
	fmt.Println("")
	fmt.Println("Authenticates user and issues a new pair of tokens")
	fmt.Println("")
	fmt.Println("Environment Variables:")
	fmt.Println("")
	fmt.Println("IDENTIFY_DB_PATH")
	fmt.Println("- path to identity database file")
	fmt.Println("- default: $HOME/.identify/identity.db")
	fmt.Println("")
	fmt.Println("IDENTIFY_CREDENTIALS_PATH")
	fmt.Println("- path to save credentials file as")
	fmt.Println("- default: $HOME/.identify/credentials.json")
	fmt.Println("")
	fmt.Println("IDENTIFY_TOKEN_DB_PATH")
	fmt.Println("- path to token database file")
	fmt.Println("- default: $HOME/.identify/token.db")
	fmt.Println("")
	fmt.Println("IDENTIFY_TOKEN_SECRET")
	fmt.Println("- secret key used to sign tokens")
}

func (c *newTokenCommand) Flags(f *flag.FlagSet) {
	c.id = f.String("id", "", "identity to authenticate")
}

func (c *newTokenCommand) Command(ctx context.Context, args []string) int {
	if len(*c.id) == 0 {
		fmt.Println("an identity must be provided to authenticate")
		return 1
	}

	tokenDBPath, err := config.GetTokenDBPath()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	tokenStore, err := token.NewLocalStore(tokenDBPath)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}
	defer tokenStore.Close()

	identity := IdentityFromContext(ctx)
	if identity == nil {
		fmt.Println("unauthorized")
		return 1
	}

	access, refresh, err := tokenStore.New(identity)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	creds := UnparsedTokenCredentials{access, refresh}
	credsJSON, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}
	fmt.Println(string(credsJSON))
	return 0
}
