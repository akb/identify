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
	"io/ioutil"

	"github.com/akb/go-cli"

	"github.com/akb/identify"
	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/identity"
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

func (c *newTokenCommand) Command(ctx context.Context) int {
	if len(*c.id) == 0 {
		fmt.Println("an identity must be provided to authenticate")
		return 1
	}

	credsPath, err := config.GetCredentialsPath()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	dbPath, err := config.GetDBPath()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	tokenSecret, err := config.GetTokenSecret()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	tokenDBPath, err := config.GetTokenDBPath()
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

	tokenStore, err := token.NewLocalStore(tokenDBPath, tokenSecret)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}
	defer tokenStore.Close()

	passphrase, err := promptForPassphrase()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	public, err := store.Get(*c.id)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	private, err := public.Authenticate(passphrase)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	access, refresh, err := tokenStore.New(private)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	creds := identify.UnparsedTokenCredentials{access, refresh}
	credsJSON, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	if err = ioutil.WriteFile(credsPath, credsJSON, 0600); err != nil {
		fmt.Println(err.Error())
		return 1
	}

	fmt.Println("Authentication succeeded.")
	return 0
}

func (newTokenCommand) Subcommands() cli.CLI {
	return nil
}
