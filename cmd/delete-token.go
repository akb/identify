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

	"github.com/dgrijalva/jwt-go"

	"github.com/akb/go-cli"

	"github.com/akb/identify"
	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/token"
)

type deleteTokenCommand struct {
	id      *string
	tokenID *string
}

func (deleteTokenCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify delete token <id>")
	fmt.Println("")
	fmt.Println("Delete a token.")
}

func (c *deleteTokenCommand) Flags(f *flag.FlagSet) {
	c.id = f.String("id", "", "identity to authenticate")
	c.tokenID = f.String("token-id", "", "id of token to delete")
}

func (c deleteTokenCommand) Command(ctx context.Context) int {
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

	tokenStore, err := token.NewLocalStore(tokenDBPath, tokenSecret)
	if err != nil {
		fmt.Println("An error occurred while opening token database file:")
		fmt.Println(err.Error())
		return 1
	}
	defer tokenStore.Close()

	var id, tokenID string
	if len(*c.id) > 0 && len(*c.tokenID) > 0 {
		id = *c.id
		tokenID = *c.tokenID

	} else if len(*c.id) > 0 || len(*c.tokenID) > 0 {
		fmt.Println("both an identity and a token must be specified")
		return 1

	} else {
		credsPath, err := config.GetCredentialsPath()
		if err != nil {
			println("error getting credentials path")
			fmt.Println(err)
			return 1
		}

		credsJSON, err := ioutil.ReadFile(credsPath)
		if err != nil {
			fmt.Println(err)
			return 1
		}

		var creds identify.UnparsedTokenCredentials
		err = json.Unmarshal(credsJSON, &creds)
		if err != nil {
			println("error unmarshaling creds json")
			fmt.Println(err)
			return 1
		}

		t, err := token.Parse(creds.Access)
		if err != nil {
			println("error parsing token")
			fmt.Println(err)
			return 1
		}

		claims, ok := t.Claims.(jwt.MapClaims)
		if !ok {
			fmt.Println("error parsing token")
			return 1
		}

		id, ok = claims["identity"].(string)
		if !ok {
			fmt.Println("error parsing token")
			return 1
		}

		tokenID, ok = claims["jti"].(string)
		if !ok {
			fmt.Println("error parsing token")
			return 1
		}
	}

	if err := tokenStore.Delete(id, tokenID); err != nil {
		fmt.Println(err.Error())
		return 1
	}

	fmt.Println("Token successfully deleted")
	return 0
}

func (deleteTokenCommand) Subcommands() cli.CLI {
	return nil
}
