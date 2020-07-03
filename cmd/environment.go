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
	"fmt"
	"os"
	"path"
)

var address, realm, dbPath, tokenDBPath, tokenSecret string

func init() {
	address = os.Getenv("IDENTITY_HTTP_ADDRESS")
	dbPath = os.Getenv("IDENTITY_DB_PATH")
	realm = os.Getenv("IDENTITY_REALM")
	tokenDBPath = os.Getenv("IDENTITY_TOKEN_DB_PATH")
	tokenSecret = os.Getenv("IDENTITY_TOKEN_SECRET")
}

func validateAddress() {
	if len(address) == 0 {
		fmt.Print("An address to listen on must be provided by the environment ")
		fmt.Println("variable IDENTITY_HTTP_ADDRESS.")
		os.Exit(1)
	}
}

func validateRealm() {
	if len(realm) == 0 {
		realm = "localhost"
	}
}

func validateTokenSecret() {
	if len(tokenSecret) == 0 {
		fmt.Print("An secret key to sign tokens with must be provided by the ")
		fmt.Println("environment variable IDENTITY_TOKEN_SECRET.")
		os.Exit(1)
	}
}

func validateDBPath() {
	if len(dbPath) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Print("A path to an identity database file must be provided by the ")
			fmt.Println("environment variable IDENTITY_DB_PATH.")
			os.Exit(1)
		}
		dbPath = path.Join(home, ".identify", "identity.db")
	}
}

func validateTokenDBPath() {
	if len(tokenDBPath) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Print("A path to an identity database file must be provided by the ")
			fmt.Println("environment variable IDENTITY_TOKEN_DB_PATH.")
			os.Exit(1)
		}
		tokenDBPath = path.Join(home, ".identify", "token.db")
	}
}
