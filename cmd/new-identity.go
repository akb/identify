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
	"log"

	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/identity"
)

type newIdentityCommand struct{}

func (newIdentityCommand) Help() {}

func (c newIdentityCommand) Command(ctx context.Context, args []string) int {
	dbPath, err := config.GetDBPath()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	log.Printf("Creating local store at %s.", dbPath)
	store, err := identity.NewLocalStore(dbPath)
	if err != nil {
		log.Printf("An error occurred while opening identity database file:\n")
		log.Fatal(err)
	}
	defer store.Close()

	var alias string
	fmt.Printf("Alias: ")
	_, err = fmt.Scanf("%s", &alias)
	if err != nil {
		log.Printf("Error while reading alias.\n%s\n", err.Error())
		log.Fatal(err)
	}

	passphrase, err := promptForPassphrase()
	if err != nil {
		fmt.Printf("Error while reading passphrase.\n%s\n", err.Error())
		return 1
	}

	public, _, err := store.NewIdentity(string(passphrase), []string{alias})
	if err != nil {
		fmt.Printf("Error while creating new identity.\n%s\n", err.Error())
		return 1
	}

	fmt.Println(public.String())
	return 0
}
