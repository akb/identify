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
	"log"
	"os"

	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/http"
	"github.com/akb/identify/internal/identity"
	"github.com/akb/identify/internal/token"
)

type listenCommand struct{}

func (listenCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify new <resource>")
	fmt.Println("")
	fmt.Println("Create new resources.")
}

func (c listenCommand) Command(ctx context.Context, args []string) int {
	address := config.GetHTTPAddress()
	realm := config.GetRealm()

	dbPath, err := config.GetDBPath()
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
		fmt.Printf("An error occurred while opening identity database file:\n")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer store.Close()

	tokenStore, err := token.NewLocalStore(tokenDBPath)
	if err != nil {
		fmt.Printf("An error occurred while opening token database file:\n")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer tokenStore.Close()

	server := http.NewServer(
		http.ServerConfig{address, realm, store}) //, tokenStore})

	fmt.Printf("Identity API listening for HTTP requests on %s...\n", address)
	log.Fatal(server.ListenAndServe())
	return 0
}
