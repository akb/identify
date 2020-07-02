// "identity" authentication and authorization service
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
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/akb/identity/internal"
)

func main() {
	notice()

	if len(os.Args) < 2 {
		help()
		os.Exit(1)
	}

	switch command := os.Args[1]; command {
	case "new":
		newIdentity()
	case "new-token":
		newToken()
	case "listen":
		listen()
	case "help":
		help()
	default:
		help()
		os.Exit(1)
	}
}

func newIdentity() {
	validateDBPath()

	store, err := identity.NewLocalStore(dbPath)
	if err != nil {
		fmt.Printf("An error occurred while opening identity database file:\n")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer store.Close()

	fmt.Print("Enter passphrase: ")
	key, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println("")
	if err != nil {
		fmt.Printf("Error while reading passphrase.\n%s\n", err.Error())
		os.Exit(1)
	}

	id, err := store.New(string(key))
	if err != nil {
		fmt.Printf("Error while creating new identity.\n%s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("New identity created: %s\n", id)
}

func newToken() {
	flags := flag.NewFlagSet("new-token", flag.ExitOnError)
	var id = flags.String("id", "", "identity to authenticate")
	flags.Parse(os.Args[2:])

	if len(*id) == 0 {
		fmt.Println("an identity must be provided to authenticate")
		os.Exit(1)
	}

	fmt.Print("Enter passphrase: ")
	key, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println("")
	if err != nil {
		fmt.Printf("Error while reading passphrase.\n%s\n", err.Error())
		os.Exit(1)
	}

	validateDBPath()
	store, err := identity.NewLocalStore(dbPath)
	if err != nil {
		fmt.Printf("An error occurred while opening identity database file:\n")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer store.Close()

	i, err := store.Get(*id)
	if err != nil {
		fmt.Println("Unable to authenticate identity")
		os.Exit(1)
	}

	if !i.Authenticate(string(key)) {
		fmt.Println("Unable to authenticate identity")
		os.Exit(1)
	}

	validateTokenSecret()
	validateTokenDBPath()

	tokenStore, err := identity.NewLocalTokenStore(tokenDBPath, tokenSecret)
	if err != nil {
		fmt.Printf("An error occurred while opening token database file:\n")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer tokenStore.Close()

	access, refresh, err := tokenStore.New(i)
	if err != nil {
		fmt.Printf("An error occurred while generating token:\n")
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("Access Token: %s\n\nRefresh Token: %s\n", access, refresh)
}

func listen() {
	validateAddress()
	validateTokenSecret()
	validateDBPath()
	validateTokenDBPath()

	store, err := identity.NewLocalStore(dbPath)
	if err != nil {
		fmt.Printf("An error occurred while opening identity database file:\n")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer store.Close()

	tokenStore, err := identity.NewLocalTokenStore(tokenDBPath, tokenSecret)
	if err != nil {
		fmt.Printf("An error occurred while opening token database file:\n")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer tokenStore.Close()

	server := identity.NewHTTPServer(
		identity.HTTPServerConfig{address, realm, store, tokenStore})

	fmt.Printf("Identity API listening for HTTP requests on %s...\n", address)
	log.Fatal(server.ListenAndServe())
}
