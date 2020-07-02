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
	"path"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/akb/identity/internal"
)

var address, realm, dbPath, tokenDBPath, tokenSecret string

func init() {
	address = os.Getenv("IDENTITY_HTTP_ADDRESS")
	dbPath = os.Getenv("IDENTITY_DB_PATH")
	realm = os.Getenv("IDENTITY_REALM")
	tokenDBPath = os.Getenv("IDENTITY_TOKEN_DB_PATH")
	tokenSecret = os.Getenv("IDENTITY_TOKEN_SECRET")
}

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

func help() {
	fmt.Println("identity - authentication and authorization service")

	var command string
	if len(os.Args) == 2 && os.Args[1] == "help" {
		command = "help"
	} else if len(os.Args) > 2 {
		command = os.Args[2]
	}

	switch command {
	case "new":
		fmt.Println("Usage: identity new")
		fmt.Println("")
		fmt.Println("Prompts user for a key (passphrase) and creates a new identity")
		fmt.Println("")
		fmt.Println("Environment Variables:")
		fmt.Println("IDENTITY_DB_PATH")
		fmt.Println("- path to identity database file")
		fmt.Println("- default: $HOME/.identity/identity.db")

	case "listen":
		fmt.Println("Usage: identity listen")
		fmt.Println("")
		fmt.Println("Listen for incoming http requests")
		fmt.Println("")
		fmt.Println("Environment Variables:")
		fmt.Println("IDENTITY_HTTP_ADDRESS")
		fmt.Println("- address to listen for incoming http requests on")
		fmt.Println("IDENTITY_DB_PATH")
		fmt.Println("- path to identity database file")
		fmt.Println("- default: $HOME/.identity/identity.db")
		fmt.Println("IDENTITY_TOKEN_DB_PATH")
		fmt.Println("- path to token database file")
		fmt.Println("- default: $HOME/.identity/token.db")
		fmt.Println("IDENTITY_TOKEN_SECRET")
		fmt.Println("- secret key used to sign tokens")

	case "help":
		fmt.Println("Usage: identity help <subcommand>")
		fmt.Println("")
		fmt.Println("Display usage instructions for <subcommand>")
		fmt.Println("")
		fmt.Println("Subcommands:")
		fmt.Println("help         display usage instructions")
		fmt.Println("listen       listen for incoming http requests")

	default:
		fmt.Println("Usage: identity <subcommand>")
		fmt.Println("")
		fmt.Println("Subcommands:")
		fmt.Println("new          create a new identity")
		fmt.Println("listen       listen for incoming http requests")
		fmt.Println("help         display usage instructions")
	}
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
		dbPath = path.Join(home, ".identity", "identity.db")
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
		tokenDBPath = path.Join(home, ".identity", "token.db")
	}
}

func notice() {
	fmt.Println("identity Copyright (C) 2020 Alexei Broner")
	fmt.Println("")
	fmt.Println("This program comes with ABSOLUTELY NO WARRANTY.")
	fmt.Print("This is free software, and you are welcome to redistribute it ")
	fmt.Println("under certain conditions; type `identity license' for details.")
	fmt.Println("")
}
