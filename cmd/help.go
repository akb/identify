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
)

func notice() {
	fmt.Println("Identify Copyright (C) 2020 Alexei Broner")
	fmt.Println("")
	fmt.Println("This program comes with ABSOLUTELY NO WARRANTY.")
	fmt.Print("This is free software, and you are welcome to redistribute it ")
	fmt.Println("under certain conditions; type `identify license' for details.")
	fmt.Println("")
}

func help() {
	fmt.Println("identify - authentication and authorization service")

	var command string
	if len(os.Args) == 2 && os.Args[1] == "help" {
		command = "help"
	} else if len(os.Args) > 2 {
		command = os.Args[2]
	}

	switch command {
	case "new-identity":
		fmt.Println("Usage: identify new-identity")
		fmt.Println("")
		fmt.Println("Prompts user for a key (passphrase) and creates a new identity")
		fmt.Println("")
		fmt.Println("Environment Variables:")
		fmt.Println("IDENTITY_DB_PATH")
		fmt.Println("- path to identity database file")
		fmt.Println("- default: $HOME/.identify/identity.db")

	case "log-out":
		fmt.Println("Usage: identify log-out")
		fmt.Println("")
		fmt.Println("Deletes a token belonging to the authenticated user")
		fmt.Println("")
		fmt.Println("Environment Variables:")
		fmt.Println("IDENTITY_DB_PATH")
		fmt.Println("- path to identity database file")
		fmt.Println("- default: $HOME/.identify/identity.db")
		fmt.Println("IDENTITY_TOKEN_DB_PATH")
		fmt.Println("- path to token database file")
		fmt.Println("- default: $HOME/.identify/token.db")
		fmt.Println("IDENTITY_TOKEN_SECRET")
		fmt.Println("- secret key used to sign tokens")

	case "listen":
		fmt.Println("Usage: identify listen")
		fmt.Println("")
		fmt.Println("Listen for incoming http requests")
		fmt.Println("")
		fmt.Println("Environment Variables:")
		fmt.Println("IDENTITY_HTTP_ADDRESS")
		fmt.Println("- address to listen for incoming http requests on")
		fmt.Println("IDENTITY_DB_PATH")
		fmt.Println("- path to identity database file")
		fmt.Println("- default: $HOME/.identify/identity.db")
		fmt.Println("IDENTITY_TOKEN_DB_PATH")
		fmt.Println("- path to token database file")
		fmt.Println("- default: $HOME/.identify/token.db")
		fmt.Println("IDENTITY_TOKEN_SECRET")
		fmt.Println("- secret key used to sign tokens")

	case "help":
		fmt.Println("Usage: identify <subcommand>")
		fmt.Println("")
		fmt.Println("Subcommands:")
		fmt.Println("new          create a new identity")
		fmt.Println("new-token    create a new token")
		fmt.Println("delete-token delete a new token")
		fmt.Println("listen       listen for incoming http requests")
		fmt.Println("help         display usage instructions")

	default:
		fmt.Println("Usage: identify")
		fmt.Println("")
		fmt.Println("Authenticates user and issues a new pair of tokens")
		fmt.Println("")
		fmt.Println("Environment Variables:")
		fmt.Println("IDENTITY_DB_PATH")
		fmt.Println("- path to identity database file")
		fmt.Println("- default: $HOME/.identify/identity.db")
		fmt.Println("IDENTITY_TOKEN_DB_PATH")
		fmt.Println("- path to token database file")
		fmt.Println("- default: $HOME/.identify/token.db")
		fmt.Println("IDENTITY_TOKEN_SECRET")
		fmt.Println("- secret key used to sign tokens")
	}
}
