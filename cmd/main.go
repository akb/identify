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
	"os"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/akb/go-cli"
)

func promptForPassphrase() (string, error) {
	fmt.Print("Enter passphrase: ")
	passphrase, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println("")
	if err != nil {
		fmt.Printf("Error while reading passphrase.\n%s\n", err.Error())
		return "", err
	}
	return string(passphrase), nil
}

type identify struct {
	cmd *newTokenCommand
}

func (i identify) Help() {
	i.cmd.Help()
}

func (i identify) Flags(f *flag.FlagSet) {
	i.cmd.Flags(f)
}

func (i identify) Command(ctx context.Context) int {
	return i.cmd.Command(ctx)
}

func (identify) Subcommands() cli.CLI {
	return map[string]cli.Command{
		"new":    &newCommand{},
		"delete": &deleteCommand{},
		"listen": &listenCommand{},
	}
}

func main() {
	os.Exit(cli.Main("identify", &identify{&newTokenCommand{}}))
}
