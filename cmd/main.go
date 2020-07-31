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
	"os"

	"github.com/akb/go-cli"
)

type identifyCommand struct{}

func (c identifyCommand) Help() {
	fmt.Println(`
identify - authentication and authorization service

Usage: identify <subcommand>

Subcommands:
new     create new resources
get     get resource content
delete  delete resources
listen  listen for http requests
`)
}

func (c identifyCommand) Command(ctx context.Context, args []string) int {
	c.Help()
	return 1
}

func (identifyCommand) Subcommands() cli.CLI {
	return map[string]cli.Command{
		"new":    &newCommand{},
		"get":    &getCommand{},
		"delete": &deleteCommand{},
		"listen": &listenCommand{},
	}
}

func main() {
	os.Exit(cli.Main(&identifyCommand{}))
}
