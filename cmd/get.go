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

	"github.com/akb/go-cli"
	"github.com/akb/identify"
)

type getCommand struct{}

func (getCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify get <resource> <key>")
	fmt.Println("")
	fmt.Println("Get the value of a resource.")
}

func (c getCommand) Command(ctx context.Context, args []string) int {
	c.Help()
	return 0
}

func (c getCommand) Subcommands() cli.CLI {
	return cli.CLI{
		"secret": identify.RequiresUserAuth(&getSecretCommand{}),
	}
}
