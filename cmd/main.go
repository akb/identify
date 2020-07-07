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
	"os"

	"github.com/akb/go-cli"
)

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
