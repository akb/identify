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

package newcmd

import (
	"context"
	"flag"
	"syscall"

	"github.com/akb/go-cli"

	"github.com/akb/identify/internal/config"
	"github.com/akb/identify/internal/identity"
	"golang.org/x/crypto/ssh/terminal"
)

type NewIdentityCommand struct {
	alias *string
}

func (c *NewIdentityCommand) Flags(f *flag.FlagSet) {
	c.alias = f.String("alias", "", "comma-separated list of aliases for identity")
}

func (NewIdentityCommand) Help() {}

func (c NewIdentityCommand) Command(ctx context.Context, args []string, s cli.System) int {
	dbPath, err := config.GetDBPath()
	if err != nil {
		s.Fatal(err)
	}

	s.Log("Creating local store at %s.", dbPath)
	store, err := identity.NewLocalStore(dbPath)
	if err != nil {
		s.Fatal(err)
	}
	defer store.Close()

	// FIXME: This is gross. In order to read the password silently, a syscall is
	// made to disable echo. this makes decoupling IO using go's Reader/Writer
	// impossible because the system is only aware of file descriptors.
	s.Print("Passphrase: ")
	passphrase, err := terminal.ReadPassword(int(syscall.Stdin))
	s.Println("")
	if err != nil {
		s.Fatal(err)
	}

	var aliases []string
	if len(*c.alias) > 0 {
		aliases = append(aliases, *c.alias)
	}
	public, _, err := store.NewIdentity(string(passphrase), aliases)
	if err != nil {
		s.Fatal(err)
	}

	s.Println(public.String())
	return 0
}
