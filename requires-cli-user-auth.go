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

package identify

import (
	"context"
	"flag"
	"fmt"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/akb/go-cli"
	"github.com/akb/identify/internal/config"
	"github.com/akb/identify/internal/identity"
)

type contextKey string

const identityContextKey = contextKey("identity")

func RequiresCLIUserAuth(wrapped cli.Command) cli.Command {
	return &requiresCLIUserAuthCommand{nil, wrapped}
}

type requiresCLIUserAuthCommand struct {
	id      *string
	wrapped cli.Command
}

func (c requiresCLIUserAuthCommand) Help() {
	c.wrapped.Help()
}

func (c *requiresCLIUserAuthCommand) Flags(f *flag.FlagSet) {
	c.id = f.String("id", "", "your identity")
	if b, ok := (interface{})(c.wrapped).(cli.HasFlags); ok {
		b.Flags(f)
	}
}

func (c requiresCLIUserAuthCommand) Command(ctx context.Context, args []string, s cli.System) {
	dbPath, err := config.GetDBPath()
	if err != nil {
		s.Fatal(err)
	}

	store, err := identity.NewLocalStore(dbPath)
	if err != nil {
		s.Fatal(err)
	}

	public, err := store.GetIdentity(*c.id)
	store.Close()
	if err != nil {
		s.Fatal(err)
	}

	fmt.Print("Passphrase: ")
	passphrase, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println("")
	if err != nil {
		s.Fatalf("Error while reading passphrase.\n%s\n", err.Error())
	}

	private, err := public.Authenticate(string(passphrase))
	if err != nil {
		s.Fatal(err)
	}

	ctx = context.WithValue(ctx, identityContextKey, private)

	if b, ok := (interface{})(c.wrapped).(cli.Action); ok {
		b.Command(ctx, args, s)
	}

	c.Help()
	s.Exit(1)
}

func (c requiresCLIUserAuthCommand) Subcommands() cli.CLI {
	if b, ok := (interface{})(c.wrapped).(cli.HasSubcommands); ok {
		return b.Subcommands()
	}
	return nil
}

func IdentityFromContext(ctx context.Context) identity.PrivateIdentity {
	if v := ctx.Value(identityContextKey); v != nil {
		if p, ok := v.(identity.PrivateIdentity); ok {
			return p
		}
	}
	return nil
}
