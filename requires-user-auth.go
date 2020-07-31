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
	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/identity"
)

type contextKey string

const identityContextKey = contextKey("identity")

func RequiresUserAuth(wrapped cli.Command) cli.Command {
	return &requiresUserAuthCommand{nil, wrapped}
}

type requiresUserAuthCommand struct {
	id      *string
	wrapped cli.Command
}

func (c requiresUserAuthCommand) Help() {
	c.wrapped.Help()
}

func (c *requiresUserAuthCommand) Flags(f *flag.FlagSet) {
	c.id = f.String("id", "", "your identity")
	c.wrapped.Flags(f)
}

func (c requiresUserAuthCommand) Command(ctx context.Context, args []string) int {
	dbPath, err := config.GetDBPath()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	store, err := identity.NewLocalStore(dbPath)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	public, err := store.GetIdentity(*c.id)
	store.Close()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	fmt.Print("Enter passphrase: ")
	passphrase, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println("")
	if err != nil {
		fmt.Printf("Error while reading passphrase.\n%s\n", err.Error())
		return 1
	}

	private, err := public.Authenticate(string(passphrase))
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	ctx = context.WithValue(ctx, identityContextKey, private)

	return c.wrapped.Command(ctx, args)
}

func (c requiresUserAuthCommand) Subcommands() cli.CLI {
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
