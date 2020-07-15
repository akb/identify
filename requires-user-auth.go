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

	"github.com/akb/go-cli"
	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/token"
)

type contextKey string

const tokenContextKey = contextKey("token")

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

func (c requiresUserAuthCommand) Command(ctx context.Context) int {
	credsPath, err := config.GetCredentialsPath()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	tokenSecret, err := config.GetTokenSecret()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	creds, err := LoadTokenCredentials(credsPath, tokenSecret)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	return c.wrapped.Command(context.WithValue(ctx, tokenContextKey, creds.Access))
}

func (c requiresUserAuthCommand) Subcommands() cli.CLI {
	return c.Subcommands()
}

func TokenFromContext(ctx context.Context) (t token.Token) {
	if v := ctx.Value(tokenContextKey); v != nil {
		if t, ok := v.(token.Token); ok {
			return t
		}
	}
	return
}
