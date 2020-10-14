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

package deletecmd

import (
	"context"
	"flag"
	"fmt"

	"github.com/pkg/errors"

	"github.com/akb/go-cli"

	"github.com/akb/identify"
	"github.com/akb/identify/internal/config"
	"github.com/akb/identify/internal/token"
)

type DeleteTokenCommand struct {
	id      *string
	tokenID *string
}

func (DeleteTokenCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify delete token <id>")
	fmt.Println("")
	fmt.Println("Delete a token.")
}

func (c *DeleteTokenCommand) Flags(f *flag.FlagSet) {
	c.id = f.String("id", "", "identity to authenticate")
	c.tokenID = f.String("token-id", "", "id of token to delete")
}

func (c DeleteTokenCommand) Command(ctx context.Context, args []string, s cli.System) error {
	tokenDBPath, err := config.GetTokenDBPath(s)
	if err != nil {
		return err
	}

	tokenStore, err := token.NewLocalStore(tokenDBPath)
	if err != nil {
		return err
	}
	defer tokenStore.Close()

	var id, tokenID string
	if len(*c.id) > 0 && len(*c.tokenID) > 0 {
		id = *c.id
		tokenID = *c.tokenID
	} else {
		return errors.Wrap(identify.ErrorValidation,
			"Both an identity and a token must be specified")
	}

	return tokenStore.Delete(id, tokenID)
}
