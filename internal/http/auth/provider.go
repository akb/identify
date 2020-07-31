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

package auth

import (
	"context"
	"fmt"

	"github.com/akb/identify/internal/identity"
)

type contextKey string

const (
	identityContextKey = contextKey("identity")
)

type Provider struct {
	Realm string

	IdentityStore identity.Store
	//TokenStore    token.Store
}

func IdentityFromContext(ctx context.Context) (identity.PrivateIdentity, error) {
	v := ctx.Value(identityContextKey)
	if v == nil {
		return nil, fmt.Errorf("Identity not found in request context")
	}
	return v.(identity.PrivateIdentity), nil
}