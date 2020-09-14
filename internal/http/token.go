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

package web

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/akb/identify/internal/token"
)

const (
	tokenContextKey = contextKey("token")
)

func TokenFromContext(ctx context.Context) (token.Token, error) {
	v := ctx.Value(tokenContextKey)
	if v == nil {
		return nil, fmt.Errorf("Token not found in request context")
	}
	return v.(token.Token), nil
}

func (p AuthProvider) RequireTokenAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		splitHeader := strings.Split(authHeader, " ")
		if len(splitHeader) < 2 {
			log.Printf("Authorization header failed to parse: \"%s\"\n", authHeader)
			p.unauthorizedToken(w)
			return
		}

		if splitHeader[0] != "Bearer" {
			log.Printf("Authorization header should have a scheme of 'Bearer'")
			p.unauthorizedToken(w)
			return
		}

		token, err := p.TokenStore.Parse(splitHeader[1])
		if err != nil {
			log.Printf("Token failed to parse: %s\n", err.Error())
			p.unauthorizedToken(w)
			return
		}

		if !token.Valid() {
			log.Printf("Token is invalid: %s\n", splitHeader[1])
			p.unauthorizedToken(w)
			return
		}

		id := token.Identity()
		if id == "" {
			log.Println("Token has no identity")
			p.unauthorizedToken(w)
			return
		}

		identity, err := p.IdentityStore.Get(id)
		if err != nil {
			log.Printf("error retrieving identity from database: %s\n", err.Error())
			p.unauthorizedToken(w)
			return
		}

		h.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), identityContextKey, identity),
		))
	})
}

func (p AuthProvider) unauthorizedToken(w http.ResponseWriter) {
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}
