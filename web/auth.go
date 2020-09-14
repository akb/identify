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
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"

	"github.com/akb/identify/internal/identity"
	"github.com/akb/identify/internal/token"
)

type contextKey string

const (
	tokenContextKey = contextKey("token")
)

var (
	ErrorNotAuthenticated = fmt.Errorf("Token not found in request context")
)

func TokenFromContext(ctx context.Context) *jwt.Token {
	return ctx.Value(tokenContextKey).(*jwt.Token)
}

func RequireTokenAuth(identity identity.PublicIdentity, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var authToken string
		authCookie, err := r.Cookie("Authorization")
		if err != nil {
			authHeader := r.Header.Get("Authorization")
			if len(authHeader) == 0 {
				log.Println("No authorization provided")
				log.Printf("Authorization header failed to parse: \"%s\"\n", authHeader)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}

			splitHeader := strings.Split(authHeader, " ")
			if len(splitHeader) < 2 {
				log.Printf("Authorization header failed to parse: \"%s\"\n", authHeader)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if splitHeader[0] != "Bearer" {
				log.Printf("Authorization header should have a scheme of 'Bearer'")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			authToken = splitHeader[1]
			log.Println("request authorization provided via header")
		} else {
			authToken = authCookie.Value
			log.Println("request authorization provided via cookie")
		}

		accessToken, err := token.Parse(identity.Ed25519PublicKey(), authToken)
		if err != nil {
			log.Printf("Token failed to parse: %s\nToken: %s\n", err.Error(), authToken)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if !accessToken.Valid {
			log.Printf("Token is invalid: %s\n", authToken)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		h.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), tokenContextKey, accessToken),
		))
	})
}
