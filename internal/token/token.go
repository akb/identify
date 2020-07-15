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

package token

import (
	"fmt"
	"regexp"

	"github.com/akb/identify/internal/identity"
	"github.com/dgrijalva/jwt-go"
)

var listPattern = regexp.MustCompile(`[^\s]+`)

type Credentials struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

type Token interface {
	ID() string
	Identity() string
	GetClaim(string) string
	Valid() bool
	String() string
	HasPermission(string) bool
}

type Store interface {
	New(identity.Identity) (Token, Token, error)
	Parse(string) (Token, error)
	Delete(string, string) error
	Close()
}

type jwToken struct {
	*jwt.Token
	secret []byte
}

func Parse(unparsed string, secret []byte) (Token, error) {
	token, err := jwt.Parse(unparsed, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signature algorithm: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	return &jwToken{token, secret}, nil
}

func (t *jwToken) GetClaim(key string) string {
	claims, ok := t.Token.Claims.(jwt.MapClaims)
	if !ok {
		return ""
	}

	value, ok := claims[key].(string)
	if !ok {
		return ""
	}

	return value
}

func (t *jwToken) HasPermission(name string) bool {
	unparsed := t.GetClaim("permissions")
	if len(name) == 0 {
		return false
	}

	permissions := listPattern.FindAllString(unparsed, -1)
	for _, p := range permissions {
		if p == name {
			return true
		}
	}
	return false
}

func (t *jwToken) ID() string {
	return t.GetClaim("jti")
}

func (t *jwToken) Identity() string {
	return t.GetClaim("identity")
}

func (t *jwToken) Valid() bool {
	return t.Token.Valid
}

func (t *jwToken) String() string {
	s, err := t.SignedString([]byte(t.secret))
	if err != nil {
		return ""
	}
	return s
}
