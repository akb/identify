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

	"github.com/dgrijalva/jwt-go"
)

type Credentials struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

func Parse(unparsed string) (*jwt.Token, error) {
	token, err := jwt.Parse(unparsed, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*signingMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signature algorithm: %v", token.Header["alg"])
		}
		return []byte{}, nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}
