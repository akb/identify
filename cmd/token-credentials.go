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

package main

import (
	"encoding/json"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"

	"github.com/akb/identify/internal/token"
)

type UnparsedTokenCredentials struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

func (c UnparsedTokenCredentials) Parse() (*TokenCredentials, error) {
	access, err := token.Parse(c.Access)
	if err != nil {
		return nil, err
	}

	// TODO: Attempt to refresh if access is expired
	return &TokenCredentials{access, nil}, nil
}

type TokenCredentials struct {
	Access  *jwt.Token
	Refresh *jwt.Token
}

func LoadTokenCredentials(credsPath string) (*TokenCredentials, error) {
	credsJSON, err := ioutil.ReadFile(credsPath)
	if err != nil {
		return nil, err
	}

	var creds UnparsedTokenCredentials
	if err = json.Unmarshal(credsJSON, &creds); err != nil {
		return nil, err
	}

	return creds.Parse()
}
