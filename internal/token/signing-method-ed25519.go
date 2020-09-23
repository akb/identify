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
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/dgrijalva/jwt-go"
)

var (
	ErrorInvalidPublicKey   = fmt.Errorf("key is not an Ed25519	public key")
	ErrorInvalidPrivateKey  = fmt.Errorf("key is not an Ed25519 private key")
	ErrorInauthenticMessage = fmt.Errorf("message is inauthentic")
)

var (
	EncodeToString = base64.StdEncoding.EncodeToString
	DecodeString   = base64.StdEncoding.DecodeString
)

var SigningMethod *SigningMethodEd25519

func init() {
	SigningMethod = &SigningMethodEd25519{}
	jwt.RegisterSigningMethod(SigningMethod.Alg(), func() jwt.SigningMethod {
		return SigningMethod
	})
}

type SigningMethodEd25519 struct{}

func (SigningMethodEd25519) Verify(message, signature string, key interface{}) error {
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		log.Println("public key type assertion failed")
		return ErrorInvalidPublicKey
	}

	signatureBytes, err := DecodeString(signature)
	if err != nil {
		log.Println("unable to base64 decode signature")
		return err
	}

	if !ed25519.Verify(publicKey, []byte(message), signatureBytes) {
		return ErrorInauthenticMessage
	}
	return nil
}

func (SigningMethodEd25519) Sign(message string, key interface{}) (string, error) {
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		log.Println("private key type assertion failed")
		return "", ErrorInvalidPrivateKey
	}

	return EncodeToString(ed25519.Sign(privateKey, []byte(message))), nil
}

func (SigningMethodEd25519) Alg() string {
	return "Ed25519"
}
