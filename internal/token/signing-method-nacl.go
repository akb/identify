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

	"golang.org/x/crypto/nacl/sign"
)

var (
	ErrorInvalidPublicKey   = fmt.Errorf("key is not a NaCl public key")
	ErrorInvalidPrivateKey  = fmt.Errorf("key is not a NaCl private key")
	ErrorUnauthenticMessage = fmt.Errorf("message is unauthentic")
)

var SigningMethodNaCl *signingMethodNaCl

func init() {
	SigningMethodNaCl = &signingMethodNaCl{}
}

type signingMethodNaCl struct{}

func (signingMethodNaCl) Verify(message, signature string, key interface{}) error {
	publicKey, ok := key.(*ed25519.PublicKey)
	if !ok {
		return ErrorInvalidPublicKey
	}

	publicKeyBytes, ok := (interface{}(*publicKey)).([]byte)
	if !ok {
		return ErrorInvalidPublicKey
	}
	var publicKeyByteArray [32]byte
	copy(publicKeyByteArray[:], publicKeyBytes[:32])
	if _, ok = sign.Open(nil, []byte(message), &publicKeyByteArray); !ok {
		return ErrorUnauthenticMessage
	}

	return nil
}

func (signingMethodNaCl) Sign(message string, key interface{}) (string, error) {
	privateKey, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return "", ErrorInvalidPrivateKey
	}

	privateKeyBytes, ok := (interface{}(*privateKey)).([]byte)
	if !ok {
		return "", ErrorInvalidPrivateKey
	}
	var privateKeyByteArray [64]byte
	copy(privateKeyByteArray[:], privateKeyBytes[:64])

	signature := sign.Sign(nil, []byte(message), &privateKeyByteArray)
	return base64.RawStdEncoding.EncodeToString(signature), nil
}

func (signingMethodNaCl) Alg() string {
	return "NaCl"
}
