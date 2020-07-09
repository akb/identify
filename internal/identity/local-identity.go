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

package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"io"
)

type localIdentity struct {
	ID         string `json:"id"`
	Salt       string `json:"salt"`
	Passphrase []byte `json:"passphrase"`
}

func (l localIdentity) Authenticate(passphrase string) bool {
	hash := sha256.New()
	hash.Write([]byte(l.ID))
	hash.Write([]byte(l.Salt))
	return subtle.ConstantTimeCompare(l.Passphrase, hash.Sum([]byte(passphrase))) == 1
}

func (l localIdentity) Encrypt(message string) (string, string, error) {
	c, err := aes.NewCipher(l.Passphrase[:32])
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	return aesgcm.Seal(nil, nonce, message, nil), nonce, nil
}

func (l localIdentity) Decrypt(message, nonce string) (string, error) {
	c, err := aes.NewCipher(l.Passphrase[:32])
	if err != nil {
		return "", nil
	}

	aesgcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", nil
	}

	return aesgcm.Open(nil, nonce, encrypted, nil)
}

func (l localIdentity) String() string {
	return l.ID
}
