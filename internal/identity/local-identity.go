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

	"github.com/google/uuid"
)

type localIdentity struct {
	ID         string `json:"id"`
	Salt       string `json:"salt"`
	Passphrase []byte `json:"passphrase"`
	AESKey     []byte `json:"aes-key"`
}

func NewLocalIdentity(passphrase string) (*localIdentity, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	salt, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	hash := sha256.New()
	hash.Write([]byte(salt.String()))

	return &localIdentity{
		ID:         id.String(),
		Salt:       salt.String(),
		Passphrase: hash.Sum([]byte(passphrase)),
	}, nil
}

func (l localIdentity) Authenticate(passphrase string) bool {
	hash := sha256.New()
	hash.Write([]byte(l.Salt))
	return subtle.ConstantTimeCompare(l.Passphrase, hash.Sum([]byte(passphrase))) == 1
}

func (l localIdentity) EncryptString(message string) ([]byte, []byte, error) {
	c, err := aes.NewCipher(l.Passphrase[:32])
	if err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	return nonce, aesgcm.Seal(nil, nonce, []byte(message), nil), nil
}

func (l localIdentity) DecryptString(nonce, encrypted []byte) (string, error) {
	c, err := aes.NewCipher(l.Passphrase[:32])
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	message, err := aesgcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return "", err
	}

	return string(message), nil
}

func (l localIdentity) String() string {
	return l.ID
}
