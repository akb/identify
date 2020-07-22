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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

var (
	errorCantAuthenticate = fmt.Errorf("can not authenticate a private identity")
)

type PrivateIdentity interface {
	PublicIdentity

	SignPrivateKey() [64]byte
	SealPrivateKey() [32]byte

	OpenMessage(PublicIdentity, []byte) (string, error)
	SealMessage(PublicIdentity, string) ([]byte, error)
}

type jsonPrivateIdentity struct {
	SignPrivateKey string `json:"sign-private-key"`
	SealPrivateKey string `json:"seal-private-key"`
}

type privateIdentity struct {
	public *publicIdentity

	signPrivateKey *[64]byte
	sealPrivateKey *[32]byte
}

func (i privateIdentity) SignPublicKey() [32]byte {
	return i.public.SignPublicKey()
}

func (i privateIdentity) SealPublicKey() [32]byte {
	return i.public.SealPublicKey()
}

func (i privateIdentity) String() string {
	return i.public.String()
}

func (i privateIdentity) Authenticate(passphrase string) (PrivateIdentity, error) {
	return nil, errorCantAuthenticate
}

func (i privateIdentity) SignPrivateKey() [64]byte {
	return *i.signPrivateKey
}

func (i privateIdentity) SealPrivateKey() [32]byte {
	return *i.sealPrivateKey
}

func (i privateIdentity) OpenMessage(
	sender PublicIdentity,
	encrypted []byte,
) (string, error) {
	var nonce [24]byte
	copy(nonce[:], encrypted[:24])
	key := sender.SealPublicKey()
	decrypted, ok := box.Open(nil, encrypted[24:], &nonce, &key, i.sealPrivateKey)
	if !ok {
		return "", fmt.Errorf("unauthorized")
	}
	return string(decrypted), nil
}

func (i privateIdentity) SealMessage(
	recipient PublicIdentity,
	message string,
) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	key := recipient.SealPublicKey()
	return box.Seal(nonce[:], []byte(message), &nonce, &key, i.sealPrivateKey), nil
}

func (i privateIdentity) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonPrivateIdentity{
		SignPrivateKey: base64.RawStdEncoding.EncodeToString(i.signPrivateKey[:]),
		SealPrivateKey: base64.RawStdEncoding.EncodeToString(i.sealPrivateKey[:]),
	})
}

func (i *privateIdentity) UnmarshalJSON(marshaled []byte) error {
	var unmarshaled jsonPrivateIdentity
	if err := json.Unmarshal(marshaled, &unmarshaled); err != nil {
		return err
	}

	signPrivateKey, err := base64.RawStdEncoding.DecodeString(unmarshaled.SignPrivateKey)
	if err != nil {
		return err
	}
	i.signPrivateKey = &[64]byte{}
	copy(i.signPrivateKey[:], signPrivateKey[:64])

	sealPrivateKey, err := base64.RawStdEncoding.DecodeString(unmarshaled.SealPrivateKey)
	if err != nil {
		return err
	}
	i.sealPrivateKey = &[32]byte{}
	copy(i.sealPrivateKey[:], sealPrivateKey[:32])

	return nil
}
