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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/nacl/sign"

	"github.com/google/uuid"
)

type PublicIdentity interface {
	SignPublicKey() [32]byte
	SealPublicKey() [32]byte

	String() string

	Authenticate(passphrase string) (PrivateIdentity, error)
	SealAnonymous(value string) ([]byte, error)
}

type publicIdentity struct {
	id uuid.UUID

	signPublicKey *[32]byte
	sealPublicKey *[32]byte

	private []byte
}

type jsonPublicIdentity struct {
	ID string `json:"id"`

	SignPublicKey string `json:"sign-public-key"`
	SealPublicKey string `json:"seal-public-key"`

	Private string `json:"private"`
}

func NewIdentity(passphrase string) (*publicIdentity, *privateIdentity, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, nil, err
	}

	signPublicKey, signPrivateKey, err := sign.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	sealPublicKey, sealPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	public := publicIdentity{id, signPublicKey, sealPublicKey, nil}
	private := privateIdentity{&public, signPrivateKey, sealPrivateKey}

	marshaled, err := json.Marshal(private)
	if err != nil {
		return nil, nil, err
	}

	var nonce [24]byte
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, nil, err
	}

	key := sha256.Sum256([]byte(passphrase))

	private.public = &public
	public.private = secretbox.Seal(nonce[:], marshaled, &nonce, &key)

	return &public, &private, nil
}

func (i publicIdentity) String() string {
	return i.id.String()
}

func (i publicIdentity) SignPublicKey() [32]byte {
	return *i.signPublicKey
}

func (i publicIdentity) SealPublicKey() [32]byte {
	return *i.sealPublicKey
}

func (i *publicIdentity) Authenticate(passphrase string) (PrivateIdentity, error) {
	key := sha256.Sum256([]byte(passphrase))

	var nonce [24]byte
	copy(nonce[:], i.private[:24])
	unparsed, ok := secretbox.Open(nil, i.private[24:], &nonce, &key)
	if !ok {
		return nil, fmt.Errorf("unable to decrypt identity")
	}

	var identity privateIdentity
	err := json.Unmarshal(unparsed, &identity)
	identity.public = i
	return &identity, err
}

func (i *publicIdentity) SealAnonymous(value string) ([]byte, error) {
	return box.SealAnonymous(nil, []byte(value), i.sealPublicKey, rand.Reader)
}

func (i publicIdentity) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonPublicIdentity{
		ID: i.id.String(),

		SignPublicKey: base64.RawStdEncoding.EncodeToString(i.signPublicKey[:]),
		SealPublicKey: base64.RawStdEncoding.EncodeToString(i.sealPublicKey[:]),

		Private: base64.RawStdEncoding.EncodeToString(i.private),
	})
}

func (i *publicIdentity) UnmarshalJSON(marshaled []byte) error {
	var unmarshaled jsonPublicIdentity
	if err := json.Unmarshal(marshaled, &unmarshaled); err != nil {
		return err
	}

	id, err := uuid.Parse(unmarshaled.ID)
	if err != nil {
		return err
	}

	i.id = id

	i.signPublicKey = &[32]byte{}
	signPublicKey, err := base64.RawStdEncoding.DecodeString(unmarshaled.SignPublicKey)
	if err != nil {
		return err
	}
	copy(i.signPublicKey[:], signPublicKey[:32])

	sealPublicKey, err := base64.RawStdEncoding.DecodeString(unmarshaled.SealPublicKey)
	if err != nil {
		return err
	}
	i.sealPublicKey = &[32]byte{}
	copy(i.sealPublicKey[:], sealPublicKey[:32])

	private, err := base64.RawStdEncoding.DecodeString(unmarshaled.Private)
	if err != nil {
		return err
	}
	i.private = private

	return nil
}
