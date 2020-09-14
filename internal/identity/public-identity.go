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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/google/uuid"
)

type PublicIdentity interface {
	ECDSAPublicKey() *ecdsa.PublicKey
	Ed25519PublicKey() ed25519.PublicKey
	SealPublicKey() [32]byte

	String() string

	Authenticate(passphrase string) (PrivateIdentity, error)
	SealAnonymous(value string) ([]byte, error)
}

type publicIdentity struct {
	id               uuid.UUID
	ecdsaPublicKey   *ecdsa.PublicKey
	ed25519PublicKey *ed25519.PublicKey
	sealPublicKey    *[32]byte
	private          []byte
}

type jsonPublicIdentity struct {
	ID               string `json:"id"`
	ECDSAPublicKey   string `json:"ecdsa-public-key"`
	Ed25519PublicKey string `json:"ed25519-public-key"`
	SealPublicKey    string `json:"seal-public-key"`
	Private          string `json:"private"`
}

func NewIdentity(passphrase string) (*publicIdentity, *privateIdentity, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, nil, err
	}

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ecdsaPublicKey, ok := ecdsaPrivateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		panic("ecdsa private key did not produce a valid public key")
	}

	ed25519PublicKey, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	sealPublicKey, sealPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	public := publicIdentity{
		id:               id,
		ecdsaPublicKey:   ecdsaPublicKey,
		ed25519PublicKey: &ed25519PublicKey,
		sealPublicKey:    sealPublicKey,
		private:          nil,
	}

	private := privateIdentity{
		public:            &public,
		ecdsaPrivateKey:   ecdsaPrivateKey,
		ed25519PrivateKey: &ed25519PrivateKey,
		sealPrivateKey:    sealPrivateKey,
	}

	marshaled, err := json.Marshal(private)
	if err != nil {
		return nil, nil, err
	}

	var nonce [24]byte
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, nil, err
	}

	key := sha256.Sum256([]byte(passphrase))

	public.private = secretbox.Seal(nonce[:], marshaled, &nonce, &key)

	return &public, &private, nil
}

func (i publicIdentity) String() string {
	return i.id.String()
}

func (i publicIdentity) SealPublicKey() [32]byte {
	return *i.sealPublicKey
}

func (i publicIdentity) Ed25519PublicKey() ed25519.PublicKey {
	return *i.ed25519PublicKey
}

func (i publicIdentity) ECDSAPublicKey() *ecdsa.PublicKey {
	return i.ecdsaPublicKey
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
	marshaledECDSAPublicKey, err := x509.MarshalPKIXPublicKey(i.ecdsaPublicKey)
	if err != nil {
		return nil, err
	}

	return json.Marshal(jsonPublicIdentity{
		ID: i.id.String(),

		ECDSAPublicKey:   EncodeToString(marshaledECDSAPublicKey),
		Ed25519PublicKey: EncodeToString([]byte(*i.ed25519PublicKey)),
		SealPublicKey:    EncodeToString(i.sealPublicKey[:]),

		Private: EncodeToString(i.private),
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

	decodedECDSAPublicKey, err := DecodeString(unmarshaled.ECDSAPublicKey)
	if err != nil {
		return err
	}
	untypedECDSAPublicKey, err := x509.ParsePKIXPublicKey(decodedECDSAPublicKey)
	if err != nil {
		return err
	}
	ecdsaPublicKey, ok := untypedECDSAPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is not a valid ecdsa public key")
	}
	i.ecdsaPublicKey = ecdsaPublicKey

	decodedEd25519PublicKey, err := DecodeString(unmarshaled.Ed25519PublicKey)
	if err != nil {
		return err
	}
	ed25519PublicKey := ed25519.PublicKey(decodedEd25519PublicKey)
	i.ed25519PublicKey = &ed25519PublicKey

	sealPublicKey, err := DecodeString(unmarshaled.SealPublicKey)
	if err != nil {
		return err
	}
	i.sealPublicKey = &[32]byte{}
	copy(i.sealPublicKey[:], sealPublicKey[:32])

	private, err := DecodeString(unmarshaled.Private)
	if err != nil {
		return err
	}
	i.private = private

	return nil
}
