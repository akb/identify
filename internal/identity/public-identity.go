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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	ECDSAPublicKey() (*ecdsa.PublicKey, error)

	String() string

	Authenticate(passphrase string) (PrivateIdentity, error)
	SealAnonymous(value string) ([]byte, error)
}

type publicIdentity struct {
	id uuid.UUID

	signPublicKey  *[32]byte
	sealPublicKey  *[32]byte
	ecdsaPublicKey string

	private []byte
}

type jsonPublicIdentity struct {
	ID string `json:"id"`

	SignPublicKey  string `json:"sign-public-key"`
	SealPublicKey  string `json:"seal-public-key"`
	ECDSAPublicKey string `json:"ecdsa-public-key"`

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

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	marshaledECDSAKey, err := x509.MarshalPKCS8PrivateKey(ecdsaPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	ecdsaPrivateKeyBlock := pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledECDSAKey}
	var encodedECDSAPrivateKey bytes.Buffer
	if err := pem.Encode(&encodedECDSAPrivateKey, &ecdsaPrivateKeyBlock); err != nil {
		return nil, nil, err
	}

	marshaledECDSAPublicKey, err := x509.MarshalPKIXPublicKey(ecdsaPrivateKey.Public())
	if err != nil {
		return nil, nil, err
	}

	ecdsaPublicKeyBlock := pem.Block{Type: "EC PUBLIC KEY", Bytes: marshaledECDSAPublicKey}
	var encodedECDSAPublicKey bytes.Buffer
	if err := pem.Encode(&encodedECDSAPublicKey, &ecdsaPublicKeyBlock); err != nil {
		return nil, nil, err
	}
	fmt.Printf("key: %s\n", encodedECDSAPublicKey.String())

	public := publicIdentity{
		id:             id,
		signPublicKey:  signPublicKey,
		sealPublicKey:  sealPublicKey,
		ecdsaPublicKey: encodedECDSAPublicKey.String(),
		private:        nil,
	}

	private := privateIdentity{
		public:          &public,
		signPrivateKey:  signPrivateKey,
		sealPrivateKey:  sealPrivateKey,
		ecdsaPrivateKey: encodedECDSAPrivateKey.Bytes(),
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

func (i publicIdentity) SignPublicKey() [32]byte {
	return *i.signPublicKey
}

func (i publicIdentity) SealPublicKey() [32]byte {
	return *i.sealPublicKey
}

func (i publicIdentity) ECDSAPublicKey() (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(i.ecdsaPublicKey))
	if block == nil || block.Type != "EC PUBLIC KEY" {
		// TODO: do this at creation and drop error from signature
		return nil, fmt.Errorf("unable to parse public key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse public key")
	}

	if ecdsaKey, ok := key.(*ecdsa.PublicKey); ok {
		return ecdsaKey, nil
	}

	return nil, fmt.Errorf("key is not an ecdsa public key")
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

		SignPublicKey:  base64.RawStdEncoding.EncodeToString(i.signPublicKey[:]),
		SealPublicKey:  base64.RawStdEncoding.EncodeToString(i.sealPublicKey[:]),
		ECDSAPublicKey: string(i.ecdsaPublicKey),

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

	i.ecdsaPublicKey = unmarshaled.ECDSAPublicKey

	private, err := base64.RawStdEncoding.DecodeString(unmarshaled.Private)
	if err != nil {
		return err
	}
	i.private = private

	return nil
}
