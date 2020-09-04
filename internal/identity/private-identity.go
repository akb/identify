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
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

	ECDSAPrivateKey() (*ecdsa.PrivateKey, error)

	OpenMessage(PublicIdentity, []byte) (string, error)
	SealMessage(PublicIdentity, string) ([]byte, error)

	OpenAnonymous([]byte) (string, error)
}

type jsonPrivateIdentity struct {
	SignPrivateKey  string `json:"sign-private-key"`
	SealPrivateKey  string `json:"seal-private-key"`
	ECDSAPrivateKey string `json:"ecdsa-private-key"`
}

type privateIdentity struct {
	public *publicIdentity

	signPrivateKey  *[64]byte
	sealPrivateKey  *[32]byte
	ecdsaPrivateKey []byte
}

func (i privateIdentity) SignPublicKey() [32]byte {
	return i.public.SignPublicKey()
}

func (i privateIdentity) SealPublicKey() [32]byte {
	return i.public.SealPublicKey()
}

func (i privateIdentity) ECDSAPublicKey() (*ecdsa.PublicKey, error) {
	return i.public.ECDSAPublicKey()
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

func (i privateIdentity) ECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(i.ecdsaPrivateKey)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		// TODO: do this at creation and drop error from signature
		return nil, fmt.Errorf("unable to parse private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key")
	}

	if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
		return ecdsaKey, nil
	}

	return nil, fmt.Errorf("key is not an ecdsa private key")
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

func (i privateIdentity) OpenAnonymous(sealed []byte) (string, error) {
	unsealed, ok := box.OpenAnonymous(nil, sealed, i.public.sealPublicKey, i.sealPrivateKey)
	if !ok {
		return "", fmt.Errorf("key doesn't fit")
	}
	return string(unsealed), nil
}

func (i privateIdentity) SealAnonymous(value string) ([]byte, error) {
	return i.public.SealAnonymous(value)
}

func (i privateIdentity) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonPrivateIdentity{
		SignPrivateKey:  base64.RawStdEncoding.EncodeToString(i.signPrivateKey[:]),
		SealPrivateKey:  base64.RawStdEncoding.EncodeToString(i.sealPrivateKey[:]),
		ECDSAPrivateKey: base64.RawStdEncoding.EncodeToString(i.ecdsaPrivateKey),
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

	ecdsaPrivateKey, err := base64.RawStdEncoding.DecodeString(unmarshaled.ECDSAPrivateKey)
	if err != nil {
		return err
	}
	i.ecdsaPrivateKey = ecdsaPrivateKey

	return nil
}
