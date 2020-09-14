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
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

var (
	DecodeString   = base64.RawStdEncoding.DecodeString
	EncodeToString = base64.RawStdEncoding.EncodeToString
)

var (
	errorCantAuthenticate = fmt.Errorf("can not authenticate a private identity")
)

type PrivateIdentity interface {
	PublicIdentity

	ECDSAPrivateKey() *ecdsa.PrivateKey
	Ed25519PrivateKey() ed25519.PrivateKey
	SealPrivateKey() [32]byte

	OpenMessage(PublicIdentity, []byte) (string, error)
	SealMessage(PublicIdentity, string) ([]byte, error)

	OpenAnonymous([]byte) (string, error)
}

type jsonPrivateIdentity struct {
	ECDSAPrivateKey   string `json:"ecdsa-private-key"`
	Ed25519PrivateKey string `json:"ed25519-private-key"`
	SealPrivateKey    string `json:"seal-private-key"`
}

type privateIdentity struct {
	public *publicIdentity

	ecdsaPrivateKey   *ecdsa.PrivateKey
	ed25519PrivateKey *ed25519.PrivateKey
	sealPrivateKey    *[32]byte
}

func (i privateIdentity) ECDSAPublicKey() *ecdsa.PublicKey {
	return i.public.ECDSAPublicKey()
}

func (i privateIdentity) Ed25519PublicKey() ed25519.PublicKey {
	return i.public.Ed25519PublicKey()
}

func (i privateIdentity) SealPublicKey() [32]byte {
	return i.public.SealPublicKey()
}

func (i privateIdentity) String() string {
	return i.public.String()
}

func (i privateIdentity) Authenticate(passphrase string) (PrivateIdentity, error) {
	return i, nil
}

func (i privateIdentity) Ed25519PrivateKey() ed25519.PrivateKey {
	return *i.ed25519PrivateKey
}

func (i privateIdentity) ECDSAPrivateKey() *ecdsa.PrivateKey {
	return i.ecdsaPrivateKey
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
	marshaledECDSAPrivateKey, err := x509.MarshalPKCS8PrivateKey(i.ecdsaPrivateKey)
	if err != nil {
		return nil, err
	}

	return json.Marshal(jsonPrivateIdentity{
		ECDSAPrivateKey:   EncodeToString(marshaledECDSAPrivateKey),
		Ed25519PrivateKey: EncodeToString([]byte(*i.ed25519PrivateKey)),
		SealPrivateKey:    EncodeToString(i.sealPrivateKey[:]),
	})
}

func (i *privateIdentity) UnmarshalJSON(marshaled []byte) error {
	var unmarshaled jsonPrivateIdentity
	if err := json.Unmarshal(marshaled, &unmarshaled); err != nil {
		return err
	}

	decodedECDSAPrivateKey, err := DecodeString(unmarshaled.ECDSAPrivateKey)
	if err != nil {
		return err
	}
	untypedECDSAPrivateKey, err := x509.ParsePKCS8PrivateKey(decodedECDSAPrivateKey)
	if err != nil {
		return err
	}
	ecdsaPrivateKey, ok := untypedECDSAPrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("key is not a valid ecdsa private key")
	}
	i.ecdsaPrivateKey = ecdsaPrivateKey

	decodedEd25519PrivateKey, err := DecodeString(unmarshaled.Ed25519PrivateKey)
	if err != nil {
		return err
	}
	ed25519PrivateKey := ed25519.PrivateKey(decodedEd25519PrivateKey)
	i.ed25519PrivateKey = &ed25519PrivateKey

	sealPrivateKey, err := DecodeString(unmarshaled.SealPrivateKey)
	if err != nil {
		return err
	}
	i.sealPrivateKey = &[32]byte{}
	copy(i.sealPrivateKey[:], sealPrivateKey[:32])

	return nil
}
