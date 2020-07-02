// "identity" authentication and authorization service
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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"time"

	"github.com/boltdb/bolt"
	"github.com/google/uuid"
)

var (
	identityBucket = []byte("identity")
)

type localIdentity struct {
	ID   string `json:"id"`
	Salt string `json:"salt"`
	Key  []byte `json:"key"`
}

func (l localIdentity) Authenticate(key string) bool {
	hash := sha256.New()
	hash.Write([]byte(l.ID))
	hash.Write([]byte(l.Salt))
	return subtle.ConstantTimeCompare(l.Key, hash.Sum([]byte(key))) == 1
}

func (l localIdentity) String() string {
	return l.ID
}

type localStore struct {
	db *bolt.DB
}

func NewLocalStore(dbPath string) (*localStore, error) {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	return &localStore{db}, nil
}

func (s *localStore) Close() {
	s.db.Close()
}

func (s *localStore) New(key string) (Identity, error) {
	var err error

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	salt, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	hash := sha256.New()
	hash.Write([]byte(id.String()))
	hash.Write([]byte(salt.String()))

	identity := localIdentity{
		ID:   id.String(),
		Salt: salt.String(),
		Key:  hash.Sum([]byte(key)),
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(identityBucket)
		if err != nil {
			return err
		}

		encoded, err := json.Marshal(identity)
		if err != nil {
			return err
		}

		return b.Put([]byte(identity.ID), encoded)
	})

	if err != nil {
		return nil, err
	}

	return &identity, nil
}

func (s *localStore) Get(id string) (Identity, error) {
	_, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}

	var identity localIdentity
	if err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(identityBucket)
		if b == nil {
			return nil
		}

		unparsed := b.Get([]byte(id))
		if unparsed == nil {
			return nil
		}

		return json.Unmarshal(unparsed, &identity)
	}); err != nil {
		return nil, err
	}

	if identity.Key == nil {
		return nil, nil
	}

	return &identity, nil
}
