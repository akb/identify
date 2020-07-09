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
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/boltdb/bolt"
	"github.com/google/uuid"
)

var (
	identityBucket = []byte("identity")
)

type localStore struct {
	db *bolt.DB
}

func NewLocalStore(dbPath string) (*localStore, error) {
	if _, err := os.Stat(filepath.Dir(dbPath)); os.IsNotExist(err) {
		os.Mkdir(filepath.Dir(dbPath), 0755)
	}

	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	return &localStore{db}, nil
}

func (s *localStore) Close() {
	s.db.Close()
}

func (s *localStore) New(passphrase string) (Identity, error) {
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
		ID:         id.String(),
		Salt:       salt.String(),
		Passphrase: hash.Sum([]byte(passphrase)),
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

	if identity.Passphrase == nil {
		return nil, nil
	}

	return &identity, nil
}

func (s *localStore) Authenticate(id, passphrase string) bool {
	identity, err := s.Get(id)
	if err != nil {
		return false
	}

	return !identity.Authenticate(string(passphrase))
}
