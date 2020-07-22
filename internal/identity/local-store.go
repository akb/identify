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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/boltdb/bolt"
	"github.com/google/uuid"
)

type Store interface {
	New(string) (PublicIdentity, PrivateIdentity, error)
	Get(string) (PublicIdentity, error)
	Close()
}

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

func (s *localStore) New(passphrase string) (PublicIdentity, PrivateIdentity, error) {
	public, private, err := NewIdentity(passphrase)
	if err != nil {
		return nil, nil, err
	}

	marshaled, err := json.Marshal(public)
	if err != nil {
		return nil, nil, err
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(identityBucket)
		if err != nil {
			return err
		}
		return b.Put([]byte(public.String()), marshaled)
	})
	if err != nil {
		return nil, nil, err
	}

	return public, private, nil
}

func (s *localStore) Get(id string) (PublicIdentity, error) {
	_, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}

	var identity publicIdentity
	if err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(identityBucket)
		if b == nil {
			return fmt.Errorf("identity bucket doesn't exist")
		}

		unparsed := b.Get([]byte(id))
		if unparsed == nil {
			return fmt.Errorf("could not find identity for id %s", id)
		}

		return json.Unmarshal(unparsed, &identity)
	}); err != nil {
		return nil, err
	}

	return &identity, nil
}
