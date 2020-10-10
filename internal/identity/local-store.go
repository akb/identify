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
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/boltdb/bolt"
	"github.com/google/uuid"
)

type Store interface {
	NewIdentity(string, []string) (PublicIdentity, PrivateIdentity, error)
	GetIdentity(string) (PublicIdentity, error)
	PutSecret(PublicIdentity, string, string) error
	GetSecret(PrivateIdentity, string) (string, error)
	Close()
}

var (
	aliasBucketKey    = []byte("alias")
	identityBucketKey = []byte("identity")
	secretBucketKey   = []byte("secret")
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

func (s *localStore) NewIdentity(passphrase string, aliases []string) (PublicIdentity, PrivateIdentity, error) {
	public, private, err := NewIdentity(passphrase, aliases)
	if err != nil {
		return nil, nil, err
	}

	marshaled, err := json.Marshal(public)
	if err != nil {
		return nil, nil, err
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(identityBucketKey)
		if err != nil {
			return err
		}

		err = b.Put([]byte(public.String()), marshaled)
		if err != nil {
			return err
		}

		ab, err := tx.CreateBucketIfNotExists(aliasBucketKey)
		if err != nil {
			return err
		}

		var msg string
		if len(aliases) == 0 || len(aliases[0]) == 0 {
			msg = fmt.Sprintf("created new identity: %s\n", public.String())
		} else {
			msg = fmt.Sprintf("created new identity: %s, a.k.a. ", public.String())
			for i, a := range aliases {
				if i+1 == len(aliases) {
					msg = fmt.Sprintf("%s%s", msg, a)
				} else {
					msg = fmt.Sprintf("%s%s, ", msg, a)
				}
				err = ab.Put([]byte(a), []byte(public.String()))
			}
		}

		log.Print(msg)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return public, private, nil
}

func (s *localStore) GetIdentity(id string) (PublicIdentity, error) {
	var identity publicIdentity
	err := s.db.View(func(tx *bolt.Tx) error {
		_, err := uuid.Parse(id)
		if err != nil {
			ab := tx.Bucket(aliasBucketKey)
			if ab == nil {
				return fmt.Errorf("alias bucket doesn't exist")
			}
			aliasID := ab.Get([]byte(id))
			if aliasID == nil {
				return fmt.Errorf("unknown alias")
			}
			id = string(aliasID)
		}

		b := tx.Bucket(identityBucketKey)
		if b == nil {
			return fmt.Errorf("identity bucket doesn't exist")
		}

		unparsed := b.Get([]byte(id))
		if unparsed == nil {
			return fmt.Errorf("could not find identity for id %s", id)
		}

		return json.Unmarshal(unparsed, &identity)
	})
	if err != nil {
		return nil, err
	}

	return &identity, nil
}

func (s *localStore) PutSecret(i PublicIdentity, key, value string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(secretBucketKey)
		if err != nil {
			return err
		}
		sealed, err := i.SealAnonymous(value)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), sealed)
	})
}

func (s *localStore) GetSecret(i PrivateIdentity, key string) (string, error) {
	var value string
	if err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(secretBucketKey)
		if b == nil {
			return fmt.Errorf("secret bucket doesn't exist")
		}

		sealed := b.Get([]byte(key))
		if sealed == nil {
			return fmt.Errorf("secret for key doesn't exist")
		}

		var err error
		value, err = i.OpenAnonymous(sealed)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return "", err
	}
	return value, nil
}
