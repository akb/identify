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

package token

import (
	"bytes"
	"fmt"
	"log"
	"time"

	"github.com/boltdb/bolt"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"

	"github.com/akb/identify/internal/identity"
)

type Store interface {
	New(identity.PrivateIdentity) (string, error)
	Delete(string, string) error
	Close()
}

var (
	tokenBucket     = []byte("token")
	accessTTLBucket = []byte("access-ttl")
	AccessMaxAge    = time.Minute * 5
)

type localStore struct {
	db   *bolt.DB
	done chan struct{}
}

func NewLocalStore(dbPath string) (*localStore, error) {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	store := localStore{db, make(chan struct{})}

	go func() {
		var timer *time.Timer = time.NewTimer(time.Minute)
		for {
			select {
			case <-store.done:
				timer.Stop()
				return
			case <-timer.C:
				store.sweep()
				timer = time.NewTimer(time.Minute)
			}
		}
	}()

	return &store, nil
}

func (s *localStore) Close() {
	s.done <- struct{}{}
	if err := s.sweep(); err != nil {
		log.Println(err)
	}
	s.db.Close()
}

func (s *localStore) New(identity identity.PrivateIdentity) (string, error) {
	id := identity.String()

	accessUUID, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	accessID := accessUUID.String()

	atExpiry := time.Now().Add(AccessMaxAge).Unix()
	at := jwt.NewWithClaims(SigningMethod, jwt.MapClaims{
		"exp":      atExpiry,
		"jti":      accessID,
		"identity": id,
	})

	err = s.db.Update(func(tx *bolt.Tx) error {
		ts := time.Now().UTC().Format(time.RFC3339Nano)

		for _, g := range []struct {
			bucket []byte
			key    string
			value  string
		}{
			{tokenBucket, accessID, id},
			{accessTTLBucket, ts, accessID},
		} {
			b, err := tx.CreateBucketIfNotExists(g.bucket)
			if err = b.Put([]byte(g.key), []byte(g.value)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	return at.SignedString(identity.Ed25519PrivateKey())
}

func (s *localStore) Delete(identity, id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(tokenBucket)
		if string(b.Get([]byte(id))) == identity {
			return b.Delete([]byte(id))
		}
		return fmt.Errorf("unauthorized")
	})
}

func (s *localStore) sweep() error {
	var atk, attk [][]byte
	var err error

	log.Println("scanning for expired tokens...")
	atk, attk, err = s.getExpiredTokens(accessTTLBucket, AccessMaxAge)
	if err != nil {
		return err
	}

	if len(atk) == 0 && len(attk) == 0 {
		return nil
	}

	log.Println("deleting expired tokens...")
	return s.db.Update(func(tx *bolt.Tx) error {
		var count int
		for _, b := range []struct {
			*bolt.Bucket
			keys [][]byte
		}{
			{tx.Bucket(tokenBucket), atk},
			{tx.Bucket(accessTTLBucket), attk},
		} {
			count += len(b.keys)
			for _, key := range b.keys {
				if err = b.Delete(key); err != nil {
					return err
				}
			}
		}
		log.Printf("deleted %d expired tokens.\n", count)
		return nil
	})
}

func (s *localStore) getExpiredTokens(
	bucket []byte, maxAge time.Duration) ([][]byte, [][]byte, error) {
	keys := [][]byte{}
	ttlKeys := [][]byte{}

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		max := []byte(time.Now().UTC().Add(-maxAge).Format(time.RFC3339Nano))
		for k, v := c.First(); k != nil && bytes.Compare(k, max) <= 0; k, v = c.Next() {
			keys = append(keys, v)
			ttlKeys = append(ttlKeys, k)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return keys, ttlKeys, nil
}
