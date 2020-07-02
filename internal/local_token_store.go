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
	"bytes"
	"fmt"
	"time"

	"github.com/boltdb/bolt"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

var (
	accessTokenBucket     = []byte("access-token")
	accessTokenTTLBucket  = []byte("access-token-ttl")
	refreshTokenBucket    = []byte("refresh-token")
	refreshTokenTTLBucket = []byte("refresh-token-ttl")
	accessMaxAge          = time.Second * 15
	refreshMaxAge         = time.Hour * 24 * 7
)

type jwToken struct {
	*jwt.Token
}

func (t *jwToken) GetClaim(key string) (string, error) {
	claims, ok := t.Token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("Unable to read claims from Token")
	}

	value, ok := claims[key].(string)
	if !ok {
		return "", fmt.Errorf("Unable to read \"%s\" claim from Token", key)
	}

	return value, nil
}

func (t *jwToken) ID() (string, error) {
	return t.GetClaim("jti")
}

func (t *jwToken) Identity() (string, error) {
	return t.GetClaim("identity")
}

func (t *jwToken) Valid() bool {
	return t.Token.Valid
}

type localTokenStore struct {
	db     *bolt.DB
	secret string
	done   chan struct{}
}

func NewLocalTokenStore(dbPath, secret string) (*localTokenStore, error) {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	store := localTokenStore{db, secret, make(chan struct{})}

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

func (s *localTokenStore) Close() {
	s.done <- struct{}{}
	s.sweep() // TODO: handle error
	s.db.Close()
}

func (s *localTokenStore) Parse(unparsed string) (Token, error) {
	token, err := jwt.Parse(unparsed, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signature algorithm: %v", token.Header["alg"])
		}
		return []byte(s.secret), nil
	})
	if err != nil {
		return nil, err
	}
	return &jwToken{token}, nil
}

func (s *localTokenStore) New(identity Identity) (string, string, error) {
	id := identity.String()

	accessUUID, err := uuid.NewRandom()
	if err != nil {
		return "", "", err
	}

	refreshUUID, err := uuid.NewRandom()
	if err != nil {
		return "", "", err
	}

	accessID := accessUUID.String()
	refreshID := refreshUUID.String()

	atExpiry := time.Now().Add(accessMaxAge).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp":      atExpiry,
		"jti":      accessID,
		"identity": id,
	})

	rtExpiry := time.Now().Add(refreshMaxAge).Unix()
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp":      rtExpiry,
		"jti":      refreshID,
		"identity": id,
	})

	if err := s.db.Update(func(tx *bolt.Tx) error {
		ts := time.Now().UTC().Format(time.RFC3339Nano)

		for _, g := range []struct {
			bucket []byte
			key    string
			value  string
		}{
			{accessTokenBucket, accessID, id},
			{accessTokenTTLBucket, ts, accessID},
			{refreshTokenBucket, refreshID, id},
			{refreshTokenTTLBucket, ts, refreshID},
		} {
			b, err := tx.CreateBucketIfNotExists(g.bucket)
			if err = b.Put([]byte(g.key), []byte(g.value)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return "", "", err
	}

	access, err := at.SignedString([]byte(s.secret))
	if err != nil {
		return "", "", err
	}

	refresh, err := rt.SignedString([]byte(s.secret))
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}

func (s *localTokenStore) sweep() error {
	var atk, attk, rtk, rttk [][]byte
	var err error

	atk, attk, err = s.getExpiredTokens(accessTokenTTLBucket, accessMaxAge)
	if err != nil {
		return err
	}

	rtk, rttk, err = s.getExpiredTokens(refreshTokenTTLBucket, refreshMaxAge)
	if err != nil {
		return err
	}

	if len(atk) == 0 && len(attk) == 0 && len(rtk) == 0 && len(rttk) == 0 {
		return nil
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range []struct {
			*bolt.Bucket
			keys [][]byte
		}{
			{tx.Bucket(accessTokenBucket), atk},
			{tx.Bucket(accessTokenTTLBucket), attk},
			{tx.Bucket(refreshTokenBucket), rtk},
			{tx.Bucket(refreshTokenTTLBucket), rttk},
		} {
			for _, key := range b.keys {
				if err = b.Delete(key); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (s *localTokenStore) getExpiredTokens(
	bucket []byte, maxAge time.Duration) ([][]byte, [][]byte, error) {
	keys := [][]byte{}
	ttlKeys := [][]byte{}

	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucket).Cursor()
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
