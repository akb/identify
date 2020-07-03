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
	"context"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"strings"
)

type NewIdentityRequest struct {
	Key string `json:"key"`
}

type NewIdentityResponse struct {
	ID string `json:"id"`
}

type NewTokenResponse struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

type HTTPServerConfig struct {
	Addr  string
	Realm string

	Store      Store
	TokenStore TokenStore
}

type api struct {
	HTTPServerConfig

	auth AuthProvider
}

func NewHTTPServer(c HTTPServerConfig) *http.Server {
	return &http.Server{
		Addr:    c.Addr,
		Handler: api{c, AuthProvider{c.Realm, c.Store, c.TokenStore}},
	}
}

func (a api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "Only POST requests are allowed for this endpoint.",
				http.StatusMethodNotAllowed)
			return
		}
		a.new(w, r)

	} else if r.URL.Path == "/token" {
		if r.Method == http.MethodPost {
			a.auth.RequireBasicAuth(http.HandlerFunc(a.newToken)).ServeHTTP(w, r)
		} else if r.Method == http.MethodDelete {
			a.auth.RequireTokenAuth(http.HandlerFunc(a.deleteToken)).ServeHTTP(w, r)
		} else {
			w.Header().Set("Allow", "POST, DELETE")
			http.Error(w,
				"Only DELETE or POST requests are allowed for this endpoint.",
				http.StatusMethodNotAllowed)
			return
		}
	} else {
		http.NotFound(w, r)
	}
}

func (a api) new(w http.ResponseWriter, r *http.Request) {
	var key string

	if hasContentType(r, "application/x-www-form-urlencoded") ||
		hasContentType(r, "multipart/form-data") {
		key = r.PostFormValue("key")

	} else if hasContentType(r, "application/json") {
		var parsed NewIdentityRequest
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&parsed); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		key = parsed.Key

	} else {
		http.Error(w, "Unable to parse request body.", http.StatusUnsupportedMediaType)
		return
	}

	id, err := a.Store.New(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(NewIdentityResponse{id.String()})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func (a api) newToken(w http.ResponseWriter, r *http.Request) {
	identity, err := IdentityFromContext(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	access, refresh, err := a.TokenStore.New(identity)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(NewTokenResponse{
		Access:  access.String(),
		Refresh: refresh.String(),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func (a api) deleteToken(w http.ResponseWriter, r *http.Request) {
	token, err := TokenFromContext(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = a.TokenStore.Delete(token.Identity(), token.ID())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type AuthProvider struct {
	realm string

	store      Store
	tokenStore TokenStore
}

type contextKey string

const (
	identityContextKey = contextKey("identity")
	tokenContextKey    = contextKey("token")
)

func IdentityFromContext(ctx context.Context) (Identity, error) {
	v := ctx.Value(identityContextKey)
	if v == nil {
		return nil, fmt.Errorf("Identity not found in request context")
	}
	return v.(Identity), nil
}

func TokenFromContext(ctx context.Context) (Token, error) {
	v := ctx.Value(tokenContextKey)
	if v == nil {
		return nil, fmt.Errorf("Token not found in request context")
	}
	return v.(Token), nil
}

func (p AuthProvider) RequireBasicAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, key, ok := r.BasicAuth()
		if !ok {
			p.unauthorizedBasic(w)
			return
		}

		identity, err := p.store.Get(id)
		if err != nil {
			p.unauthorizedBasic(w)
			return
		}

		if !identity.Authenticate(key) {
			p.unauthorizedBasic(w)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), identityContextKey, identity))
		h.ServeHTTP(w, r)
	})
}

func (p AuthProvider) RequireTokenAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		splitHeader := strings.Split(authHeader, " ")
		if len(splitHeader) < 2 {
			p.unauthorizedToken(w)
			return
		}

		token, err := p.tokenStore.Parse(splitHeader[1])
		if err != nil || !token.Valid() {
			p.unauthorizedToken(w)
			return
		}

		id := token.Identity()
		if id == "" {
			p.unauthorizedToken(w)
			return
		}

		identity, err := p.store.Get(id)
		if err != nil {
			p.unauthorizedToken(w)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), identityContextKey, identity))
		h.ServeHTTP(w, r)
	})
}

func (p AuthProvider) unauthorizedBasic(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+p.realm+`"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (p AuthProvider) unauthorizedToken(w http.ResponseWriter) {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func hasContentType(r *http.Request, mimetype string) bool {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return mimetype == "application/octet-stream"
	}

	for _, v := range strings.Split(contentType, ",") {
		t, _, err := mime.ParseMediaType(v)
		if err != nil {
			break
		}
		if t == mimetype {
			return true
		}
	}
	return false
}
