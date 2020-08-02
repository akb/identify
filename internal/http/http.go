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

package http

import (
	"mime"
	"net/http"
	"strings"

	"github.com/akb/identify/internal/http/auth"
	"github.com/akb/identify/internal/identity"
	//"github.com/akb/identify/internal/token"
)

type ServerConfig struct {
	Addr  string
	Realm string

	IdentityStore identity.Store
	//TokenStore    token.Store
}

type api struct {
	ServerConfig

	auth auth.Provider
}

func NewServer(c ServerConfig) *http.Server {
	return &http.Server{
		Addr:    c.Addr,
		Handler: api{c, auth.Provider{c.Realm, c.IdentityStore}}, //, c.TokenStore}},
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

		//} else if r.URL.Path == "/token" {
		//	if r.Method == http.MethodPost {
		//		a.auth.RequireBasicAuth(http.HandlerFunc(a.newToken)).ServeHTTP(w, r)
		//		//} else if r.Method == http.MethodDelete {
		//		//	a.auth.RequireTokenAuth(http.HandlerFunc(a.deleteToken)).ServeHTTP(w, r)
		//	} else {
		//		w.Header().Set("Allow", "POST") //, DELETE")
		//		http.Error(w,
		//			"Only POST requests are allowed for this endpoint.",
		//			http.StatusMethodNotAllowed)
		//		return
		//	}
	} else {
		http.NotFound(w, r)
	}
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
