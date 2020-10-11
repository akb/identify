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

package web

import (
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"strings"

	"github.com/justinas/nosurf"
	//"github.com/unrolled/logger"

	"github.com/akb/identify/internal/identity"
	"github.com/akb/identify/internal/token"
)

type Config struct {
	Identity      identity.PrivateIdentity
	IdentityStore identity.Store
	TokenStore    token.Store
}

func NewHandler(c *Config) (http.Handler, error) {
	template, err := template.ParseGlob("web/templates/*")
	if err != nil {
		return nil, err
	}

	h := handler{
		ServeMux:      http.NewServeMux(),
		Template:      template,
		identity:      c.Identity,
		IdentityStore: c.IdentityStore,
		TokenStore:    c.TokenStore,
	}

	h.Handle("/", RequireTokenAuth(c.Identity, http.HandlerFunc(h.dashboard)))
	h.Handle("/tokens", http.HandlerFunc(h.tokens))
	h.Handle("/tokens/new", http.HandlerFunc(h.tokensNew))
	h.Handle("/identities", http.HandlerFunc(h.identities))
	h.Handle("/identities/new", http.HandlerFunc(h.identitiesNew))

	csrfHandler := nosurf.New(h)
	csrfHandler.SetFailureHandler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			message := fmt.Sprintln("<h1>Bad Request</h1>") +
				fmt.Sprintf("<p>%s</p>", nosurf.Reason(r).Error())
			http.Error(w, message, 400)
		}),
	)

	// TODO: make this debug-only
	//return logger.New().Handler(csrfHandler), nil

	return csrfHandler, nil
}

type Page struct {
	Encoding     string
	LanguageCode string
	Title        string
	CSRFToken    string
}

type handler struct {
	*http.ServeMux
	*template.Template

	identity identity.PrivateIdentity

	IdentityStore identity.Store
	TokenStore    token.Store
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
