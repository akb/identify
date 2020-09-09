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
	"crypto/tls"
	"fmt"
	"html/template"
	"log"
	"mime"
	"net/http"
	"strings"

	"github.com/justinas/nosurf"
	"github.com/unrolled/logger"

	"github.com/akb/identify/internal/identity"
	"github.com/akb/identify/internal/token"
)

type Config struct {
	ServerName string
	Address    string

	IdentityStore identity.Store
	TokenStore    token.Store
}

func NewServer(c *Config) (*http.Server, error) {
	template, err := template.ParseGlob("web/templates/*")
	if err != nil {
		return nil, err
	}

	h := handler{http.NewServeMux(), template, c.IdentityStore, c.TokenStore}
	h.Handle("/", http.HandlerFunc(h.identify))
	h.Handle("/new", http.HandlerFunc(h.new))

	// TODO: make this debug-only
	csrfHandler := nosurf.New(h)
	csrfHandler.SetFailureHandler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			message := fmt.Sprintln("<h1>Bad Request</h1>") +
				fmt.Sprintf("<p>%s</p>", nosurf.Reason(r).Error())
			http.Error(w, message, 400)
		}),
	)

	log.Printf("created new identify server: %s\n", c.ServerName)
	return &http.Server{
		Addr:      c.Address,
		Handler:   logger.New().Handler(csrfHandler),
		TLSConfig: &tls.Config{ServerName: c.ServerName},
	}, nil
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
