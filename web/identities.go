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
	"log"
	"net/http"
	"strings"

	"github.com/justinas/nosurf"
)

type NewIdentityPage struct {
	*Page
	ID string
}

type NewIdentityRequest struct {
	Alias      string `json:"alias"`
	Passphrase string `json:"passphrase"`
}

type NewIdentityResponse struct {
	ID string `json:"id"`
}

func (h *handler) identitiesNew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Only GET requests are allowed for this endpoint.",
			http.StatusMethodNotAllowed)
	}

	page := &Page{
		Encoding:     "utf-8",
		LanguageCode: "en",
		Title:        "identify",
		CSRFToken:    nosurf.Token(r),
	}

	if err := h.ExecuteTemplate(w, "new-identity-form", page); err != nil {
		log.Printf("error while rendering new identity form: %s\n", err.Error())
		http.Error(w, err.Error(), 500)
	}
}

func (h *handler) identities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Only POST requests are allowed for this endpoint.",
			http.StatusMethodNotAllowed)
	}

	if !hasContentType(r, "application/x-www-form-urlencoded") &&
		!hasContentType(r, "multipart/form-data") {
		http.Error(w, "unable to parse request body", http.StatusBadRequest)
		return
	}

	alias := r.PostFormValue("alias")
	var aliases []string
	for _, a := range strings.Split(alias, ",") {
		aliases = append(aliases, strings.TrimSpace(a))
	}

	passphrase := r.PostFormValue("passphrase")

	public, _, err := h.IdentityStore.NewIdentity(passphrase, aliases)
	if err != nil {
		log.Printf("error creating new identity: %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	page := &NewIdentityPage{
		Page: &Page{
			Encoding:     "utf-8",
			LanguageCode: "en",
			Title:        "identify",
			CSRFToken:    nosurf.Token(r),
		},
		ID: public.String(),
	}

	if err := h.ExecuteTemplate(w, "new-identity", page); err != nil {
		log.Printf("error while rendering new identity page: %s\n", err.Error())
		http.Error(w, err.Error(), 500)
	}
}
