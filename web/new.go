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
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/justinas/nosurf"
)

type NewIdentityRequest struct {
	Passphrase string `json:"passphrase"`
}

type NewIdentityResponse struct {
	ID string `json:"id"`
}

func (h *handler) new(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		h.showNewIdentityForm(w, r)
	} else if r.Method == http.MethodPost {
		h.createNewIdentity(w, r)
	} else {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Only GET and POST requests are allowed for this endpoint.",
			http.StatusMethodNotAllowed)
	}
}

func (h *handler) showNewIdentityForm(w http.ResponseWriter, r *http.Request) {
	page := &Page{
		Encoding:     "utf-8",
		LanguageCode: "en",
		Title:        "identify",
		CSRFToken:    nosurf.Token(r),
	}

	log.Print("rendering new identity form")
	if err := h.ExecuteTemplate(w, "new-identity-form", page); err != nil {
		log.Printf("error while rendering new identity form: %s\n", err.Error())
		http.Error(w, err.Error(), 500)
	}
}

type NewIdentityPage struct {
	*Page
	ID string
}

func (h *handler) createNewIdentity(w http.ResponseWriter, r *http.Request) {
	log.Print("creating new identity...")
	passphrase, err := extractPassphrase(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	public, _, err := h.IdentityStore.NewIdentity(passphrase)
	if err != nil {
		log.Printf("error creating new identity: %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("new identity created: %s\n", public.String())

	// TODO: this, if JSON is requested
	// response, err := json.Marshal(NewIdentityResponse{public.String()})
	// if err != nil {
	// 	log.Printf("error marshaling json response: %s\n", err.Error())
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }
	// w.Header().Set("Content-Type", "application/json")
	// w.Write(response)

	page := &NewIdentityPage{
		Page: &Page{
			Encoding:     "utf-8",
			LanguageCode: "en",
			Title:        "identify",
			CSRFToken:    nosurf.Token(r),
		},
		ID: public.String(),
	}

	log.Print("rendering new identity notification")
	if err := h.ExecuteTemplate(w, "new-identity", page); err != nil {
		log.Printf("error while rendering new identity form: %s\n", err.Error())
		http.Error(w, err.Error(), 500)
	}
}

func extractPassphrase(w http.ResponseWriter, r *http.Request) (string, error) {
	if hasContentType(r, "application/x-www-form-urlencoded") ||
		hasContentType(r, "multipart/form-data") {
		return r.PostFormValue("passphrase"), nil

	} else if hasContentType(r, "application/json") {
		var parsed NewIdentityRequest
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&parsed); err != nil {
			return "", err
		}
		return parsed.Passphrase, nil

	} else {
		return "", fmt.Errorf("Unable to parse request body.")
	}
}
