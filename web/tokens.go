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
	"time"

	"github.com/justinas/nosurf"

	"github.com/akb/identify/internal/token"
)

type NewTokenResponse struct {
	Token string `json:"token"`
}

func (h *handler) tokensNew(w http.ResponseWriter, r *http.Request) {
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

	if err := h.ExecuteTemplate(w, "passphrase", page); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

type NewTokenPage struct {
	*Page
	Token string
}

func (h *handler) tokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Only POST requests are allowed for this endpoint.",
			http.StatusMethodNotAllowed)
	}

	id := r.PostFormValue("id")
	passphrase := r.PostFormValue("passphrase")

	identity, err := h.IdentityStore.GetIdentity(id)
	if err != nil {
		log.Printf("error while retrieving identity: %s\n", err.Error())
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	_, err = identity.Authenticate(passphrase)
	if err != nil {
		log.Printf("error while decrypting private identity: %s\n", err.Error())
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	access, err := h.TokenStore.New(h.identity)
	if err != nil {
		log.Printf("error while creating token: %s\n", err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("new token created for user: %s\n", id)

	// TODO: this, if json is requested
	//response, err := json.Marshal(NewTokenResponse{token})
	//if err != nil {
	//	log.Printf("error while marshaling json response: %s\n", err.Error())
	//	http.Error(w, err.Error(), http.StatusInternalServerError)
	//	return
	//}

	//w.Header().Set("Content-Type", "application/json")
	//w.Write(response)

	page := &NewTokenPage{
		Page: &Page{
			Encoding:     "utf-8",
			LanguageCode: "en",
			Title:        "identify",
			CSRFToken:    nosurf.Token(r),
		},
		Token: access,
	}

	expires := time.Now().Add(token.AccessMaxAge)
	cookie := http.Cookie{
		Name:     "Authorization",
		Value:    access,
		Path:     "/",
		Expires:  expires,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	log.Print("rendering new token notification")
	if err := h.ExecuteTemplate(w, "new-token", page); err != nil {
		log.Printf("error while rendering new token page: %s\n", err.Error())
		http.Error(w, err.Error(), 500)
	}
}
