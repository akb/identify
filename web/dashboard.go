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

	"github.com/dgrijalva/jwt-go"

	"github.com/justinas/nosurf"
)

type DashboardPage struct {
	*Page
	AccessToken *jwt.Token
}

func (h *handler) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Only GET requests are allowed for this endpoint.",
			http.StatusMethodNotAllowed)
	}

	log.Println("serving dashboard.")

	page := &DashboardPage{
		&Page{
			Encoding:     "utf-8",
			LanguageCode: "en",
			Title:        "identify",
			CSRFToken:    nosurf.Token(r),
		},
		TokenFromContext(r.Context()),
	}

	if err := h.ExecuteTemplate(w, "dashboard", page); err != nil {
		log.Printf("error executing template: \n%s\n", err.Error())
		http.Error(w, err.Error(), 500)
	}
}
