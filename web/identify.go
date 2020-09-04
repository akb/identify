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
	"net/http"

	"github.com/justinas/nosurf"
)

func (h *handler) identify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Only GET requests are allowed for this endpoint.",
			http.StatusMethodNotAllowed)
		return
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
