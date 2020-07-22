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
	"encoding/json"
	"net/http"
)

type NewIdentityRequest struct {
	Key string `json:"key"`
}

type NewIdentityResponse struct {
	ID string `json:"id"`
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

	public, _, err := a.IdentityStore.New(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(NewIdentityResponse{public.String()})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}
