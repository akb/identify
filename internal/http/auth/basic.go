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

package auth

import (
	"context"
	"net/http"
)

func (p Provider) RequireBasicAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, passphrase, ok := r.BasicAuth()
		if !ok {
			p.unauthorizedBasic(w)
			return
		}

		public, err := p.IdentityStore.Get(id)
		if err != nil {
			p.unauthorizedBasic(w)
			return
		}

		private, err := public.Authenticate(passphrase)
		if err != nil {
			p.unauthorizedBasic(w)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), identityContextKey, private))
		h.ServeHTTP(w, r)
	})
}

func (p Provider) unauthorizedBasic(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+p.Realm+`"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
