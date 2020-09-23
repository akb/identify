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
	"testing"

	"github.com/PuerkitoBio/goquery"
)

type Dashboard struct {
	*goquery.Document
}

func FetchDashboard(t *testing.T) *Dashboard {
	tc := NewTestClient(t)

	document, err := tc.Fetch("https://localhost:8443/")
	if err != nil {
		t.Fatal(err)
	}
	return &Dashboard{document}
}

func (d *Dashboard) Test(t *testing.T) {
	tokenInfoElement := d.Find("[data-testid=dashboard]")
	if tokenInfoElement.Length() == 0 {
		t.Fatal("expected authenticated GET / to respond with dashboard")
	}
}
