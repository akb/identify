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
	"net/url"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v5"
	"github.com/google/uuid"
)

func TestNewIdentityForm(t *testing.T) {
	tc := NewTestClient(t)

	newIdentityForm, err := tc.FetchNewIdentityForm()
	if err != nil {
		t.Fatal(err)
	}

	passphrase := gofakeit.Password(true, true, true, true, true, 24)

	_, err = newIdentityForm.Submit(passphrase)
	if err != nil {
		t.Fatal(err)
	}
}

func (tc *testClient) CreateNewIdentity(passphrase string) (string, error) {
	form, err := tc.FetchNewIdentityForm()
	if err != nil {
		return "", err
	}

	result, err := form.Submit(passphrase)
	if err != nil {
		return "", err
	}

	return result.GetID(), nil
}

type newIdentityForm struct {
	*goquery.Document
	tc *testClient
}

func (tc *testClient) FetchNewIdentityForm() (*newIdentityForm, error) {
	document, err := tc.Fetch("https://localhost:8443/identities/new")
	if err != nil {
		return nil, err
	}

	formElement := document.Find("form")
	if formElement.Length() != 1 {
		return nil, fmt.Errorf("expected GET /identities/new to respond with a form")
	}

	method, _ := formElement.Attr("method")
	if method != "POST" {
		return nil, fmt.Errorf("expected GET /identities/new to respond with a form with a method of POST")
	}

	action, _ := formElement.Attr("action")
	if action != "/identities" {
		return nil, fmt.Errorf("expected GET /identities/new to respond with a form with an action of /identities")
	}

	if document.Find("[name=passphrase]").Length() != 1 {
		return nil, fmt.Errorf("expected /identities/new to contain a field named 'passphrase'")
	}

	if document.Find("[type=submit]").Length() < 1 {
		return nil, fmt.Errorf("expected GET /identities/new to respond with a form that can be submitted")
	}

	_, exists := document.Find("[name=csrf_token]").Attr("value")
	if !exists {
		return nil, fmt.Errorf("expected GET /identities/new to respond with a form that includes a CSRF token")
	}

	return &newIdentityForm{document, tc}, nil
}

func (f *newIdentityForm) GetCSRFToken() (string, error) {
	csrfToken, exists := f.Find("[name=csrf_token]").Attr("value")
	if !exists {
		return "", fmt.Errorf("could not find csrf token in new-identity form")
	}

	return csrfToken, nil
}

func (f *newIdentityForm) Submit(passphrase string) (*NewIdentityResult, error) {
	csrfToken, err := f.GetCSRFToken()
	if err != nil {
		return nil, err
	}

	document, err := f.tc.Submit("https://localhost:8443/identities", url.Values{
		"csrf_token": []string{csrfToken},
		"passphrase": []string{passphrase},
	})
	if err != nil {
		return nil, err
	}

	result := NewIdentityResult{document}

	_, err = uuid.Parse(result.GetID())
	if err != nil {
		return nil, err
	}

	return &result, nil
}

type NewIdentityResult struct {
	*goquery.Document
}

func (r *NewIdentityResult) GetID() string {
	return r.Find("[data-testid=id]").First().Text()
}
