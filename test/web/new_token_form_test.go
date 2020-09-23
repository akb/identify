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
	"github.com/dgrijalva/jwt-go"

	"github.com/akb/identify/internal/token"
)

func TestNewTokenFormWithID(t *testing.T) {
	tc := NewTestClient(t)

	passphrase := gofakeit.Password(true, true, true, true, true, 24)

	id, err := tc.CreateNewIdentity("", passphrase)
	if err != nil {
		t.Fatal(err)
	}

	newTokenForm, err := tc.FetchNewTokenForm()
	if err != nil {
		t.Fatal(err)
	}

	newTokenResult, err := newTokenForm.Submit(id, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	tokenString, err := newTokenResult.GetToken()
	if err != nil {
		t.Fatal(err)
	}

	_, err = jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*token.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
		}

		return tc.Ed25519PublicKey(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewTokenFormWithAlias(t *testing.T) {
	tc := NewTestClient(t)

	alias := gofakeit.Username()
	passphrase := gofakeit.Password(true, true, true, true, true, 24)

	_, err := tc.CreateNewIdentity(alias, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	newTokenForm, err := tc.FetchNewTokenForm()
	if err != nil {
		t.Fatal(err)
	}

	newTokenResult, err := newTokenForm.Submit(alias, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	tokenString, err := newTokenResult.GetToken()
	if err != nil {
		t.Fatal(err)
	}

	_, err = jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*token.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
		}

		return tc.Ed25519PublicKey(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type NewTokenForm struct {
	*goquery.Document
	tc *testClient
}

func (tc *testClient) FetchNewTokenForm() (*NewTokenForm, error) {
	document, err := tc.Fetch("https://localhost:8443/tokens/new")
	if err != nil {
		return nil, err
	}
	return &NewTokenForm{document, tc}, nil
}

func (f *NewTokenForm) Test(t *testing.T) {
	if f.Find("[name=id]").Length() != 1 {
		t.Fatal("expected new-token form to contain a field named 'id'")
	}

	if f.Find("[name=passphrase]").Length() != 1 {
		t.Fatal("expected new-token form to contain a field named 'passphrase'")
	}

	formElement := f.Find("form")
	if formElement.Length() != 1 {
		t.Fatal("expected GET /tokens/new to respond with a form")
	}
	action, _ := formElement.Attr("action")
	method, _ := formElement.Attr("method")
	if method != "POST" {
		t.Fatal("expected GET /tokens/new to respond with a form with a method of POST")
	}
	if action != "/tokens" {
		t.Fatal("expected GET /tokens/new to respond with a form with an action of /tokens")
	}

	if f.Find("[type=submit]").Length() < 1 {
		t.Fatal("expected GET /tokens/new to respond with a form that includes a submit button")
	}

	_, exists := f.Find("[name=csrf_token]").Attr("value")
	if !exists {
		t.Fatal("expected GET /tokens/new to respond with a form that includes a CSRF token")
	}
}

func (f *NewTokenForm) GetCSRFToken() (string, error) {
	csrfToken, exists := f.Find("[name=csrf_token]").Attr("value")
	if !exists {
		return "", fmt.Errorf("could not find csrf token in new-token form")
	}

	return csrfToken, nil
}

func (f *NewTokenForm) Submit(id, passphrase string) (*NewTokenResult, error) {
	csrfToken, err := f.GetCSRFToken()
	if err != nil {
		return nil, err
	}

	document, err := f.tc.Submit("https://localhost:8443/tokens", url.Values{
		"csrf_token": []string{csrfToken},
		"id":         []string{id},
		"passphrase": []string{passphrase},
	})
	if err != nil {
		return nil, err
	}

	return &NewTokenResult{document}, nil
}

type NewTokenResult struct {
	*goquery.Document
}

func (r *NewTokenResult) GetToken() (string, error) {
	tokenElement := r.Find("[data-testid=token]")
	if tokenElement.Length() == 0 {
		return "", fmt.Errorf("new-token result does not contain a token")
	}
	return tokenElement.First().Text(), nil
}
