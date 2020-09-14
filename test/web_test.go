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

package test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/google/uuid"

	"github.com/akb/identify/cmd/config"
)

var client *http.Client

const passphrase = "this-will-do-for-now"

func init() {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	certpath, err := config.GetCertificatePath()
	if err != nil {
		log.Fatal(err)
	}

	certs, err := ioutil.ReadFile(certpath)
	if err != nil {
		log.Fatalf("Failed to append %q to RootCAs: %v", certpath, err)
	}

	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Fatal("failed to append certificate to root CAs")
	}

	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		log.Fatal(err)
	}

	client = &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: rootCAs},
		},
	}
}

func TestCreateIdentity(t *testing.T) {
	var csrfToken string

	// get and test new-identity form
	{
		document, err := fetch("https://localhost:8443/identities/new")
		if err != nil {
			t.Fatal(err)
		}

		var exists bool
		csrfToken, exists = document.Find("[name=csrf_token]").Attr("value")
		if !exists {
			t.Fatal("could not find csrf token in new-identity form")
		}

		if document.Find("[name=passphrase]").Length() != 1 {
			t.Fatal("expected new-identity form to contain a field name 'passphrase'")
		}

		formElement := document.Find("form")
		if formElement.Length() != 1 {
			t.Fatal("expected GET /identities/new to respond with a form")
		}
		action, _ := formElement.Attr("action")
		method, _ := formElement.Attr("method")
		if method != "POST" {
			t.Fatal("expected GET /identities/new to respond with a form with a method of POST")
		}
		if action != "/new" {
			t.Fatal("expected GET /identities/new to respond with a form with an action of /identities/new")
		}

		if document.Find("[type=submit]").Length() < 1 {
			t.Fatal("expected GET /identities/new to respond with a form that can be submitted")
		}
	}

	// submit new-identity form and test
	var id string
	{
		document, err := submit("https://localhost:8443/identities", url.Values{
			"csrf_token": []string{csrfToken},
			"passphrase": []string{passphrase},
		})
		if err != nil {
			t.Fatal(err)
		}

		idElement := document.Find("[data-testid=id]")
		if idElement.Length() == 0 {
			t.Fatal("expected POST /identities/new to respond with id of new identity")
		}
		id = idElement.First().Text()
		_, err = uuid.Parse(id)
		if err != nil {
			t.Errorf("Failed to parse UUID from: %s\n", id)
			t.Fatal(err)
		}
	}

	// get new-token form and test
	{
		document, err := fetch("https://localhost:8443/tokens/new")
		if err != nil {
			t.Fatal(err)
		}

		if document.Find("[name=id]").Length() != 1 {
			t.Fatal("expected new-token form to contain a field named 'id'")
		}

		if document.Find("[name=passphrase]").Length() != 1 {
			t.Fatal("expected new-token form to contain a field named 'passphrase'")
		}

		var exists bool
		csrfToken, exists = document.Find("[name=csrf_token]").Attr("value")
		if !exists {
			t.Fatal("could not find csrf token in new-token form")
		}

		formElement := document.Find("form")
		if formElement.Length() != 1 {
			t.Fatal("expected GET /tokens/new to respond with a form")
		}
		action, _ := formElement.Attr("action")
		method, _ := formElement.Attr("method")
		if method != "POST" {
			t.Fatal("expected GET /tokens/new to respond with a form with a method of POST")
		}
		if action != "/" {
			t.Fatal("expected GET /tokens/new to respond with a form with an action of /tokens/new")
		}

		if document.Find("[type=submit]").Length() < 1 {
			t.Fatal("expected GET /tokens/new to respond with a form includes a submit button")
		}
	}

	// submit new-token form
	{
		document, err := submit("https://localhost:8443/tokens", url.Values{
			"csrf_token": []string{csrfToken},
			"id":         []string{id},
			"passphrase": []string{passphrase},
		})
		if err != nil {
			t.Fatal(err)
		}

		tokenElement := document.Find("[data-testid=token]")
		if tokenElement.Length() == 0 {
			t.Fatal("expected POST /tokens/new to respond with a token")
		}
	}

	// visit dashboard w/ token
	{
		document, err := fetch("https://localhost:8443/")
		if err != nil {
			t.Fatal(err)
		}

		tokenInfoElement := document.Find("[data-testid=dashboard]")
		if tokenInfoElement.Length() == 0 {
			t.Fatal("expected authenticated GET / to respond with dashboard")
		}
	}
}

func fetch(location string) (*goquery.Document, error) {
	response, err := client.Get(location)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("expected 200 status code, received %d", response.StatusCode)
	}

	return goquery.NewDocumentFromReader(response.Body)
}

func authenticatedFetch(location, token string) (*goquery.Document, error) {
	request, err := http.NewRequest(http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}

	if len(token) > 0 {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("expected 200 status code, received %d", response.StatusCode)
	}

	return goquery.NewDocumentFromReader(response.Body)
}

func submit(location string, values url.Values) (*goquery.Document, error) {
	request, err := http.NewRequest(
		http.MethodPost, location,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := client.Do(request)
	defer response.Body.Close()
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 {
		msg := fmt.Sprintf("expected 200 status code, received %d\n", response.StatusCode)
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%s%s", msg, body)
	}

	return goquery.NewDocumentFromReader(response.Body)
}
