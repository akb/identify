package test

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"

	"github.com/akb/identify/cmd/config"
)

var client *http.Client
var jar http.CookieJar

func init() {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	certpath, err := config.GetCertificatePath()
	if err != nil {
		panic(err)
	}

	certs, err := ioutil.ReadFile(certpath)
	if err != nil {
		log.Fatalf("Failed to append %q to RootCAs: %v", certpath, err)
	}

	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Fatal("no certs appended, using system certs only")
	}

	jar, err = cookiejar.New(&cookiejar.Options{})
	if err != nil {
		log.Fatalf("error creating cookie jar: %s", err.Error())
	}

	client = &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				RootCAs:            rootCAs,
			},
		},
	}
}

func TestCreateIdentity(t *testing.T) {
	var csrfToken string
	var cookies []*http.Cookie
	{
		response, err := client.Get("https://localhost:8443/new")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("expected 200 status code, received %d", response.StatusCode)
		}
		cookies = response.Cookies()

		document, err := goquery.NewDocumentFromReader(response.Body)
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
			t.Fatal("expected GET /new to respond with a form")
		}
		action, _ := formElement.Attr("action")
		method, _ := formElement.Attr("method")
		if method != "POST" {
			t.Fatal("expected GET /new to respond with a form with a method of POST")
		}
		if action != "/new" {
			t.Fatal("expected GET /new to respond with a form with an action of /new")
		}

		if document.Find("[type=submit]").Length() < 1 {
			t.Fatal("expected GET /new to respond with a form that can be submitted")
		}
	}

	{
		form := url.Values{
			"csrf_token": []string{csrfToken},
			"passphrase": []string{"this-will-do-for-now"},
		}.Encode()

		location := "https://localhost:8443/new"
		request, err := http.NewRequest(http.MethodPost, location, strings.NewReader(form))
		if err != nil {
			t.Fatal(err)
		}

		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		for _, c := range cookies {
			request.AddCookie(c)
		}

		response, err := client.Do(request)
		defer response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 {
			t.Errorf("expected 200 status code, received %d\n", response.StatusCode)
			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatal(string(body))
		}

		document, err := goquery.NewDocumentFromReader(response.Body)
		if err != nil {
			t.Fatal(err)
		}

		if document.Find("[data-testid=id]").Length() == 0 {
			t.Fatal("expected POST /new to respond with id of new identity")
		}
	}
}
