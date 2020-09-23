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
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v5"

	"github.com/akb/identify/internal/certificate"
	"github.com/akb/identify/internal/identity"
	"github.com/akb/identify/internal/token"
	"github.com/akb/identify/web"
)

func init() {
	gofakeit.Seed(time.Now().UnixNano())
	os.Chdir("../..")
}

type testClient struct {
	*http.Client
	identity.PrivateIdentity
}

func NewTestClient(t *testing.T) *testClient {
	dir, err := ioutil.TempDir("", "identify-testing")
	if err != nil {
		log.Printf("An error occurred while creating a temporary directory\n")
		log.Fatal(err.Error())
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	dbPath := filepath.Join(dir, "identity.db")
	tokenDBPath := filepath.Join(dir, "token.db")

	identityStore, err := identity.NewLocalStore(dbPath)
	if err != nil {
		log.Printf("An error occurred while opening identity database file: %s\n", dbPath)
		log.Fatal(err.Error())
	}
	t.Cleanup(func() { identityStore.Close() })

	tokenStore, err := token.NewLocalStore(tokenDBPath)
	if err != nil {
		log.Printf("An error occurred while opening token database file: %s\n", tokenDBPath)
		log.Fatal(err.Error())
	}
	t.Cleanup(func() { tokenStore.Close() })

	passphrase := gofakeit.Password(true, true, true, true, true, 24)

	_, private, err := identityStore.NewIdentity(passphrase)
	if err != nil {
		log.Printf("An error occurred while creating server identity:\n")
		log.Fatal(err.Error())
	}

	certificatePath := filepath.Join(dir, "certificate.pem")
	certificateKeyPath := filepath.Join(dir, "certificate.key")
	if err := certificate.Generate(private, certificatePath, certificateKeyPath); err != nil {
		log.Println("An error occurred while generating a certificate:")
		log.Fatal(err)
	}

	certs, err := certificate.Trust(certificatePath)
	if err != nil {
		log.Println("An error occurred while adding certificate to trusted pool:")
		log.Fatal(err)
	}

	handler, err := web.NewHandler(&web.Config{
		Identity:      private,
		IdentityStore: identityStore,
		TokenStore:    tokenStore,
	})
	if err != nil {
		log.Fatal(err.Error())
	}

	server := &http.Server{
		Addr:      "localhost:8443",
		Handler:   handler,
		TLSConfig: &tls.Config{ServerName: "localhost"},
	}

	go func() {
		err := server.ListenAndServeTLS(certificatePath, certificateKeyPath)
		if err != nil && err != http.ErrServerClosed {
			log.Println("server returned errror")
			log.Fatal(err)
		}
	}()

	for i := 0; i <= 50; i++ {
		if i == 50 {
			log.Fatal("server has not started after 5 seconds")
		}
		conn, err := tls.Dial("tcp", "localhost:8443", &tls.Config{RootCAs: certs})
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if err = conn.Close(); err != nil {
			log.Println("error occurred while closing conn")
			log.Fatal(err)
		}
		break
	}

	t.Cleanup(func() {
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)

		if err = server.Shutdown(ctx); err != nil {
			log.Fatal(err)
		}
	})

	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		log.Fatal(err)
	}

	return &testClient{
		&http.Client{
			Jar: jar,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: certs},
			},
		},
		private,
	}
}

func (tc *testClient) Fetch(location string) (*goquery.Document, error) {
	response, err := tc.Get(location)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("expected 200 status code, received %d", response.StatusCode)
	}

	return goquery.NewDocumentFromReader(response.Body)
}

func (tc *testClient) Submit(location string, values url.Values) (*goquery.Document, error) {
	request, err := http.NewRequest(
		http.MethodPost, location,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := tc.Do(request)
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
