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
	"context"
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v5"

	"github.com/akb/identify/internal/certificate"
	"github.com/akb/identify/internal/identity"
	"github.com/akb/identify/internal/token"
	"github.com/akb/identify/web"
)

var client *http.Client

func init() {
	gofakeit.Seed(time.Now().UnixNano())
}

func TestMain(m *testing.M) {
	os.Chdir("../..")

	dir, err := ioutil.TempDir("", "identify-testing")
	if err != nil {
		log.Printf("An error occurred while creating a temporary directory\n")
		log.Fatal(err.Error())
	}

	dbPath := filepath.Join(dir, "identity.db")
	tokenDBPath := filepath.Join(dir, "token.db")

	identityStore, err := identity.NewLocalStore(dbPath)
	if err != nil {
		log.Printf("An error occurred while opening identity database file: %s\n", dbPath)
		log.Fatal(err.Error())
	}

	tokenStore, err := token.NewLocalStore(tokenDBPath)
	if err != nil {
		log.Printf("An error occurred while opening token database file: %s\n", tokenDBPath)
		log.Fatal(err.Error())
	}

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

	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		log.Fatal(err)
	}

	client = &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certs},
		},
	}

	status := m.Run()

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)

	if err = server.Shutdown(ctx); err != nil {
		log.Fatal(err)
	}

	tokenStore.Close()
	identityStore.Close()

	os.RemoveAll(dir)

	os.Exit(status)
}
