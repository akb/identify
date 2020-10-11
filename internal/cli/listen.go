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

package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/akb/go-cli"

	"github.com/akb/identify"
	"github.com/akb/identify/internal/config"
	"github.com/akb/identify/internal/identity"
	"github.com/akb/identify/internal/token"
	"github.com/akb/identify/web"
)

type ListenCommand struct{}

func (ListenCommand) Help() {
	fmt.Println("identify - authentication and authorization service")
	fmt.Println("")
	fmt.Println("Usage: identify listen")
	fmt.Println("")
	fmt.Println("Listen for HTTPS traffic")
}

func (c ListenCommand) Command(ctx context.Context, args []string, s cli.System) {
	address := config.GetHTTPAddress()
	realm := config.GetRealm()

	dbPath, err := config.GetDBPath()
	if err != nil {
		s.Fatal(err)
	}

	tokenDBPath, err := config.GetTokenDBPath()
	if err != nil {
		s.Fatal(err)
	}

	certPath, err := config.GetCertificatePath()
	if err != nil {
		s.Fatal(err)
	}

	keyPath, err := config.GetCertificateKeyPath()
	if err != nil {
		s.Fatal(err)
	}

	store, err := identity.NewLocalStore(dbPath)
	if err != nil {
		s.Fatal(err)
	}
	defer store.Close()

	tokenStore, err := token.NewLocalStore(tokenDBPath)
	if err != nil {
		s.Fatal(err)
	}
	defer tokenStore.Close()

	identity := identify.IdentityFromContext(ctx)
	if identity == nil {
		s.Fatal("Unauthorized")
	}

	handler, err := web.NewHandler(&web.Config{
		Identity:      identity,
		IdentityStore: store,
		TokenStore:    tokenStore,
	})
	if err != nil {
		s.Fatal(err)
	}

	server := &http.Server{
		Addr:      address,
		Handler:   handler,
		TLSConfig: &tls.Config{ServerName: realm},
	}

	go func() {
		s.Printf("Listening for HTTP requests on %s...\n", address)
		err = server.ListenAndServeTLS(certPath, keyPath)
		if err != nil && err != http.ErrServerClosed {
			s.Fatal(err)
		}
	}()

	<-ctx.Done()

	ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() { cancel() }()

	if err = server.Shutdown(ctxShutdown); err != nil {
		s.Fatalf("Server shutdown failed: %s\n", err)
	}
}
