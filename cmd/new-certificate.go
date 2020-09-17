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

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/akb/identify/cmd/config"
	"github.com/akb/identify/internal/certificate"
)

type newCertificateCommand struct{}

func (newCertificateCommand) Help() {
	fmt.Println(`identify - authentication and authorization service

Usage: identify new certificate

Creates a new self-signed certificate and key file.

WARNING: Certificate functionality is incomplete, this presently just generates
a bogus cert to get the http server running.
`)
}

func (c newCertificateCommand) Command(ctx context.Context, args []string) int {
	i := IdentityFromContext(ctx)
	if i == nil {
		log.Fatal("unauthorized")
	}

	certificatePath, err := config.GetCertificatePath()
	if err != nil {
		log.Fatal(err)
	}

	certificateKeyPath, err := config.GetCertificateKeyPath()
	if err != nil {
		log.Fatal(err)
	}

	if _, err := os.Stat(certificatePath); !os.IsNotExist(err) {
		var confirmation string
		fmt.Printf("Certificate exists, overwrite? ")
		_, err := fmt.Scan(&confirmation)
		if err != nil {
			log.Fatal(err)
		}
		confirmation = strings.TrimSpace(confirmation)
		confirmation = strings.ToLower(confirmation)
		if confirmation[0] != 'y' {
			return 0
		}
	}

	if err := certificate.Generate(i, certificatePath, certificateKeyPath); err != nil {
		log.Fatal(err)
	}

	log.Println("WARNING: Certificates should only be used for testing")
	return 1
}
