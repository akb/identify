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

package newcmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/akb/go-cli"

	"github.com/akb/identify"
	"github.com/akb/identify/internal/certificate"
	"github.com/akb/identify/internal/config"
)

type NewCertificateCommand struct{}

func (NewCertificateCommand) Help() {
	fmt.Println(`identify - authentication and authorization service

Usage: identify new certificate

Creates a new self-signed certificate and key file.

WARNING: Certificate functionality is incomplete, this presently just generates
a bogus cert to get the http server running.
`)
}

func (c NewCertificateCommand) Command(ctx context.Context, args []string, s cli.System) int {
	i := identify.IdentityFromContext(ctx)
	if i == nil {
		s.Fatal("unauthorized")
	}

	certificatePath, err := config.GetCertificatePath()
	if err != nil {
		s.Fatal(err)
	}

	certificateKeyPath, err := config.GetCertificateKeyPath()
	if err != nil {
		s.Fatal(err)
	}

	if _, err := os.Stat(certificatePath); !os.IsNotExist(err) {
		var confirmation string
		s.Printf("Certificate exists, overwrite? ")
		_, err := s.Scan(&confirmation)
		if err != nil {
			s.Fatal(err)
		}
		confirmation = strings.TrimSpace(confirmation)
		confirmation = strings.ToLower(confirmation)
		if confirmation[0] != 'y' {
			return 0
		}
	}

	if err := certificate.Generate(i, certificatePath, certificateKeyPath); err != nil {
		s.Fatal(err)
	}

	s.Println("WARNING: Certificates should only be used for testing")
	return 0
}
