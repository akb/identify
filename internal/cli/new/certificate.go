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

	"github.com/pkg/errors"

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

func (c NewCertificateCommand) Command(ctx context.Context, args []string, s cli.System) error {
	i := identify.IdentityFromContext(ctx)
	if i == nil {
		return errors.New("unauthorized")
	}

	certificatePath, err := config.GetCertificatePath(s)
	if err != nil {
		return err
	}

	certificateKeyPath, err := config.GetCertificateKeyPath(s)
	if err != nil {
		return err
	}

	if _, err := os.Stat(certificatePath); !os.IsNotExist(err) {
		var confirmation string
		s.Printf("Certificate exists, overwrite? ")
		_, err := s.Scan(&confirmation)
		if err != nil {
			return err
		}
		confirmation = strings.TrimSpace(confirmation)
		confirmation = strings.ToLower(confirmation)
		if confirmation[0] != 'y' {
			return nil
		}
	}

	if err := certificate.Generate(i, certificatePath, certificateKeyPath); err != nil {
		return err
	}

	s.Log("WARNING: Certificates should only be used for testing")

	return nil
}
