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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/akb/identify/cmd/config"
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

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Humanity"},
		},

		NotBefore: time.Now().Add(-10 * time.Second),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,

		DNSNames: []string{"localhost"},
	}

	encodedKey, err := x509.MarshalPKCS8PrivateKey(i.ECDSAPrivateKey())
	if err != nil {
		log.Fatal(err)
	}

	keyFile, err := os.Create(certificateKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	defer keyFile.Close()

	keyBlock := pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}
	if err := pem.Encode(keyFile, &keyBlock); err != nil {
		log.Fatal(err)
	}

	certificate, err := x509.CreateCertificate(
		rand.Reader, &template, &template, i.ECDSAPublicKey(), i.ECDSAPrivateKey())
	if err != nil {
		log.Fatalf("error while creating certificate: %s\n", err.Error())
	}

	certFile, err := os.Create(certificatePath)
	if err != nil {
		log.Fatal(err)
	}
	defer certFile.Close()

	certBlock := pem.Block{Type: "CERTIFICATE", Bytes: certificate}
	if err := pem.Encode(certFile, &certBlock); err != nil {
		log.Fatal(err)
	}

	log.Println("WARNING: Certificates should only be used for testing")
	return 1
}
