package certificate

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"github.com/akb/identify/internal/identity"
)

func Generate(i identity.PrivateIdentity, certificatePath, certificateKeyPath string) error {
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
		return err
	}

	keyFile, err := os.Create(certificateKeyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	keyBlock := pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}
	if err := pem.Encode(keyFile, &keyBlock); err != nil {
		return err
	}

	certificate, err := x509.CreateCertificate(
		rand.Reader, &template, &template, i.ECDSAPublicKey(), i.ECDSAPrivateKey())
	if err != nil {
		return err
	}

	certFile, err := os.Create(certificatePath)
	if err != nil {
		return err
	}
	defer certFile.Close()

	certBlock := pem.Block{Type: "CERTIFICATE", Bytes: certificate}
	if err := pem.Encode(certFile, &certBlock); err != nil {
		return err
	}

	return nil
}
