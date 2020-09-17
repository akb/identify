package certificate

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

func Trust(certpath string) (*x509.CertPool, error) {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	certificate, err := ioutil.ReadFile(certpath)
	if err != nil {
		return nil, err
	}

	if ok := rootCAs.AppendCertsFromPEM(certificate); !ok {
		return nil, fmt.Errorf("failed to append certificate to root CAs")
	}

	return rootCAs, nil
}
