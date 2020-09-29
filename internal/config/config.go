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

package config

import (
	"fmt"
	"os"
	"path"
)

func GetHTTPAddress() string {
	address := os.Getenv("IDENTIFY_HTTP_ADDRESS")
	if len(address) == 0 {
		return "0.0.0.0:8443"
	}
	return address
}

func GetRealm() string {
	realm := os.Getenv("IDENTIFY_REALM")
	if len(realm) == 0 {
		return "localhost"
	}
	return realm
}

func GetTokenSecret() ([]byte, error) {
	tokenSecret := os.Getenv("IDENTIFY_TOKEN_SECRET")
	if len(tokenSecret) == 0 {
		return []byte{}, fmt.Errorf("An secret key to sign tokens with must be " +
			"provided by the environment variable IDENTIFY_TOKEN_SECRET.")
	}
	return []byte(tokenSecret), nil
}

func GetDBPath() (string, error) {
	dbPath := os.Getenv("IDENTIFY_DB_PATH")
	if len(dbPath) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("A path to an identity database file must be " +
				"provided by the environment variable IDENTIFY_DB_PATH.")
		}
		return path.Join(home, ".identify", "identity.db"), nil
	}
	return dbPath, nil
}

func GetTokenDBPath() (string, error) {
	tokenDBPath := os.Getenv("IDENTIFY_TOKEN_DB_PATH")
	if len(tokenDBPath) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("A path to an identity database file must be " +
				"provided by the environment variable IDENTIFY_TOKEN_DB_PATH.")
		}
		return path.Join(home, ".identify", "token.db"), nil
	}
	return tokenDBPath, nil
}

func GetCertificatePath() (string, error) {
	certificatePath := os.Getenv("IDENTIFY_CERTIFICATE_PATH")
	if len(certificatePath) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("A path to a PEM-encoded certificate file must be " +
				"provided by the environment variable IDENTIFY_CERTIFICATE_PATH.")
		}
		return path.Join(home, ".identify", "certificate.pem"), nil
	}
	return certificatePath, nil
}

func GetCertificateKeyPath() (string, error) {
	certificateKeyPath := os.Getenv("IDENTIFY_CERTIFICATE_KEY_PATH")
	if len(certificateKeyPath) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("A path to a PEM-encoded certificate key file " +
				"must be provided by the environment variable " +
				"IDENTIFY_CERTIFICATE_PATH.")
		}
		return path.Join(home, ".identify", "key.pem"), nil
	}
	return certificateKeyPath, nil
}
