identity
========

Identity and authentication service. Identity provides a secure interface for
authenticating one's identity and provides token-based authorization for other
services.

This project is in its infancy, feel free to submit issues but I'm not quite
ready for pull requests. Use at your own risk, this code is far from being
production ready.

## Building

    go build -o bin/identity cmd/identity.go

## TODO
- Automated tests
- Token deletion
- Token refresh
- Token validation
- Token claim assertion
- Multi-challenge authentication
- OAuth support
- JavaScript client
- HTML interface
- CORS
- API versioning/specification/discovery
- External token store (Redis?)
- External identity store
- Federated authentication
- X.509 support
- CLI token persistence/authentication
- Structured CLI output

## CLI

`identity new`
- creates a new identity

`identity log-in`
- authenticates an identity and generates access and refresh tokens

`identity log-out`
- deletes access tokens

`identity listen`
- listens for HTTP traffic

## HTTP API

`POST /`
- Creates a new identity
- Accepts a JSON or form-encoded request body consisting of a single key,
  "key", and its value which should be a password or passphrase used to
  authenticate the identity.
- Responds with a JSON object containing a single key "id", which has a value
  consisting of a UUID used to identify the new identity.

`POST /token`
- Requires HTTP Basic auth, user should be an identity's UUID, pass should be
  the identity's password.
- Creates a new pair of access and refresh JWTs

`DELETE /token`
- Requires Token auth
- Deletes authenticated access token

# License

    identity authentication and authorization service
    Copyright (C) 2020 Alexei Broner

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
