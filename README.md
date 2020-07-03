Identify
========

Identity authentication and authorization service. Identify provides a secure
interface for authenticating one's identity and provides token-based
authorization for other services.

This project is in its infancy, feel free to submit issues but I'm not quite
ready for pull requests. Use at your own risk, this code is far from being
production ready.

## Building

    make

## CLI
`identify new-identity`
- creates a new identity

`identify`
- authenticates an identity and generates access and refresh tokens

`identify log-out`
- deletes access tokens

`identify listen`
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

Identify authentication and authorization service
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
