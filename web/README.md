Implemented, Name, Access, Request Formats, Method, Path, Response Formats
[ ] Dashboard          Auth Required                   GET  /                 HTML, JSON
[o] Token List         Permissioned                    GET  /tokens           HTML, JSON
[x] Passphrase Form    Public                          GET  /tokens/new       HTML, JSON Schema
[ ] New Auth Token     Public         HTML Form, JSON  POST /tokens           HTML, JSON
[o] Identity List      Permissioned                    GET  /identities       HTML, JSON
[x] New Identity Form  Public                          GET  /identities/new   HTML, JSON Schema
[ ] Create Identity    Public         HTML Form, JSON  POST /identities       HTML, JSON
[ ] Identity Details   Permissioned                    GET  /identities/<id>  HTML, JSON

HTTP API
========

## Resources

### Dashboard
#### GET /

### Tokens
#### POST /tokens

### New Token Form
#### GET /token/new

### Identities
#### POST /identities

### New Identity Form
#### GET /identities/new
