# Secure go-chat
This is a secure chat written in [golang](https://golang.org/) for backend and golang / [AngularJS](https://angularjs.org/) for frontend
## Components
### Database
For database, it uses SQLite3, using [go-sqlite3](https://github.com/mattn/go-sqlite3) driver
### Pusher
To send notifications from golang to web interface, it uses [go-pushes](https://github.com/Toorop/go-pusher)
### Security
- Block cipher ([AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)) for the chat messages
- Passwords hashed by [SHA-512](https://en.wikipedia.org/wiki/SHA-2)
- [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security), using [crypto/tls](https://golang.org/pkg/crypto/tls/) package

## Usage
- Create a database called `data/database.go`, using `data/DBScript.sql` and [SQLiteBrowser](https://github.com/sqlitebrowser/sqlitebrowser)
- `go run servidor.go`
- `go run cliente.go`
- https://localhost:8095
