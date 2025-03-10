module forum

go 1.18

require github.com/mattn/go-sqlite3 v1.14.22

require golang.org/x/crypto v0.24.0

require (
	github.com/gorilla/sessions v1.3.0
	golang.org/x/oauth2 v0.21.0
)

require (
	cloud.google.com/go/compute/metadata v0.4.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
)

replace example.com/old => example.com/new v1.0.0
