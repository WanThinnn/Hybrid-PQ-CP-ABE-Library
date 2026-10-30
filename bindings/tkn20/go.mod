module cpabe_tkn20

go 1.25.0

require github.com/cloudflare/circl v1.6.4

require (
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/cloudflare/circl => ../../vendor/circl
