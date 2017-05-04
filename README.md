# JSON Web Key Proxy

This proxy is used to combine JSON Web Key sets into a single endpoint. It
enables you to combine the JWKs from multiple origins and locally from files.

Currently only RSA keys are supported.

## Quickstart

```sh
# Generate a private key
openssl genpkey -algorithm RSA -out abc.private.pem -pkeyopt rsa_keygen_bits:2048

# Make directory to serve public keys from
mkdir public

# Generate a public key
openssl rsa -pubout -in abc.private.pem -out public/abc.public.pem

# Proxy combination of Auth0 keys and those in public/
export JWKS_ORIGINS=https://yourdomain.auth0.com/.well-known/jwks.json
go run main.go
```

## Configuration

Configuration is done via environment variables. Local keys are served out of a
single directory.

```sh
# Port to listen for http traffic (defaults to 8080)
JWKS_PORT=4000

# Comma-seperated list of origins
JWKS_ORIGINS=http://abc.com/.well-known/jwks.json,http://xyz.com/.well-known/jwks.json

# Directory to serve keys from
# Must be of the form <key-id>.private.pem
# Defaults to public/
JWKS_KEY_DIR=mypublickeys/
```

## Development

Vendoring is done via [govendor](https://github.com/kardianos/govendor).

