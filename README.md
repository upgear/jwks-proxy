# JSON Web Key Proxy

```sh
# Generate a private key
openssl genpkey -algorithm RSA -out abc.private.pem -pkeyopt rsa_keygen_bits:2048

# Make directory to serve public keys from
mkdir public

# Generate a public key
openssl rsa -pubout -in abc.private.pem -out public/abc.public.pem
```
