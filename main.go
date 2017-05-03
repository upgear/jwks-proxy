package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	jose "github.com/square/go-jose"
)

var (
	config struct {
		Origins []string
		KeyDir  string
		Port    string
	}
	internalKeys []jose.JsonWebKey
)

func init() {
	configure()

	var err error
	internalKeys, err = readPEMFiles(config.KeyDir)
	if err != nil {
		panic("unable to read pem files: " + err.Error())
	}
}

func configure() {
	// Grabs values from environment
	config.KeyDir = os.Getenv("JWKS_KEY_DIR")
	config.Origins = strings.Split(os.Getenv("JWKS_ORIGINS"), ",")
	config.Port = os.Getenv("JWKS_PORT")

	// Defaults
	if config.Port == "" {
		config.Port = "8080"
	}
	if config.KeyDir == "" {
		config.KeyDir = "public"
	}
}

func main() {
	log.Println("listening for http traffic on port " + config.Port)
	log.Fatal(http.ListenAndServe(":"+config.Port, http.HandlerFunc(handle)))
}

func handle(w http.ResponseWriter, r *http.Request) {
	ks, err := fetchAllJWKs(config.Origins)
	if err != nil {
		jsonErr(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		log.Println("unable to fetch jwks from origins: " + err.Error())
		return
	}

	ks = append(ks, internalKeys...)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(jose.JsonWebKeySet{ks})
}

func jsonErr(w http.ResponseWriter, err string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(struct {
		Error string `json:"error" xml:"error"`
	}{err})
}

func readPEMFiles(dir string) ([]jose.JsonWebKey, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var keys []jose.JsonWebKey

	const suffix = ".public.pem"
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), suffix) {
			continue
		}

		fp := filepath.Join(dir, f.Name())
		btys, err := ioutil.ReadFile(fp)
		if err != nil {
			return nil, err
		}

		k, err := pemToKey(btys, strings.TrimSuffix(f.Name(), suffix))
		if err != nil {
			return nil, err
		}

		keys = append(keys, k)
	}

	return keys, nil
}

func pemToKey(key []byte, kid string) (jose.JsonWebKey, error) {
	var err error
	var k jose.JsonWebKey

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return k, errors.New("must be PEM encoded")
	}

	// Parse the key
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return k, err
	}

	// Assert that the key is the right type
	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = cert.PublicKey.(*rsa.PublicKey); !ok {
		return k, errors.New("not RSA public key")
	}

	// Build the JsonWebKey
	k.Key = pkey
	k.KeyID = kid
	k.Algorithm = string(jose.RS256)
	k.Use = "sig"
	k.Certificates = []*x509.Certificate{cert}

	return k, nil
}

func fetchAllJWKs(origins []string) ([]jose.JsonWebKey, error) {
	var keys []jose.JsonWebKey

	var g errgroup.Group
	mutex := &sync.Mutex{}
	for _, url := range origins {
		log.Println("fetching from: " + url)

		url := url // https://golang.org/doc/faq#closures_and_goroutines
		g.Go(func() error {
			ks, err := fetchJWKs(url)
			if err != nil {
				return err
			}

			mutex.Lock()
			keys = append(keys, ks...)
			mutex.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return keys, nil
}

func fetchJWKs(origin string) ([]jose.JsonWebKey, error) {
	var ks jose.JsonWebKeySet

	resp, err := http.Get(origin)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&ks); err != nil {
		return nil, err
	}

	return ks.Keys, nil
}
