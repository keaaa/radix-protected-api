package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

type AzurePublicKeys struct {
	Keys []AzurePublicKey `json:"keys"`
}

type AzurePublicKey struct {
	Kid       string   `json:"kid"`
	X5C       []string `json:"x5c"`
	PublicKey *rsa.PublicKey
}

var publicKeys map[string]*rsa.PublicKey

func main() {
	go func() {
		for true {
			loadPublicKeys()
			time.Sleep(10 * time.Minute)
		}
	}()

	router := mux.NewRouter().StrictSlash(true)
	router.PathPrefix("/").HandlerFunc(authorizeRequest)
	log.Fatal(http.ListenAndServe(":8080", router))
}

func authorizeRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("Method %q, Request %q\n", r.Method, r.RequestURI)
	// 401 Unauthorized - not authenticated
	// 403 Forbidden - not authorized
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		errMsg := "Unauthorized - missing access token in Authorization header"
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, errMsg)
		log.Print(errMsg)
	} else if !strings.Contains(authorization, "Bearer ") && !strings.Contains(authorization, "bearer ") {
		errMsg := fmt.Sprintf("Unauthorized - Authorization should be prefixed with \"Bearer\". Current value %s", authorization)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, errMsg)
		log.Print(errMsg)
	} else {
		token := authorization[7:len(authorization)]
		err := validateToken(token)
		if err != nil {
			errMsg := fmt.Sprintf("Forbidden - %v", err)
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, errMsg)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	}
}

func validateToken(token string) error {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		publicKey := getPublicKey(fmt.Sprintf("%v", token.Header["kid"]))
		return publicKey, nil
	})
	if err != nil {
		return err
	}
	if !parsedToken.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}

func loadPublicKeys() error {
	kidToKey := map[string]*rsa.PublicKey{}
	keys := AzurePublicKeys{}
	r, err := http.Get("https://login.microsoftonline.com/3aa4a235-b6e2-48d5-9195-7fcf05b459b0/discovery/v2.0/keys")
	if err != nil {
		return err
	}
	defer r.Body.Close()
	err = json.NewDecoder(r.Body).Decode(&keys)
	if err != nil {
		return err
	}
	for _, key := range keys.Keys {
		kidToKey[key.Kid] = createPublicKey(key.X5C[0])
	}
	publicKeys = kidToKey
	log.Printf("public keys loaded")
	return nil
}

func getPublicKey(kid string) *rsa.PublicKey {
	return publicKeys[kid]
}

func createPublicKey(publicKey string) *rsa.PublicKey {
	pk := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", publicKey)
	pkByte := []byte(pk)
	block, _ := pem.Decode(pkByte)
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	return cert.PublicKey.(*rsa.PublicKey)

	// publicKey := []byte("-----BEGIN PUBLIC KEY-----\nMIIDBTCCAe2gAwIBAgIQbiJkXaenk61AKixVocnLRTANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE5MTAwNTAwMDAwMFoXDTI0MTAwNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ2H9Y6Z+3BXUCtlbmXr6H5owYy15XTl3vdpOZLUkk4OV9LMsB1phjNp+wgl28eAgrNNfu4BTVlHdR9x6NTrSiIapsYjzzEz4mOmRh1Bw5tJxit0VEGn00/ZENniTjgeEFYgDHYwjrfZQ6dERBFiw1OQb2IG5f3KLtx92lUXeIZ7ZvTaPkUpc4Qd6wQZmWgzPqWFocRsJATGyZzXiiXQUrc9cVqm1bws3P0lFBcqNtv+AKDYKT5IRYLsyCkueQC9R6LUCsZVD7bVIkeQuA3iehJKIEAlk/e3j5E4VaCRs642ajb/z9kByTl2xL2k0AeZGc8/Rcy7SQn0LBcJNZGp/SMCAwEAAaMhMB8wHQYDVR0OBBYEFOLhl3BDPLNVYDe38Dp9JbUmd4kKMA0GCSqGSIb3DQEBCwUAA4IBAQAN4XwyqYfVdMl0xEbBMa/OzSfIbuI4pQWWpl3isKRAyhXezAX1t/0532LsIcYkwubLifnjHHqo4x1jnVqkvkFjcPZ12kjs/q5d1L0LxlQST/Uqwm/9/AeTzRZXtUKNBWBOWy9gmw9DEH593sNYytGAEerbWhCR3agUxsnQSYTTwg4K9cSqLWzHX5Kcz0NLCGwLx015/Jc7HwPJnp7q5Bo0O0VfhomDiEctIFfzqE5x9T9ZTUSWUDn3J7DYzs2L1pDrOQaNs/YEkXsKDP1j4tOFyxic6OvjQ10Yugjo5jg1uWoxeU8pI0BxY6sj2GZt3Ynzev2bZqmj68y0I9Z+NTZo\n-----END PUBLIC KEY-----")
	// block, _ := pem.Decode(publicKey)
	// var cert *x509.Certificate
	// cert, _ = x509.ParseCertificate(block.Bytes)
	// return cert.PublicKey.(*rsa.PublicKey)
}
