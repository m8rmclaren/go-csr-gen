package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"strings"
)

func main() {
	csr := generateCSR("ejbca-k8s-proxy"+randStringFromCharSet(10), "Administrators", "Internal Test", "US")
	log.Println("\nCSR Bytes:\n", string(csr))

	encoded := base64.StdEncoding.EncodeToString(csr)
	log.Println("\nBase64 encoded CSR:\n", encoded)

	trimmed := strings.ReplaceAll(encoded, "\n", "")
	log.Println("\nTrimmed CSR:\n", trimmed)

	err := os.WriteFile("newrequest.csr", []byte(trimmed), 0644)
	if err != nil {
		log.Fatal(err)
	}

	decoded, _ := pem.Decode(csr)
	log.Println("\nRaw CSR:\n", string(decoded.Bytes))

	request, err := x509.ParseCertificateRequest(decoded.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(request.Subject)
}

func generateCSR(commonName string, ou string, o string, country string) []byte {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	subj := pkix.Name{
		CommonName: commonName,
	}
	if ou != "" {
		subj.OrganizationalUnit = []string{ou}
	}
	if o != "" {
		subj.Organization = []string{o}
	}
	if country != "" {
		subj.Country = []string{country}
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	var csrBuf bytes.Buffer
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	err := pem.Encode(&csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err != nil {
		return make([]byte, 0, 0)
	}

	return csrBuf.Bytes()
}

// From https://github.com/hashicorp/terraform-plugin-sdk/blob/v2.10.0/helper/acctest/random.go#L51
func randStringFromCharSet(strlen int) string {
	charSet := "abcdefghijklmnopqrstuvwxyz012346789"
	result := make([]byte, strlen)
	for i := 0; i < strlen; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
		if err != nil {
			return ""
		}
		result[i] = charSet[num.Int64()]
	}
	return string(result)
}
