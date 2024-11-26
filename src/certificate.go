package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func loadCertificate(certPath string) (*x509.Certificate, error) {
	certPEMBlock, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("помилка читання сертифіката: %v", err)
	}

	block, _ := pem.Decode(certPEMBlock)
	if block == nil {
		return nil, fmt.Errorf("не вдалося декодувати PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}
