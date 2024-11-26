package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os/exec"
	"path/filepath"
	"time"
)

func encryptFile(inputPath string) (string, error) {
	outputPath := inputPath + ".encrypted"
	cmd := exec.Command("aes", "--encrypt", inputPath)
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("помилка шифрування AES: %v", err)
	}
	return outputPath, nil
}

func decryptFile(encryptedPath string) (string, error) {
	outputPath := filepath.Join(filepath.Dir(encryptedPath), "decrypted_"+filepath.Base(encryptedPath))
	cmd := exec.Command("aes", "--decrypt", encryptedPath)
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("помилка дешифрування AES: %v", err)
	}
	return outputPath, nil
}

func generateCertificate(commonName string) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Secure Communication"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	template.DNSNames = []string{"localhost"}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, privateKey, nil
}

func saveCertificate(cert *x509.Certificate, privateKey *rsa.PrivateKey, certPath, keyPath string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	err := ioutil.WriteFile(certPath, certPEM, 0644)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	err = ioutil.WriteFile(keyPath, keyPEM, 0600)
	if err != nil {
		return err
	}

	return nil
}

func verifyCertificate(certPath string) error {
	certPEMBlock, err := ioutil.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("помилка читання сертифіката: %v", err)
	}

	block, _ := pem.Decode(certPEMBlock)
	if block == nil {
		return fmt.Errorf("не вдалося декодувати PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("помилка парсингу сертифіката: %v", err)
	}

	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("термін дії сертифіката минув")
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("сертифікат не призначений для цифрового підпису")
	}

	fingerprint := sha256.Sum256(cert.Raw)
	fmt.Printf("Відбиток сертифіката (SHA256): %x\n", fingerprint)

	return nil
}
