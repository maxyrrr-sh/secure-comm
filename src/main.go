package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Secure-comm - hello!")
	fmt.Println("1. Send")
	fmt.Println("2. Listen")
	fmt.Print("Chose: ")

	var mode string
	mode, _ = reader.ReadString('\n')
	mode = strings.TrimSpace(mode)

	switch mode {
	case "1":
		sendMessage(reader)
	case "2":
		listenForMessages(reader)
	default:
		fmt.Println("Wrong! 1 or 2")
		os.Exit(1)
	}
}

func sendMessage(reader *bufio.Reader) {
	fmt.Print("Destination IP : ")
	destinationIP, _ := reader.ReadString('\n')
	destinationIP = strings.TrimSpace(destinationIP)
	sourceIP, _ := GetLocalIP()

	destinationPort := strings.TrimSpace("9001")

	fmt.Print("Attachments? (Enter to skip): ")
	filePath, _ := reader.ReadString('\n')
	filePath = strings.TrimSpace(filePath)

	var data []byte
	var encryptedPath string
	var err error

	if filePath != "" {
		encryptedPath, err = encryptFile(filePath)
		if err != nil {
			log.Fatalf("Crypto error: %v", err)
		}
		data, err = os.ReadFile(encryptedPath)
		if err != nil {
			log.Fatalf("CryptoError: %v", err)
		}
	} else {
		fmt.Print("Message: ")
		message, _ := reader.ReadString('\n')
		message = strings.TrimSpace(message)

		tmpFile := filepath.Join(os.TempDir(), "message.txt")
		if err := os.WriteFile(tmpFile, []byte(message), 0644); err != nil {
			log.Fatalf("Temp error: %v", err)
		}

		encryptedPath, err = encryptFile(tmpFile)
		if err != nil {
			log.Fatalf("Crypto Error (Message): %v", err)
		}
		defer os.Remove(tmpFile)
		defer os.Remove(encryptedPath)

		data, err = os.ReadFile(encryptedPath)
		if err != nil {
			log.Fatalf("CryptoError: %v", err)
		}
	}

	cert, privateKey, err := generateCertificate("Sender")
	if err != nil {
		log.Fatalf("Cert Error: %v", err)
	}

	err = saveCertificate(cert, privateKey, "sender_cert.pem", "sender_key.pem")
	if err != nil {
		log.Fatalf("Cert Error: %v", err)
	}

	packet := Packet{
		Source:      sourceIP,
		Destination: destinationIP,
		Certificate: "sender_cert.pem",
		Data:        data,
	}

	transmitter := NewNetworkTransmitter("localhost", "9000")
	err = transmitter.Send(destinationIP, destinationPort, packet)
	if err != nil {
		log.Fatalf("Помилка надсилання пакету: %v", err)
	}

	fmt.Println("✅ Повідомлення/файл успішно зашифровано та надіслано!")
}

func listenForMessages(reader *bufio.Reader) {
	port := strings.TrimSpace("9001")

	fmt.Print("Destination IP : ")
	localIP, _ := reader.ReadString('\n')
	localIP = strings.TrimSpace(localIP)
	if localIP == "" {
		localIP = "localhost"
	}

	transmitter := NewNetworkTransmitter(localIP, port)
	err := transmitter.Listen(func(packet Packet) {
		fmt.Println("\n🔒 Отримано зашифрований пакет:")
		fmt.Printf("Від: %s\n", packet.Source)

		err := verifyCertificate(packet.Certificate)
		if err != nil {
			log.Printf("Помилка перевірки сертифіката: %v", err)
			return
		}

		tmpEncryptedFile := filepath.Join(os.TempDir(), "received_encrypted.bin")
		err = os.WriteFile(tmpEncryptedFile, packet.Data, 0644)
		if err != nil {
			log.Printf("Помилка збереження тимчасового файлу: %v", err)
			return
		}
		defer os.Remove(tmpEncryptedFile)

		decryptedPath, err := decryptFile(tmpEncryptedFile)
		if err != nil {
			log.Printf("Помилка дешифрування: %v", err)
			return
		}
		defer os.Remove(decryptedPath)

		content, err := os.ReadFile(decryptedPath)
		if err != nil {
			log.Printf("Помилка читання розшифрованого файлу: %v", err)
			return
		}

		fmt.Println("✅ Успішно розшифровано:")
		fmt.Println(string(content))
	})
	if err != nil {
		log.Fatalf("Помилка прослуховування: %v", err)
	}
}
