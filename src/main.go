package main

import (
	"bufio"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
)

func main() {
	fmt.Println("==== Система безпечної передачі повідомлень ====")
	fmt.Println("1: Запустити сервер")
	fmt.Println("2: Підключитись до клієнта")
	var choice int
	fmt.Scanln(&choice)

	if choice == 1 {
		startServer()
	} else if choice == 2 {
		startClient()
	} else {
		fmt.Println("Невірний вибір. Завершення програми.")
	}
}

func startServer() {
	fmt.Println("[Сервер] Генерація RSA ключів...")
	privateKey, err := GenerateRSAKeys(2048)
	if err != nil {
		fmt.Println("[Сервер] Помилка генерації RSA ключів:", err)
		return
	}
	publicKey, _ := ExportPublicKey(&privateKey.PublicKey)
	fmt.Println("[Сервер] RSA ключі згенеровано успішно.")

	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("[Сервер] Помилка запуску сервера:", err)
		return
	}
	defer listener.Close()
	fmt.Println("[Сервер] Очікування підключення...")

	conn, err := listener.Accept()
	if err != nil {
		fmt.Println("[Сервер] Помилка підключення:", err)
		return
	}
	defer conn.Close()
	fmt.Println("[Сервер] Клієнт підключився.")

	fmt.Println("[Сервер] Надсилаємо публічний ключ клієнту...")
	conn.Write(publicKey)
	fmt.Println("[Сервер] Надано сертифікат сервера:\n", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKey})))

	fmt.Println("[Сервер] Отримуємо публічний ключ клієнта...")
	clientPublicKeyPEM := make([]byte, 4096)
	n, err := conn.Read(clientPublicKeyPEM)
	if err != nil {
		fmt.Println("[Сервер] Помилка отримання ключа клієнта:", err)
		return
	}
	clientPublicKey, err := ImportPublicKey(clientPublicKeyPEM[:n])
	if err != nil {
		fmt.Println("[Сервер] Помилка імпорту публічного ключа клієнта:", err)
		return
	}
	fmt.Println("[Сервер] Отримано сертифікат клієнта:\n", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: clientPublicKeyPEM[:n]})))

	fmt.Println("[Сервер] Генерація AES ключа...")
	aesKey, err := GenerateAESKey()
	if err != nil {
		fmt.Println("[Сервер] Помилка генерації AES ключа:", err)
		return
	}
	fmt.Println("[Сервер] AES ключ згенеровано.")

	fmt.Println("[Сервер] Шифруємо AES ключ RSA публічним ключем клієнта...")
	encryptedAESKey, err := EncryptRSA(clientPublicKey, aesKey)
	if err != nil {
		fmt.Println("[Сервер] Помилка шифрування AES ключа:", err)
		return
	}
	conn.Write(encryptedAESKey)
	fmt.Println("[Сервер] AES ключ надіслано клієнту (шифрування RSA).")

	fmt.Println("[Сервер] З'єднання успішно встановлено!")
	handleConnection("Сервер", conn, aesKey)
}

func startClient() {
	fmt.Println("[Клієнт] Генерація RSA ключів...")
	privateKey, err := GenerateRSAKeys(2048)
	if err != nil {
		fmt.Println("[Клієнт] Помилка генерації RSA ключів:", err)
		return
	}
	publicKey, _ := ExportPublicKey(&privateKey.PublicKey)
	fmt.Println("[Клієнт] RSA ключі згенеровано успішно.")

	fmt.Print("[Клієнт] Введіть IP сервера: ")
	var serverIP string
	fmt.Scanln(&serverIP)

	conn, err := net.Dial("tcp", serverIP+":8080")
	if err != nil {
		fmt.Println("[Клієнт] Помилка підключення до сервера:", err)
		return
	}
	defer conn.Close()
	fmt.Println("[Клієнт] Підключено до сервера.")

	fmt.Println("[Клієнт] Отримуємо публічний ключ сервера...")
	serverPublicKeyPEM := make([]byte, 4096)
	n, err := conn.Read(serverPublicKeyPEM)
	if err != nil {
		fmt.Println("[Клієнт] Помилка отримання ключа сервера:", err)
		return
	}
	fmt.Println("[Клієнт] Отримано сертифікат сервера:\n", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: serverPublicKeyPEM[:n]})))

	fmt.Println("[Клієнт] Надсилаємо публічний ключ серверу...")
	conn.Write(publicKey)
	fmt.Println("[Клієнт] Надано сертифікат клієнта:\n", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKey})))

	fmt.Println("[Клієнт] Отримуємо шифрований AES ключ...")
	encryptedAESKey := make([]byte, 256) // максимальний розмір за RSA
	n, err = conn.Read(encryptedAESKey)
	if err != nil {
		fmt.Println("[Клієнт] Помилка отримання AES ключа:", err)
		return
	}
	aesKey, err := DecryptRSA(privateKey, encryptedAESKey[:n])
	if err != nil {
		fmt.Println("[Клієнт] Помилка дешифрування AES ключа:", err)
		return
	}
	fmt.Println("[Клієнт] AES ключ отримано та дешифровано успішно.")

	fmt.Println("[Клієнт] З'єднання успішно встановлено!")
	handleConnection("Клієнт", conn, aesKey)
}

func handleConnection(role string, conn net.Conn, aesKey []byte) {
	go func() {
		for {
			msg, err := ReceiveMessage(conn)
			if err != nil {
				if err.Error() == "EOF" {
					fmt.Printf("[%s] З'єднання завершено.\n", role)
					return
				}
				fmt.Printf("[%s] Помилка отримання повідомлення: %s\n", role, err)
				continue
			}
			plaintext, err := DecryptAES(aesKey, msg.Content, msg.Nonce)
			if err != nil {
				fmt.Printf("[%s] Помилка дешифрування повідомлення: %s\n", role, err)
				continue
			}
			fmt.Printf("[%s] Отримано повідомлення: %s\n", role, string(plaintext))
		}
	}()

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Введіть повідомлення (або 'exit' для виходу): ")
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "exit" {
			fmt.Printf("[%s] Завершення з'єднання.\n", role)
			conn.Close()
			break
		}

		fmt.Printf("[%s] Шифруємо повідомлення...\n", role)
		encryptedMessage, nonce, err := EncryptAES(aesKey, []byte(text))
		if err != nil {
			fmt.Printf("[%s] Помилка шифрування: %s\n", role, err)
			continue
		}

		msg := Message{Type: "text", Content: encryptedMessage, Nonce: nonce}
		err = SendMessage(conn, msg)
		if err != nil {
			fmt.Printf("[%s] Помилка надсилання повідомлення: %s\n", role, err)
			break
		}
		fmt.Printf("[%s] Повідомлення успішно надіслано.\n", role)
	}
}
