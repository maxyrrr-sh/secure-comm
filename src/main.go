package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
)

// Message структура повідомлення
type Message struct {
	Text       string `json:"text"`
	Attachment []byte `json:"attachment,omitempty"`
	Filename   string `json:"filename,omitempty"`
	AESKey     []byte `json:"aes_key,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Використання: <mode> <ip:port>")
		fmt.Println("Режими: send або receive")
		return
	}

	mode := os.Args[1]
	address := os.Args[2]

	switch mode {
	case "send":
		sendMode(address)
	case "receive":
		receiveMode(address)
	default:
		fmt.Println("Невідомий режим:", mode)
	}
}

func sendMode(address string) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("Помилка з'єднання:", err)
		return
	}
	defer conn.Close()

	// Генеруємо RSA-ключі
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Помилка генерації RSA-ключа:", err)
		return
	}

	// Отримуємо публічний ключ іншого користувача
	pubKeyBytes := make([]byte, 512)
	_, err = conn.Read(pubKeyBytes)
	if err != nil {
		fmt.Println("Помилка отримання публічного ключа:", err)
		return
	}

	pubKey, err := parsePublicKey(pubKeyBytes)
	if err != nil {
		fmt.Println("Помилка парсингу публічного ключа:", err)
		return
	}

	// Надсилаємо свій публічний ключ
	conn.Write(serializePublicKey(&privateKey.PublicKey))

	// Зчитуємо текст повідомлення
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Введіть повідомлення: ")
	text, _ := reader.ReadString('\n')

	// Обробляємо вкладення
	var attachment []byte
	var filename string
	fmt.Print("Шлях до вкладення (порожньо, якщо немає): ")
	attachmentPath, _ := reader.ReadString('\n')
	attachmentPath = attachmentPath[:len(attachmentPath)-1] // видалення нового рядка
	if attachmentPath != "" {
		attachment, filename, err = encryptFile(attachmentPath)
		if err != nil {
			fmt.Println("Помилка шифрування файлу:", err)
			return
		}
	}

	// Генеруємо AES-ключ через зовнішній виконуваний файл
	aesKey, err := generateAESKey()
	if err != nil {
		fmt.Println("Помилка генерації AES-ключа:", err)
		return
	}

	// Шифруємо AES-ключ за допомогою RSA
	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
	if err != nil {
		fmt.Println("Помилка шифрування AES-ключа:", err)
		return
	}

	// Формуємо повідомлення
	msg := Message{
		Text:       text,
		Attachment: attachment,
		Filename:   filename,
		AESKey:     encryptedAESKey,
	}

	// Відправляємо повідомлення
	encoder := json.NewEncoder(conn)
	err = encoder.Encode(msg)
	if err != nil {
		fmt.Println("Помилка відправлення:", err)
		return
	}

	fmt.Println("Повідомлення успішно відправлено!")
}

func receiveMode(address string) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Println("Помилка запуску сервера:", err)
		return
	}
	defer listener.Close()

	fmt.Println("Очікування підключення...")

	conn, err := listener.Accept()
	if err != nil {
		fmt.Println("Помилка прийому з'єднання:", err)
		return
	}
	defer conn.Close()

	// Генеруємо RSA-ключі
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Помилка генерації RSA-ключа:", err)
		return
	}

	// Надсилаємо свій публічний ключ
	conn.Write(serializePublicKey(&privateKey.PublicKey))

	// Отримуємо публічний ключ іншого користувача
	pubKeyBytes := make([]byte, 512)
	_, err = conn.Read(pubKeyBytes)
	if err != nil {
		fmt.Println("Помилка отримання публічного ключа:", err)
		return
	}

	// Отримуємо повідомлення
	var msg Message
	decoder := json.NewDecoder(conn)
	err = decoder.Decode(&msg)
	if err != nil {
		fmt.Println("Помилка отримання повідомлення:", err)
		return
	}

	// Дешифруємо AES-ключ
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, msg.AESKey, nil)
	if err != nil {
		fmt.Println("Помилка дешифрування AES-ключа:", err)
		return
	}

	// Дешифруємо вкладення
	if len(msg.Attachment) > 0 {
		err = decryptFile(msg.Attachment, aesKey, msg.Filename)
		if err != nil {
			fmt.Println("Помилка дешифрування файлу:", err)
			return
		}
		fmt.Println("Файл успішно збережено як:", msg.Filename)
	}

	// Виводимо текст повідомлення
	fmt.Println("Отримане повідомлення:", msg.Text)
}

func encryptFile(path string) ([]byte, string, error) {
	encryptedPath := path + ".enc"
	cmd := exec.Command("aes", "--encrypt", path)
	err := cmd.Run()
	if err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(encryptedPath)
	if err != nil {
		return nil, "", err
	}
	return data, filepath.Base(path), nil
}

func decryptFile(data []byte, key []byte, filename string) error {
	tmpEncrypted := "tmp.enc"
	tmpKey := "tmp.key"

	err := os.WriteFile(tmpEncrypted, data, 0644)
	if err != nil {
		return err
	}
	err = os.WriteFile(tmpKey, key, 0644)
	if err != nil {
		return err
	}
	cmd := exec.Command("aes", "--decrypt", tmpEncrypted, "-k", tmpKey)
	return cmd.Run()
}

func generateAESKey() ([]byte, error) {
	tmpKeyPath := "aes_key"
	cmd := exec.Command("aes", "--generate-key", tmpKeyPath)
	err := cmd.Run()
	if err != nil {
		return nil, err
	}
	return os.ReadFile(tmpKeyPath)
}

func serializePublicKey(key *rsa.PublicKey) []byte {
	return []byte(fmt.Sprintf("%x,%x", key.N, key.E))
}

func parsePublicKey(data []byte) (*rsa.PublicKey, error) {
	var n, e int
	_, err := fmt.Sscanf(string(data), "%x,%x", &n, &e)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{N: big.NewInt(int64(n)), E: e}, nil
}
