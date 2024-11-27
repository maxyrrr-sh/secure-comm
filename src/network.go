package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
)

type Message struct {
	Type    string // "text" або "file"
	Content []byte
	Nonce   []byte
}

func SendMessage(conn net.Conn, msg Message) error {
	encoder := json.NewEncoder(conn)
	return encoder.Encode(msg)
}

func ReceiveMessage(conn net.Conn) (Message, error) {
	var msg Message
	decoder := json.NewDecoder(conn)
	err := decoder.Decode(&msg)
	return msg, err
}

func ReadFile(filepath string) ([]byte, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	data := make([]byte, info.Size())
	_, err = bufio.NewReader(file).Read(data)
	return data, err
}
