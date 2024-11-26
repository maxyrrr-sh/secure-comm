package main

import (
	"encoding/json"
	"fmt"
	"net"
)

type Packet struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Certificate string `json:"certificate"`
	Data        []byte `json:"data"`
}

type NetworkTransmitter struct {
	localIP   string
	localPort string
}

func NewNetworkTransmitter(ip, port string) *NetworkTransmitter {
	return &NetworkTransmitter{
		localIP:   ip,
		localPort: port,
	}
}

func GetLocalIP() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue // Інтерфейс вимкнений або це loopback
		}

		addrs, err := i.Addrs()
		if err != nil {
			return "", err
		}

		for _, addr := range addrs {
			var ip net.IP

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			// Використовуємо лише IPv4
			if ip.To4() != nil {
				return ip.String(), nil
			}
		}
	}

	return "", fmt.Errorf("локальна IP-адреса не знайдена")
}

func (nt *NetworkTransmitter) Listen(handler func(Packet)) error {
	address := net.JoinHostPort(nt.localIP, nt.localPort)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("помилка запуску прослуховувача (%s): %v", address, err)
	}
	defer listener.Close()

	fmt.Printf("Прослуховування на %s...\n", address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Помилка прийому з'єднання: %v", err)
			continue
		}

		go func(c net.Conn) {
			defer c.Close()

			var packet Packet
			decoder := json.NewDecoder(c)
			if err := decoder.Decode(&packet); err != nil {
				fmt.Printf("Помилка декодування пакета: %v", err)
				return
			}

			handler(packet)
		}(conn)
	}
}

func (nt *NetworkTransmitter) Send(destinationIP, destinationPort string, packet Packet) error {
	address := net.JoinHostPort(destinationIP, destinationPort)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()

	encoder := json.NewEncoder(conn)
	return encoder.Encode(packet)
}
