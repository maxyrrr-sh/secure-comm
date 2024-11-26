package main

import (
	"encoding/json"
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

func (nt *NetworkTransmitter) Listen(handler func(Packet)) error {
	address := net.JoinHostPort(nt.localIP, nt.localPort)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go func(c net.Conn) {
			defer c.Close()

			var packet Packet
			decoder := json.NewDecoder(c)
			if err := decoder.Decode(&packet); err != nil {
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
