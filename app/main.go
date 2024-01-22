package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

type DNSMessage struct {
  ID uint16
  QR uint8
  OPCODE uint8
  AA uint8
  TC uint8
  RD uint8
  Z uint8
  RCODE uint8
  QDCOUNT uint16
  ANCOUNT uint16
  NSCOUNT uint16
  ARCOUNT uint16
}

func (m DNSMessage) serialize() []byte {
	buffer := make([]byte, 12)
	binary.BigEndian.PutUint16(buffer[0:2], m.ID)
	buffer[2] = (m.QR << 7) | (m.OPCODE << 3) | (m.AA << 2) | (m.TC << 1) | m.RD
	buffer[3] = (m.Z << 4) | m.RCODE
	binary.BigEndian.PutUint16(buffer[4:6], m.QDCOUNT)
	binary.BigEndian.PutUint16(buffer[6:8], m.ANCOUNT)
	binary.BigEndian.PutUint16(buffer[8:10], m.NSCOUNT)
	binary.BigEndian.PutUint16(buffer[10:12], m.ARCOUNT)
	return buffer
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	// Uncomment this block to pass the first stage

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// Create an empty response
    response := DNSMessage {
      ID:  1234,
      QR: 1,
      OPCODE: 0,
      AA: 0,
      TC: 0,
      RD: 0,
      Z: 0,
      RCODE: 0,
      QDCOUNT: 0,
      ANCOUNT: 0,
      NSCOUNT: 0,
      ARCOUNT: 0,
    }

		_, err = udpConn.WriteToUDP(response.serialize(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
