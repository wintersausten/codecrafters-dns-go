package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

type DNSMessage struct {
  Header
  Questions []Question
  Answer []RR
}

type Header struct {
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

type Question struct {
  Name string
  Type uint16
  Class uint16
}

type RR struct {
  Name string
  Type uint16
  Class uint16
  TTL uint32
  Length uint16
  Data []byte
}

func newDNSMessage() DNSMessage {
  a := []RR {
    {
      Name: "codecrafters.io",
      Type: 1,
      Class: 1,
      TTL: 60,
      Length: 4,
      Data: []byte("\x08\x08\x08\x08"),
    },
  }
  q := []Question {
    {
      Name: "codecrafters.io",
      Type: 1,
      Class: 1,
    },
  }
  h := Header {
    ID:  1234,
    QR: 1,
    OPCODE: 0,
    AA: 0,
    TC: 0,
    RD: 0,
    Z: 0,
    RCODE: 0,
    QDCOUNT: uint16(len(q)),
    ANCOUNT: uint16(len(a)),
    NSCOUNT: 0,
    ARCOUNT: 0,
  }
  return DNSMessage{Questions: q, Header: h, Answer: a}
}

func (q Question) serialize() []byte {
    buffer := new(bytes.Buffer)
    buffer.Write(serializeDomain(q.Name))
    binary.Write(buffer, binary.BigEndian, q.Type)
    binary.Write(buffer, binary.BigEndian, q.Class)
    return buffer.Bytes()
}

func (r RR) serialize() []byte {
    buffer := new(bytes.Buffer)
    buffer.Write(serializeDomain(r.Name))
    binary.Write(buffer, binary.BigEndian, r.Type)
    binary.Write(buffer, binary.BigEndian, r.Class)
    binary.Write(buffer, binary.BigEndian, r.TTL)
    binary.Write(buffer, binary.BigEndian, uint16(len(r.Data)))
    buffer.Write(r.Data)
    return buffer.Bytes()
}

func (h Header) serialize() []byte {
	buffer := make([]byte, 12)
	binary.BigEndian.PutUint16(buffer[0:2], h.ID)
	buffer[2] = (h.QR << 7) | (h.OPCODE << 3) | (h.AA << 2) | (h.TC << 1) | h.RD
	buffer[3] = (h.Z << 4) | h.RCODE
	binary.BigEndian.PutUint16(buffer[4:6], h.QDCOUNT)
	binary.BigEndian.PutUint16(buffer[6:8], h.ANCOUNT)
	binary.BigEndian.PutUint16(buffer[8:10], h.NSCOUNT)
	binary.BigEndian.PutUint16(buffer[10:12], h.ARCOUNT)
	return buffer
}

func serializeDomain(domain string) []byte {
  buffer := []byte{}
  labels := strings.Split(domain, ".")
  for _, label := range(labels) {
    buffer = append(buffer, byte(len(label)))
    buffer = append(buffer, []byte(label)...)
  }
  buffer = append(buffer, '\x00')
  return buffer
}

func (m DNSMessage) serialize() []byte {
  buffer := new(bytes.Buffer)
  buffer.Write(m.Header.serialize())
  for _, q := range(m.Questions) {
    buffer.Write(q.serialize())
  }
  for _, r := range(m.Answer) {
    buffer.Write(r.serialize())
  }
  return buffer.Bytes()
}

func main() {
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

    response := newDNSMessage()

		_, err = udpConn.WriteToUDP(response.serialize(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
