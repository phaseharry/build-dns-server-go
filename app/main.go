package main

import (
	"fmt"
	"net"

	message "github.com/codecrafters-io/dns-server-starter-go/internal/dns-message"
)

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

	// UDP transport are limited to 512 bytes
	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// DNS consumes the same message format as its response as well
		// so to pass stage, just grabbing the raw bytes and sending it in response
		reqDNSMessage, err := message.NewRequestDnsMessage(buf[:size])
		if err != nil {
			fmt.Println("Error parsing requestDNSMessage:", err)
			continue
		}

		responseDNSMEssage, err := message.NewResponseDnsMessage(reqDNSMessage)
		if err != nil {
			fmt.Println("Error creating respose DNSMessage:", err)
			continue
		}
		_, err = udpConn.WriteToUDP(responseDNSMEssage.Bytes(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
