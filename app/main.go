package main

import (
	"flag"
	"fmt"
	"net"
	"time"

	message "github.com/codecrafters-io/dns-server-starter-go/internal/dns-message"
)

func main() {
	resolver := flag.String("resolver", "", "upstream DNS server, as ip:port")
	flag.Parse()

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
		reqDNSMessage, err := message.ParseDNSMessage(buf[:size])
		if err != nil {
			fmt.Println("Error parsing requestDNSMessage:", err)
			continue
		}

		// handle forwarding
		if *resolver != "" {
			// for server forwarding, each question within the initial request message gets its own message
			// and is forwarded individually to the forward server to get its question answered.
			// ex.
			// initial request has: <header><question1><question2>
			// two forward request is made with: <header><question1> & <header<question2>
			// their responses will be: <header><question1><answer1> & <header><question2><answer2>
			// we will respond to the client as <header QD=2, AN=2><question1><question2><answer1><answer2>
			forwardDNSRequests := make([]message.DNSMessage, 0, len(reqDNSMessage.Questions))
			for _, question := range reqDNSMessage.Questions {
				forwardedBytes := []byte{}
				forwardedHeader := reqDNSMessage.Header.WithQuestionCount(1)
				forwardedBytes = append(forwardedBytes, forwardedHeader.Bytes()...)
				forwardedBytes = append(forwardedBytes, question.Bytes()...)

				forwardedDNS, err := message.ParseDNSMessage(forwardedBytes)
				if err != nil {
					fmt.Println("Error parsing forwarded DNS request", err)
					break
				}
				forwardDNSRequests = append(forwardDNSRequests, forwardedDNS)
			}
			if len(forwardDNSRequests) != len(reqDNSMessage.Questions) {
				fmt.Printf("Error, unable to create the same forward DNS message requests as question count. Want: %d, Got: %d\n", len(reqDNSMessage.Questions), len(forwardDNSRequests))
				continue
			}

			forwardDNSResponse := make([]message.DNSMessage, 0, len(reqDNSMessage.Questions))
			for _, forwardedReq := range forwardDNSRequests {
				res, err := exchange(*resolver, forwardedReq.Bytes())
				if err != nil {
					fmt.Println("Error sending message to forward server:", err)
					break
				}
				dnsMessage, err := message.ParseDNSMessage(res)
				if err != nil {
					fmt.Println("Error parsing forwarded DNS response:", err)
					break
				}
				forwardDNSResponse = append(forwardDNSResponse, dnsMessage)
			}
			if len(forwardDNSRequests) != len(forwardDNSResponse) {
				fmt.Printf("Error, did not get the same number of response for the requests made. Want: %d, Got: %d\n", len(forwardDNSRequests), len(forwardDNSResponse))
				continue
			}

			questions := reqDNSMessage.Questions
			answers := make([]message.Answer, 0, len(reqDNSMessage.Questions))

			for _, forwardedRes := range forwardDNSResponse {
				answers = append(answers, forwardedRes.Answers...)
			}

			resHeader := message.BuildResponseHeader(reqDNSMessage.Header, uint16(len(answers)))

			resDNSMessage := message.DNSMessage{
				Header:    resHeader,
				Questions: questions,
				Answers:   answers,
			}
			_, err = udpConn.WriteToUDP(resDNSMessage.Bytes(), source)
			if err != nil {
				fmt.Println("Failed to send response:", err)
			}
		} else {
			// non-forwarding response
			responseDNSMessage, err := message.NewResponseDnsMessage(reqDNSMessage)
			if err != nil {
				fmt.Println("Error creating respose DNSMessage:", err)
				continue
			}
			_, err = udpConn.WriteToUDP(responseDNSMessage.Bytes(), source)
			if err != nil {
				fmt.Println("Failed to send response:", err)
			}
		}
	}
}

// exchange sends one DNS query to addr ("ip:port") and returns the raw reply.
func exchange(addr string, query []byte) ([]byte, error) {
	conn, err := net.Dial("udp", addr) // separate socket, only talks to addr
	if err != nil {
		return nil, fmt.Errorf("dialing resolver: %w", err)
	}
	defer conn.Close()

	// without this, a lost packet (or a query the resolver ignores) blocks Read forever
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("sending to resolver: %w", err)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("reading from resolver: %w", err)
	}
	return buf[:n], nil // only the bytes actually received
}
