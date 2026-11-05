package main

// DNS header is a fixed 12 bytes
const HEADER_SIZE = 12

type DNSMessage struct {
	data []byte
}

func NewDNSMessage(data []byte) (DNSMessage, error) {
	dnsMessage := DNSMessage{
		data,
	}

	return dnsMessage, nil
}
