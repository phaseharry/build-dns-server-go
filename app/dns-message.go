package main

// DNS header is a fixed 12 bytes
const HEADER_SIZE = 12

type DNSMessage struct {
	Data []byte
}

// takes an incoming DNS request message and parses its values
func NewRequestDnsMessage(data []byte) (DNSMessage, error) {
	dnsMessage := DNSMessage{
		data,
	}
	return dnsMessage, nil
}

// used for building a response DNS
func NewResponseDnsMessage() (DNSMessage, error) {
	data := make([]byte, HEADER_SIZE)
	// manually building it as of now with hardcoded values to test expected values

	// header is the first 12 bytes
	// PackageIdentifier (id) (Big Endian order) (2 bytes), hardcoded to 1234
	data = append(data, []byte{0x04, 0xD2}...)

	// 1 byte that contains a lot of info
	// Query/Response Indicator (QR)	1 bit	1 for a reply packet, 0 for a question packet.
	// Operation Code (OPCODE)	4 bits	Specifies the kind of query in a message.
	// Authoritative Answer (AA)	1 bit	1 if the responding server "owns" the domain queried, i.e., it's authoritative
	// Truncation (TC)	1 bit	1 if the message is larger than 512 bytes.
	// Recursion Desired (RD)	1 bit	Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
	data = append(data, byte(0b10000000))

	// another byte
	// Recursion Available (RA)	1 bit	Server sets this to 1 to indicate that recursion is available.
	// Reserved (Z)	3 bits	Used by DNSSEC queries. At inception, it was reserved for future use.
	// Response Code (RCODE)	4 bits	Response code indicating the status of the response.
	data = append(data, byte(0b00000000))

	// 2 bytes for Question Count
	data = append(data, []byte{0, 0}...)

	// 2 bytes for Answer Record Count
	data = append(data, []byte{0, 0}...)

	// 2 bytes for Authority Record Count
	data = append(data, []byte{0, 0}...)

	// 2 bytes for Additional Record Count
	data = append(data, []byte{0, 0}...)

	dnsMessage := DNSMessage{
		data,
	}
	return dnsMessage, nil
}
