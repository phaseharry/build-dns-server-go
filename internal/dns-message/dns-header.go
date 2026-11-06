package message

// DNS header is a fixed 12 bytes
const HEADER_SIZE = 12

type DNSHeader struct {
	data []byte // should only contain a fix sized 12 bytes
}

// ID is the first 16 bit (2 bytes) of the header
func (h DNSHeader) GetID() []byte {
	return h.data[:2]
}

// Query / Request indicator. 1 bit value indicating either or not it is a reply or query packet.
// true == 1 == reply
// false == 0 == query
// This bit is located on the 3rd byte
func (h DNSHeader) GetQRIndicator() bool {
	b := h.data[2]
	// doing bitwise AND to compare the 3rd byte to 10000000
	// and seeing if the QR bit is set. if masked == 0 then that bit isn't set
	// so it is a query packet
	masked := b & 0b10000000
	return masked != 0
}

// Operation Code. 4 bit value. specifies the kind of query the message is.
// range: [0, 15]
// located in 3rd byte
func (h DNSHeader) GetOpCode() byte {
	b := h.data[2]
	// shift rightward 3 bits to get rid of the AA, TC, and RD bits
	// then bitwise AND with 0b00001111 so only the OPCODE bits are AND'ed to get us the OPCODE's value
	b = (b >> 3) & 0b1111
	return b
}

// Authoritative Answer (AA). 1 bit value.
// 1 == true == responding server "owns" the domain
// 0 == false == not the above^
// located in 3rd byte
func (h DNSHeader) GetAuthoritativeAnswer() bool {
	b := h.data[2]
	masked := b & 0b00000100
	return masked != 0
}

// Truncation (TC). 1 bit value.
// 1 == true == message is larger than 512 bytes.
// 0 == false == not the above^
// located in 3rd byte
func (h DNSHeader) IsTruncated() bool {
	b := h.data[2]
	masked := b & 0b00000010
	return masked != 0
}

// Recursion Desired (RD). 1 bit value.
// 1 == true == server should recursively resolve this query.
// 0 == false == not the above^
// located in 3rd byte
func (h DNSHeader) IsRecursiveDesired() bool {
	b := h.data[2]
	masked := b & 0b00000001
	return masked != 0
}

// Recursion Available (RA). 1 bit value.
// 1 == true == server sets this if recursion is available.
// 0 == false == not the above^
// located in 4th byte
func (h DNSHeader) IsRecursionAvailable() bool {
	b := h.data[3]
	masked := b & 0b10000000
	return masked != 0
}

// Reserved (Z). 3 bit value. Used by DNSSEC queries. At inception, it was reserved for future use.
// located in 4th byte
func (h DNSHeader) GetReserved() int {
	b := h.data[3]
	// shift 4 bits rightward and using bitwise AND to only calculate the 3 bits
	b = (b >> 4) & 0b1111
	return int(b)
}

// Response Code (RCODE). 4 bit value. Response code indicating the status of the response.
// located in 4th byte
func (h DNSHeader) GetResponseCode() int {
	b := h.data[3]
	// no need to shift as the response code is already the lowest bit positions.
	// just need to bitwise AND it with 0b00001111 to get the actual value of the code
	b = b & 0b1111
	return int(b)
}

// Question Count (QDCOUNT). 2 bytes. Number of questions in the Question section.
// located in 5th & 6th byte
func (h DNSHeader) GetQuestionCount() []byte {
	return h.data[4:6]
}

// Answer Record Count (ANCOUNT). 2 bytes. Number of records in the Answer section.
// located in 7th & 8th byte
func (h DNSHeader) GetAnswerCount() []byte {
	return h.data[6:8]
}

// Authority Record Count (NSCOUNT). 2 bytes. Number of records in the Authority section.
// located in 9th & 10th byte
func (h DNSHeader) GetAuthorityCount() []byte {
	return h.data[8:10]
}

// Additional Record Count (ARCOUNT). 2 bytes. Number of records in the Additional section.
// located in 11th & 12th byte
func (h DNSHeader) GetAdditionalCount() []byte {
	return h.data[10:12]
}
