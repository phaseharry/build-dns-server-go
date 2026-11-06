package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// DNS header is a fixed 12 bytes
const HEADER_SIZE = 12

const NULL = byte('\x00')

type DNSMessage struct {
	Header   DNSHeader
	Question []byte
	Answer   []byte
	Data     []byte
}

// takes an incoming DNS request message and parses its values
func NewRequestDnsMessage(data []byte) (DNSMessage, error) {
	dnsMessage := DNSMessage{
		Header: DNSHeader{data[:HEADER_SIZE]},
		Data:   data,
	}
	return dnsMessage, nil
}

// used for building a response DNS
func NewResponseDnsMessage(reqHeader DNSHeader) (DNSMessage, error) {
	dnsMessage := DNSMessage{
		Header:   buildResponseHeader(reqHeader),
		Question: buildQuestion(),
		Answer:   buildAnswer(),
	}
	return dnsMessage, nil
}

func buildResponseHeader(reqHeader DNSHeader) DNSHeader {
	header := make([]byte, 0, HEADER_SIZE)
	// 1st & 2nd bytes
	header = append(header, reqHeader.GetID()...)

	// 3rd byte
	var thirdByte byte
	// bitwise OR to add a bit into the byte
	// adding the response bit
	thirdByte |= 0b10000000
	// get OPCODE and then shift it left 3 bits
	thirdByte |= (0b01111000 & (reqHeader.GetOpCode() << 3))
	// recursive bit
	if reqHeader.IsRecursiveDesired() {
		thirdByte |= 0b00000001
	}
	header = append(header, thirdByte)

	// 4th byte
	var fourthByte byte
	// if OPCODE != 0, set the response code to 4, otherwise keep it 0
	if reqHeader.GetOpCode() != 0 {
		fourthByte |= 0b00000100
	}
	header = append(header, fourthByte)
	// 5th & 6th byte
	header = append(header, reqHeader.GetQuestionCount()...)
	// 7th & 8th byte
	header = append(header, reqHeader.GetAnswerCount()...)
	// 9th & 10th byte
	header = append(header, reqHeader.GetAuthorityCount()...)
	// 11th & 12th byte
	header = append(header, reqHeader.GetAdditionalCount()...)

	return DNSHeader{header}
}

func buildQuestion() []byte {
	// domain name 1 byte for size & the rest being the actual domain name
	domain := []byte("codecrafters")
	domainLength := len(domain)
	extension := []byte("io")
	extensionLength := len(extension)

	// Type: 2-byte int; the type of record (1 for an A record, 5 for a CNAME record etc., full list here)
	questionType := make([]byte, 0, 2)
	questionType = binary.BigEndian.AppendUint16(questionType, 1)

	// Class: 2-byte int; usually set to 1 (full list here)
	class := make([]byte, 0, 2)
	class = binary.BigEndian.AppendUint16(class, 1)

	// adding 4 to include the 2 length bytes for domain & extension and their null bytes
	questionLength := domainLength + extensionLength + 4 + len(questionType) + len(class)
	question := make([]byte, 0, questionLength)

	question = append(question, byte(domainLength))
	question = append(question, domain...)
	question = append(question, byte(extensionLength))
	question = append(question, extension...)
	question = append(question, NULL)

	question = append(question, questionType...)
	question = append(question, class...)

	return question
}

func buildAnswer() []byte {
	answer := make([]byte, 0, 14)

	// domain name 1 byte for size & the rest being the actual domain name
	domain := []byte("codecrafters")
	domainLength := len(domain)
	extension := []byte("io")
	extensionLength := len(extension)

	// Type: 2-byte int; the type of record (1 for an A record, 5 for a CNAME record etc., full list here)
	questionType := make([]byte, 0, 2)
	questionType = binary.BigEndian.AppendUint16(questionType, 1)

	// Class: 2-byte int; usually set to 1 (full list here)
	class := make([]byte, 0, 2)
	class = binary.BigEndian.AppendUint16(class, 1)

	// TTL: 4 bytes
	ttl := make([]byte, 0, 4)
	ttl = binary.BigEndian.AppendUint32(ttl, 60)

	// Length: 2 bytes encoded as a 2-byte big-endian int (corresponds to the length of the RDATA field)
	rDataLength := make([]byte, 0, 2)
	rDataLength = binary.BigEndian.AppendUint16(rDataLength, 4)

	// Data: IPv4 address encoded as a 4-byte big-endian int. For example: \x08\x08\x08\x08 (that's 8.8.8.8 encoded as a 4-byte integer)
	data := []byte{0x08, 0x08, 0x08, 0x08}

	answer = append(answer, byte(domainLength))
	answer = append(answer, domain...)
	answer = append(answer, byte(extensionLength))
	answer = append(answer, extension...)
	answer = append(answer, NULL)

	answer = append(answer, questionType...)
	answer = append(answer, class...)
	answer = append(answer, ttl...)
	answer = append(answer, rDataLength...)
	answer = append(answer, data...)

	return answer
}

func (d *DNSMessage) GetData() []byte {
	data := []byte{}

	data = append(data, d.Header.data...)
	data = append(data, d.Question...)
	data = append(data, d.Answer...)

	// fmt.Printf("% x\n", data)
	fmt.Print(hex.Dump(data))
	return data
}

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
