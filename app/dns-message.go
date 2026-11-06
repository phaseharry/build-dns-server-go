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
	Header   []byte
	Question []byte
	Data     []byte
}

// takes an incoming DNS request message and parses its values
func NewRequestDnsMessage(data []byte) (DNSMessage, error) {
	dnsMessage := DNSMessage{
		Header: data[:HEADER_SIZE],
		Data:   data,
	}
	return dnsMessage, nil
}

// used for building a response DNS
func NewResponseDnsMessage() (DNSMessage, error) {
	dnsMessage := DNSMessage{
		Header:   buildHeader(1), // harding to 1 question as of now
		Question: buildQuestion(),
	}
	return dnsMessage, nil
}

func buildHeader(questionCount int) []byte {
	header := make([]byte, 0, HEADER_SIZE)
	// manually building it as of now with hardcoded values to test expected values

	// header is the first 12 bytes
	// PackageIdentifier (id) (Big Endian order) (2 bytes), hardcoded to 1234
	header = append(header, []byte{0x04, 0xD2}...)

	// 1 byte that contains a lot of info
	// Query/Response Indicator (QR)	1 bit	1 for a reply packet, 0 for a question packet.
	// Operation Code (OPCODE)	4 bits	Specifies the kind of query in a message.
	// Authoritative Answer (AA)	1 bit	1 if the responding server "owns" the domain queried, i.e., it's authoritative
	// Truncation (TC)	1 bit	1 if the message is larger than 512 bytes.
	// Recursion Desired (RD)	1 bit	Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
	header = append(header, byte(0b10000000))

	// another byte
	// Recursion Available (RA)	1 bit	Server sets this to 1 to indicate that recursion is available.
	// Reserved (Z)	3 bits	Used by DNSSEC queries. At inception, it was reserved for future use.
	// Response Code (RCODE)	4 bits	Response code indicating the status of the response.
	header = append(header, byte(0b00000000))

	// 2 bytes for Question Count (Big Endian)
	questionCountSlot := make([]byte, 2)
	binary.BigEndian.PutUint16(questionCountSlot, uint16(questionCount))
	header = append(header, questionCountSlot...)

	// 2 bytes for Answer Record Count
	header = append(header, []byte{0, 0}...)

	// 2 bytes for Authority Record Count
	header = append(header, []byte{0, 0}...)

	// 2 bytes for Additional Record Count
	header = append(header, []byte{0, 0}...)

	return header
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

func (d *DNSMessage) GetData() []byte {
	data := []byte{}

	data = append(data, d.Header...)
	data = append(data, d.Question...)

	// fmt.Printf("% x\n", data)
	fmt.Print(hex.Dump(data))
	return data
}
