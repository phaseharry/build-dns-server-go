package message

import (
	"encoding/binary"
	"fmt"
)

// DNS header is a fixed 12 bytes
const HEADER_SIZE = 12

// the 3rd and 4th bytes each pack several fields together (leftmost bit first):
//
//	3rd byte: | QR | OPCODE (4 bits) | AA | TC | RD |
//	4th byte: | RA |   Z (3 bits)    | RCODE (4 bits) |
type DNSHeader struct {
	// ID is the first 16 bit (2 bytes) of the header
	ID uint16

	// Query / Response indicator. 1 bit value indicating either or not it is a reply or query packet.
	// true == 1 == reply
	// false == 0 == query
	// This bit is located on the 3rd byte
	QRIndicator bool

	// Operation Code. 4 bit value. specifies the kind of query the message is.
	// range: [0, 15]
	// located in 3rd byte
	OpCode uint8

	// Authoritative Answer (AA). 1 bit value.
	// 1 == true == responding server "owns" the domain
	// 0 == false == not the above^
	// located in 3rd byte
	AuthoritativeAnswer bool

	// Truncation (TC). 1 bit value.
	// 1 == true == message is larger than 512 bytes.
	// 0 == false == not the above^
	// located in 3rd byte
	Truncated bool

	// Recursion Desired (RD). 1 bit value.
	// 1 == true == server should recursively resolve this query.
	// 0 == false == not the above^
	// located in 3rd byte
	RecursionDesired bool

	// Recursion Available (RA). 1 bit value.
	// 1 == true == server sets this if recursion is available.
	// 0 == false == not the above^
	// located in 4th byte
	RecursionAvailable bool

	// Reserved (Z). 3 bit value. Used by DNSSEC queries. At inception, it was reserved for future use.
	// located in 4th byte
	Reserved uint8

	// Response Code (RCODE). 4 bit value. Response code indicating the status of the response.
	// located in 4th byte
	ResponseCode uint8

	// Question Count (QDCOUNT). 2 bytes. Number of questions in the Question section.
	// located in 5th & 6th byte
	QuestionCount uint16

	// Answer Record Count (ANCOUNT). 2 bytes. Number of records in the Answer section.
	// located in 7th & 8th byte
	AnswerCount uint16

	// Authority Record Count (NSCOUNT). 2 bytes. Number of records in the Authority section.
	// located in 9th & 10th byte
	AuthorityCount uint16

	// Additional Record Count (ARCOUNT). 2 bytes. Number of records in the Additional section.
	// located in 11th & 12th byte
	AdditionalCount uint16
}

// parses the first 12 bytes of a DNS message into a DNSHeader
func parseHeader(data []byte) (DNSHeader, error) {
	if len(data) < HEADER_SIZE {
		return DNSHeader{}, fmt.Errorf("not enough bytes for a DNS header, need %d, got %d", HEADER_SIZE, len(data))
	}

	thirdByte := data[2]
	fourthByte := data[3]

	header := DNSHeader{
		ID: binary.BigEndian.Uint16(data[0:2]),

		// for the 1 bit fields, bitwise AND the byte with a mask that only has that field's bit set.
		// if masked == 0 then that bit isn't set
		QRIndicator: thirdByte&0b10000000 != 0,
		// shift rightward 3 bits to get rid of the AA, TC, and RD bits
		// then bitwise AND with 0b00001111 so only the OPCODE bits are kept (drops the QR bit)
		OpCode:              (thirdByte >> 3) & 0b1111,
		AuthoritativeAnswer: thirdByte&0b00000100 != 0,
		Truncated:           thirdByte&0b00000010 != 0,
		RecursionDesired:    thirdByte&0b00000001 != 0,

		RecursionAvailable: fourthByte&0b10000000 != 0,
		// shift rightward 4 bits to get rid of the RCODE bits
		// then bitwise AND with 0b00000111 so only the 3 Z bits are kept (drops the RA bit)
		Reserved: (fourthByte >> 4) & 0b111,
		// no need to shift as the response code is already the lowest bit positions.
		// just need to bitwise AND it with 0b00001111 to get the actual value of the code
		ResponseCode: fourthByte & 0b1111,

		QuestionCount:   binary.BigEndian.Uint16(data[4:6]),
		AnswerCount:     binary.BigEndian.Uint16(data[6:8]),
		AuthorityCount:  binary.BigEndian.Uint16(data[8:10]),
		AdditionalCount: binary.BigEndian.Uint16(data[10:12]),
	}
	return header, nil
}

// packs the header's values back into its 12 byte wire format
func (h DNSHeader) Bytes() []byte {
	data := make([]byte, 0, HEADER_SIZE)

	// 1st & 2nd bytes
	data = binary.BigEndian.AppendUint16(data, h.ID)

	// 3rd byte
	// bitwise OR to set a field's bits in the byte. multi-bit fields get masked to their width
	// before being shifted into place, so an out of range value can't spill into a neighboring field
	var thirdByte byte
	if h.QRIndicator {
		thirdByte |= 0b10000000
	}
	thirdByte |= (h.OpCode & 0b1111) << 3
	if h.AuthoritativeAnswer {
		thirdByte |= 0b00000100
	}
	if h.Truncated {
		thirdByte |= 0b00000010
	}
	if h.RecursionDesired {
		thirdByte |= 0b00000001
	}
	data = append(data, thirdByte)

	// 4th byte
	var fourthByte byte
	if h.RecursionAvailable {
		fourthByte |= 0b10000000
	}
	fourthByte |= (h.Reserved & 0b111) << 4
	fourthByte |= h.ResponseCode & 0b1111
	data = append(data, fourthByte)

	// 5th - 12th bytes
	data = binary.BigEndian.AppendUint16(data, h.QuestionCount)
	data = binary.BigEndian.AppendUint16(data, h.AnswerCount)
	data = binary.BigEndian.AppendUint16(data, h.AuthorityCount)
	data = binary.BigEndian.AppendUint16(data, h.AdditionalCount)

	return data
}

// manually modifying a copy of the DNSHeader with a new question count
func (h DNSHeader) WithQuestionCount(count int) DNSHeader {
	h.QuestionCount = uint16(count)
	return h
}
