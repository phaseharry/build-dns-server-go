package message

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type DNSMessage struct {
	Header    DNSHeader
	Questions []Question
	Answer    []byte
}

// takes an incoming DNS request message and parses its values
func NewRequestDnsMessage(data []byte) (DNSMessage, error) {
	dnsHeader := DNSHeader{data[:HEADER_SIZE]}
	questions, err := parseQuestions(data[HEADER_SIZE:], dnsHeader)
	if err != nil {
		return DNSMessage{}, err
	}
	dnsMessage := DNSMessage{
		Header:    dnsHeader,
		Questions: questions,
	}
	return dnsMessage, nil
}

func parseQuestions(remaining []byte, dnsHeader DNSHeader) ([]Question, error) {
	questions := []Question{}
	ptr := 0

	questionCount := int(binary.BigEndian.Uint16(dnsHeader.GetQuestionCount()))

	for range questionCount {
		question := []byte{}

		if ptr >= len(remaining) {
			break
		}

		// label: domain processing
		domainLength := remaining[ptr]
		ptr += 1
		// appending the domain length
		question = append(question, domainLength)

		expectedEnd := ptr + int(domainLength)
		for ptr < expectedEnd && ptr < len(remaining) {
			question = append(question, remaining[ptr])
			ptr += 1
		}
		if ptr != expectedEnd || ptr >= len(remaining) {
			return questions, fmt.Errorf("Not enough bytes given domain length")
		}

		// label: extension processing
		extensionLength := remaining[ptr]
		question = append(question, extensionLength)

		ptr += 1
		// appending the extension length
		expectedEnd = ptr + int(extensionLength)
		for ptr < expectedEnd && ptr < len(remaining) {
			question = append(question, remaining[ptr])
			ptr += 1
		}
		if ptr != expectedEnd || ptr >= len(remaining) {
			return questions, fmt.Errorf("Not enough bytes given extension length")
		}

		if remaining[ptr] != NULL {
			return questions, fmt.Errorf("Unexpected byte where NULL byte should be to terminate label")
		}
		question = append(question, remaining[ptr])
		ptr += 1

		if ptr+3 >= len(remaining) {
			return questions, fmt.Errorf("Not enough bytes leftover for the Type and Class of the question")
		}

		question = append(question, remaining[ptr:ptr+4]...)
		ptr += 4

		questions = append(questions, Question{
			question,
		})
	}

	if questionCount != len(questions) {
		return questions, fmt.Errorf("question count listed in headers did not match actual questions parsed")
	}

	return questions, nil
}

// used for building a response DNS
func NewResponseDnsMessage(reqMessage DNSMessage) (DNSMessage, error) {
	questions, err := buildQuestions(reqMessage)
	if err != nil {
		return DNSMessage{}, err
	}
	answers, err := buildAnswers(reqMessage)
	if err != nil {
		return DNSMessage{}, err
	}

	dnsMessage := DNSMessage{
		Header:    buildResponseHeader(reqMessage.Header),
		Questions: questions,
		Answer:    answers,
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
	header = append(header, []byte{1, 0}...)
	// 9th & 10th byte
	header = append(header, reqHeader.GetAuthorityCount()...)
	// 11th & 12th byte
	header = append(header, reqHeader.GetAdditionalCount()...)

	return DNSHeader{header}
}

func buildQuestions(reqMessage DNSMessage) ([]Question, error) {
	questions := make([]Question, 0, len(reqMessage.Questions))

	for _, q := range reqMessage.Questions {
		data := make([]byte, 0, len(q.data))

		data = append(data, getLabel(q)...)

		questionType, err := q.GetType()
		if err != nil {
			return questions, err
		}
		data = append(data, questionType...)

		class, err := q.GetClass()
		if err != nil {
			return questions, err
		}
		data = append(data, class...)

		questions = append(questions, Question{data})
	}

	return questions, nil
}

func buildAnswers(reqMessage DNSMessage) ([]byte, error) {
	answer := make([]byte, 0, 14)

	for _, q := range reqMessage.Questions {
		data := make([]byte, 0, len(q.data))

		data = append(data, getLabel(q)...)

		questionType, err := q.GetType()
		if err != nil {
			return answer, err
		}
		data = append(data, questionType...)

		class, err := q.GetClass()
		if err != nil {
			return answer, err
		}
		data = append(data, class...)

		// TTL: 4 bytes
		ttl := make([]byte, 0, 4)
		ttl = binary.BigEndian.AppendUint32(ttl, 60)
		data = append(data, ttl...)

		// Length: 2 bytes encoded as a 2-byte big-endian int (corresponds to the length of the RDATA field)
		rDataLength := make([]byte, 0, 2)
		rDataLength = binary.BigEndian.AppendUint16(rDataLength, 4)
		data = append(data, rDataLength...)

		// Data: IPv4 address encoded as a 4-byte big-endian int. For example: \x08\x08\x08\x08 (that's 8.8.8.8 encoded as a 4-byte integer)
		data = append(data, []byte{0x08, 0x08, 0x08, 0x08}...)

		answer = append(answer, data...)
	}

	return answer, nil
}

func (d *DNSMessage) GetData() []byte {
	data := []byte{}

	data = append(data, d.Header.data...)

	for _, q := range d.Questions {
		data = append(data, q.data...)
	}

	data = append(data, d.Answer...)

	// fmt.Printf("% x\n", data)
	fmt.Print(hex.Dump(data))
	return data
}
