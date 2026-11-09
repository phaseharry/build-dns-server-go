package message

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const NULL = byte('\x00')

type DNSMessage struct {
	Header    DNSHeader
	Questions []Question
	Answers   []Answer
}

// takes an incoming DNS request message and parses its values
func ParseDNSMessage(data []byte) (DNSMessage, error) {
	dnsHeader, err := parseHeader(data)
	if err != nil {
		return DNSMessage{}, err
	}
	questions, answerPtr, err := parseQuestions(data, dnsHeader)
	if err != nil {
		return DNSMessage{}, err
	}
	answers, err := parseAnswer(data, answerPtr, dnsHeader)
	if err != nil {
		return DNSMessage{}, err
	}

	dnsMessage := DNSMessage{
		Header:    dnsHeader,
		Questions: questions,
		Answers:   answers,
	}
	return dnsMessage, nil
}

func parseQuestions(data []byte, dnsHeader DNSHeader) ([]Question, int, error) {
	questions := []Question{}
	// automatically start pointer at HEADER_SIZE to skip the initial 12 bytes becoming to the header
	ptr := HEADER_SIZE

	questionCount := int(dnsHeader.QuestionCount)

	for range questionCount {
		if ptr >= len(data) {
			return questions, ptr, fmt.Errorf("Overflow ptr %d while having %d questions left to parse.", ptr, questionCount-len(questions))
		}

		// name processing:
		labels, iterated, err := getLabels(data, ptr)
		if err != nil {
			return questions, ptr, err
		}
		ptr += iterated

		if ptr+3 >= len(data) {
			return questions, ptr, fmt.Errorf("Not enough bytes leftover for the Type and Class of the question")
		}

		q := Question{
			Name:  labels,
			Type:  binary.BigEndian.Uint16(data[ptr : ptr+2]),
			Class: binary.BigEndian.Uint16(data[ptr+2 : ptr+4]),
		}
		ptr += 4

		questions = append(questions, q)
	}

	if questionCount != len(questions) {
		return questions, ptr, fmt.Errorf("question count listed in headers did not match actual questions parsed")
	}

	return questions, ptr, nil
}

func parseAnswer(data []byte, startPtr int, dnsHeader DNSHeader) ([]Answer, error) {
	answerCount := int(dnsHeader.AnswerCount)
	answers := make([]Answer, 0, answerCount)

	if answerCount > 0 && startPtr >= len(data) {
		return answers, fmt.Errorf("Overflow starting answer ptr %d while having %d answers to parse.", startPtr, answerCount)
	}

	ptr := startPtr

	for range answerCount {
		if ptr >= len(data) {
			return answers, fmt.Errorf("Overflow ptr %d while having %d answers left to parse.", ptr, answerCount-len(answers))
		}

		// name processing:
		labels, iterated, err := getLabels(data, ptr)
		if err != nil {
			return answers, err
		}
		ptr += iterated

		if ptr+10 > len(data) {
			return answers, fmt.Errorf("Not enough bytes leftover for the Type, Class, TTL, DataLength of the answer")
		}

		answerType := binary.BigEndian.Uint16(data[ptr : ptr+2])
		answerClass := binary.BigEndian.Uint16(data[ptr+2 : ptr+4])
		ttl := binary.BigEndian.Uint32(data[ptr+4 : ptr+8])
		dataLength := int(binary.BigEndian.Uint16(data[ptr+8 : ptr+10]))
		ptr += 10

		if ptr+dataLength > len(data) {
			return answers, fmt.Errorf("Not enough bytes leftover at ptr %d and a data length of %d to parse the data of the answer", ptr, dataLength)
		}
		answerData := data[ptr : ptr+dataLength]
		ptr += dataLength

		a := Answer{
			Name:  labels,
			Type:  answerType,
			Class: answerClass,
			TTL:   ttl,
			Data:  answerData,
		}
		answers = append(answers, a)
	}

	return answers, nil
}

// name processing. the name is always the first field of a question and is made up of labels.
// the number of labels varies, and the name is encoded in one of three forms:
// 1. all labels, ending with the NULL byte `00`.
// 2. only a pointer.
// 3. some labels, then a pointer.
// a pointer always ends the name, so no `00` follows it in forms 2 and 3. TYPE/CLASS start
// right after the pointer's 2 bytes.
//
// each label has the format <1 byte><x bytes...>, where the first byte is the length `x` (1-63).
// multiple labels sit back to back: <1 byte><x bytes...><1 byte><x bytes...>
//
// a pointer is 2 bytes: the top 2 bits are `11` and the other 14 bits are a byte offset counted
// from the start of the message (byte 0 of the header). it points to where an earlier run of
// labels starts (e.g. in an earlier question), and the name continues from there until that
// run's `00`. the target can itself be, or end in, another pointer, so keep following until `00`.
//
// only check what a byte is at a length position (jump from length to length, don't scan for `00`):
//
//	00xxxxxx -> label length, where 00000000 is the NULL byte that ends the name
//	11xxxxxx -> pointer
//	01xxxxxx, 10xxxxxx -> reserved, treat as an error
func getLabels(data []byte, start int) ([]string, int, error) {
	labels := []string{}
	if start >= len(data) {
		return labels, 0, fmt.Errorf("invalid start index being greater or equal to data length, start: %d, length: %d", start, len(data))
	}

	ptr := start

	for ptr < len(data) {
		// get the first byte to see if it's a label or a pointer.
		// if it's leftmost 2 bits are both set, then it is a pointer, otherwise it is the size byte and what follows is a label
		prefix := data[ptr]
		iterated := 1

		// check if this byte is a pointer byte by shifting the leftmost 2 bits right 6 times
		// and comparing it with 0b00000011 and seeing if it matches.
		// if those 2 bits are 11 then it is a pointer and references an earlier label
		prefixShifted := prefix >> 6
		isPointer := (prefixShifted & 0b11) == 0b11
		if isPointer {
			if ptr+1 >= len(data) {
				return labels, ptr, fmt.Errorf("not enough bytes after pointer bits to get offset")
			}
			// 1. removing the first 2 pointer indicator bytes to get the first half of the size bytes.
			// 2. convert it to an int type so it can store larger values and then shift leftwards 8 bits since the bytes are ordered in Big Endian order. 0b00111111 -> 0b0011111100000000
			// 3. order the newly shifted int value with the 2nd byte to get the offset. 0b0011111100000000 <- 0b0011111101011001
			// assuming, the first byte is 0b11111111 and the second byte is 0b01011001
			offset := int(prefix&0b00111111)<<8 | int(data[ptr+1])
			// Note: a pointer lands on a specific label, but it means that label + every label after it until it reaches the end of that name
			// previous seen label: `abc.example.com` and some pointer scenarios
			//
			// pointer (c0 0c) lands on byte 12, label: `abc`. the expected label output for this pointer is `abc.example.com`
			//
			// pointer (c0 10) lands on byte 16, label: `example`. the expected label output for this pointer is `example.com`
			//
			// pointer (c0 18) lands on byte 24, label: `com`. the expected label output for this pointer is `com`
			//
			// to achieve this, we do the following:
			// we will call getLabels recursively when it sees a pointer to start iterating through labels at a different question's name to pull it to the current question's name
			referencedLabels, _, err := getLabels(data, offset)
			if err != nil {
				return labels, ptr - start, fmt.Errorf("error while resolving label pointer: %w", err)
			}
			iterated += 1
			labels = append(labels, referencedLabels...)
			return labels, (ptr + iterated) - start, nil
		}
		invalid := (prefixShifted == 0b10 || prefixShifted == 0b01)
		if invalid {
			return labels, (ptr + iterated) - start, fmt.Errorf("reserved label type at offset %d: 0x%02x (top two bits must be 00 for a label or 11 for a pointer)", ptr, prefix)
		}

		if prefix == NULL {
			// count the NULL byte itself so the caller lands on TYPE instead of on the NULL
			ptr += iterated
			break
		}

		length := int(prefix)
		if ptr+length >= len(data) {
			return labels, ptr - start, fmt.Errorf("invalid label processing, length value is greater than the amount of bytes remaining")
		}
		iterated += length
		labels = append(labels, string(data[ptr+1:ptr+1+length]))
		ptr += iterated
	}
	return labels, ptr - start, nil
}

// used for building a response DNS
func NewResponseDnsMessage(reqMessage DNSMessage) (DNSMessage, error) {
	answers, err := buildAnswers(reqMessage)
	if err != nil {
		return DNSMessage{}, err
	}

	dnsMessage := DNSMessage{
		Header:    BuildResponseHeader(reqMessage.Header, uint16(len(answers))),
		Questions: reqMessage.Questions,
		Answers:   answers,
	}
	return dnsMessage, nil
}

func BuildResponseHeader(reqHeader DNSHeader, answerCount uint16) DNSHeader {
	header := DNSHeader{
		ID:               reqHeader.ID,
		QRIndicator:      true,
		OpCode:           reqHeader.OpCode,
		RecursionDesired: reqHeader.RecursionDesired,
		QuestionCount:    reqHeader.QuestionCount,
		AnswerCount:      answerCount,
		AuthorityCount:   reqHeader.AuthorityCount,
		AdditionalCount:  reqHeader.AdditionalCount,
	}

	// if OPCODE != 0, set the response code to 4, otherwise keep it 0
	if reqHeader.OpCode != 0 {
		header.ResponseCode = 4
	}

	return header
}

func buildAnswers(reqMessage DNSMessage) ([]Answer, error) {
	answers := make([]Answer, 0, len(reqMessage.Questions))

	for _, q := range reqMessage.Questions {
		answers = append(answers, Answer{
			// an answer's name, type, and class are laid out the same way as a question's.
			// here each question gets answered for the same name, type, and class it asked about
			Name:  q.Name,
			Type:  q.Type,
			Class: q.Class,
			TTL:   60,
			// Data: IPv4 address encoded as a 4-byte big-endian int. For example: \x08\x08\x08\x08 (that's 8.8.8.8 encoded as a 4-byte integer)
			Data: []byte{0x08, 0x08, 0x08, 0x08},
		})
	}

	return answers, nil
}

func (d *DNSMessage) Bytes() []byte {
	data := []byte{}

	data = append(data, d.Header.Bytes()...)

	for _, q := range d.Questions {
		data = append(data, q.Bytes()...)
	}

	for _, a := range d.Answers {
		data = append(data, a.Bytes()...)
	}

	// fmt.Printf("% x\n", data)
	fmt.Print(hex.Dump(data))
	return data
}
