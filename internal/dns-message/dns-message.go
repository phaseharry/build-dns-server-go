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
	Answer    []byte
}

// takes an incoming DNS request message and parses its values
func NewRequestDnsMessage(data []byte) (DNSMessage, error) {
	dnsHeader := DNSHeader{data[:HEADER_SIZE]}
	questions, err := parseQuestions(data, dnsHeader)
	if err != nil {
		return DNSMessage{}, err
	}
	dnsMessage := DNSMessage{
		Header:    dnsHeader,
		Questions: questions,
	}
	return dnsMessage, nil
}

func parseQuestions(data []byte, dnsHeader DNSHeader) ([]Question, error) {
	questions := []Question{}
	// used to store a pointer position to a value so any further labels can easily reference it
	labelCache := make(map[int]string)
	// automatically start pointer at HEADER_SIZE to skip the initial 12 bytes becoming to the header
	ptr := HEADER_SIZE

	questionCount := int(binary.BigEndian.Uint16(dnsHeader.GetQuestionCount()))

	for range questionCount {
		if ptr >= len(data) {
			break
		}

		// name processing:
		labels, iterated, err := getLabels(data, ptr, labelCache)
		if err != nil {
			return questions, err
		}
		ptr += iterated

		if ptr+3 >= len(data) {
			return questions, fmt.Errorf("Not enough bytes leftover for the Type and Class of the question")
		}

		q := Question{
			Type:  binary.BigEndian.Uint16(data[ptr : ptr+2]),
			Class: binary.BigEndian.Uint16(data[ptr+2 : ptr+4]),
			Name:  labels,
		}
		ptr += 4

		questions = append(questions, q)
	}

	if questionCount != len(questions) {
		return questions, fmt.Errorf("question count listed in headers did not match actual questions parsed")
	}

	return questions, nil
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
func getLabels(data []byte, start int, labelCache map[int]string) ([]string, int, error) {
	labels := []string{}
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
			cachedLabel, ok := labelCache[offset]
			iterated += 1
			if !ok {
				return labels, ptr + iterated, fmt.Errorf("pointer is pointing to an offset we have not seen before")
			}
			labels = append(labels, cachedLabel)

			// Note: a pointer lands on a specific label, but it means that label + every label after it until it reaches the end of that name
			// previous seen label: `abc.example.com` and some pointer scenarios
			//
			// pointer (c0 0c) lands on byte 12, label: `abc`. the expected label output for this pointer is `abc.example.com`
			//
			// pointer (c0 10) lands on byte 16, label: `example`. the expected label output for this pointer is `example.com`
			//
			// pointer (c0 18) lands on byte 18, label: `com`. the expected label output for this pointer is `com`
			//
			// to achieve this, we do the following:
			// 1. using offset to get cached label we've seen before
			// 2. use the cached label's length + the offset and see if there's another cached label to see if there's another label that can be appended to this current pointer output
			// 3. keep repeating steps 1 and 2 until we cannot find a cached offset to keep appending label values to
			return labels, start - (ptr + iterated), nil
		}
		invalid := (prefixShifted == 0b10 || prefixShifted == 0b01)
		if invalid {
			return labels, ptr + iterated, fmt.Errorf("invalid prefix byte with only one of its two leftmost bit set. either it's both set to indicate a pointer or both are not set indicating a label")
		}

		if prefix == NULL {
			break
		}

		length := int(prefix)
		if ptr+length >= len(data) {
			return labels, ptr, fmt.Errorf("invalid label processing, length value is greater than the amount of bytes remaining")
		}
		iterated += length
		label := string(data[ptr : ptr+length])

		labelCache[ptr] = label

		labels = append(labels, label)
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
		Header:    buildResponseHeader(reqMessage.Header),
		Questions: reqMessage.Questions,
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

func buildAnswers(reqMessage DNSMessage) ([]byte, error) {
	answer := make([]byte, 0, 14)

	for _, q := range reqMessage.Questions {
		data := make([]byte, 0)
		// answers are structured such that it is always prefixed by the question's payload before any of the answer's data is sent.
		// so we can just append the full question by payload before we reply to answer specific details
		data = append(data, q.Bytes()...)

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
		data = append(data, q.Bytes()...)
	}

	data = append(data, d.Answer...)

	// fmt.Printf("% x\n", data)
	fmt.Print(hex.Dump(data))
	return data
}
