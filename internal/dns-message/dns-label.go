package message

const NULL = byte('\x00')

func buildLabel(domain, extension string) []byte {
	// domain and extension both have a byte prefixed to the domain values
	// to state the length of the value
	domainLength, extensionLength := len(domain), len(extension)
	// adding 3 to include the 2 length bytes for domain & extension and their null byte
	labelLength := domainLength + extensionLength + 3
	label := make([]byte, 0, labelLength)

	label = append(label, byte(domainLength))
	label = append(label, []byte(domain)...)
	label = append(label, byte(extensionLength))
	label = append(label, []byte(extension)...)
	label = append(label, NULL)

	return label
}

func getLabel(question Question) []byte {
	label := []byte{}
	ptr := 0
	seenNull := false

	// first null byte should indicate the end of the label section
	for ptr < len(question.data) && !seenNull {
		val := question.data[ptr]
		if val == NULL {
			seenNull = true
		}
		label = append(label, val)
		ptr += 1
	}

	return label
}
