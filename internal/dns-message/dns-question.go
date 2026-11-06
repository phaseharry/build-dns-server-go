package message

import (
	"bytes"
	"fmt"
)

type Question struct {
	data []byte
}

// Type: 2-byte int; the type of record (1 for an A record, 5 for a CNAME record etc., full list here)
func (q Question) GetType() ([]byte, error) {
	questionType := make([]byte, 0, 2)

	_, after, found := bytes.Cut(q.data, []byte{NULL})
	if !found {
		return questionType, fmt.Errorf("Malformed, unable to find NULL byte in question.")
	}
	if len(after) < 2 {
		return questionType, fmt.Errorf("Malformed, missing 2 bytes for the question type.")
	}
	questionType = append(questionType, after[:2]...)
	return questionType, nil
}

// Class: 2-byte int; usually set to 1 (full list here)
func (q Question) GetClass() ([]byte, error) {
	class := make([]byte, 0, 2)

	_, after, found := bytes.Cut(q.data, []byte{NULL})
	if !found {
		return class, fmt.Errorf("Malformed, unable to find NULL byte in question.")
	}
	if len(after) < 4 {
		return class, fmt.Errorf("Malformed, missing 2 bytes for the class.")
	}
	class = append(class, after[2:4]...)
	return class, nil
}
