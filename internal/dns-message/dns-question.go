package message

import "encoding/binary"

type Question struct {
	Name  []string
	Type  uint16
	Class uint16
}

func (q Question) Bytes() []byte {
	data := []byte{}

	for _, label := range q.Name {
		labelLength := len(label)
		data = append(data, byte(labelLength))
		data = append(data, []byte(label)...)
	}
	data = append(data, NULL)

	data = binary.BigEndian.AppendUint16(data, q.Type)
	data = binary.BigEndian.AppendUint16(data, q.Class)

	return data
}
