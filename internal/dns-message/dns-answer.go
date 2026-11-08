package message

import "encoding/binary"

type Answer struct {
	// the domain name this record is for, stored as its labels. encoded the same way as a question's name
	Name []string
	// Type (TYPE). 2 bytes. the kind of record, e.g. 1 == A record
	Type uint16
	// Class (CLASS). 2 bytes. usually 1 == IN (internet)
	Class uint16
	// Time-To-Live (TTL). 4 bytes. how many seconds the record can be cached before it should be requeried
	TTL uint32
	// Data (RDATA). variable length, depends on the record type. e.g. an A record's data is a 4 byte IPv4 address.
	// the 2 byte Length (RDLENGTH) field that comes before it isn't stored, Bytes() writes it out as len(Data)
	Data []byte
}

func (a Answer) Bytes() []byte {
	data := []byte{}

	for _, label := range a.Name {
		labelLength := len(label)
		data = append(data, byte(labelLength))
		data = append(data, []byte(label)...)
	}
	data = append(data, NULL)

	data = binary.BigEndian.AppendUint16(data, a.Type)
	data = binary.BigEndian.AppendUint16(data, a.Class)
	data = binary.BigEndian.AppendUint32(data, a.TTL)
	data = binary.BigEndian.AppendUint16(data, uint16(len(a.Data)))
	data = append(data, a.Data...)

	return data
}
