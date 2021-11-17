package dnsparser

type Flag struct {
	QueryResponseFlag       byte
	OperationCode           byte
	AuthoritativeAnswerFlag byte
	TruncationFlag          byte
	RecursionDesired        byte
	RecursionAvailable      byte
	ResponseCode            byte
}

func (f Flag) OperationCodeString() string {
	switch f.OperationCode {
	case 0:
		return "QUERY"
	case 1:
		return "IQUERY"
	case 2:
		return "STATUS"
	case 4:
		return "NOTIFY"
	case 5:
		return "UPDATE"
	default:
		return "UNKOWN"
	}
}

func (f Flag) ResponseCodeString() string {
	switch f.ResponseCode {
	case 0:
		return "No Error"
	case 1:
		return "Format Error"
	case 2:
		return "Server Failure"
	case 3:
		return "Name Error"
	case 4:
		return "Not Implemented"
	case 5:
		return "Refused"
	case 6:
		return "YX Domain"
	case 7:
		return "YX RR Set"
	case 8:
		return "NX RR Set"
	case 9:
		return "Not Auth"
	case 10:
		return "Not Zone"
	default:
		return "UNKOWN"
	}
}

type Header struct {
	Identifer             uint16
	Flag                  Flag
	QuestionCount         uint16
	AnswerRecordCount     uint16
	AuthorityRecordCount  uint16
	AdditionalRecordCount uint16
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

func (q Question) TypeString() string {
	switch q.Type {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 251:
		return "IXFR"
	case 252:
		return "AXFR"
	case 253:
		return "MAILB"
	case 254:
		return "MAILA"
	case 255:
		return "*"
	default:
		return "UNKOWN"
	}
}

func (q Question) ClassString() string {
	switch q.Class {
	case 1:
		return "IN"
	case 255:
		return "ANY"
	default:
		return "UNKOWN"
	}
}

type DNSMessage struct {
	Header    Header
	Questions []Question
}

func (m *DNSMessage) String() string {
	if m.Header.Flag.QueryResponseFlag != 0 {
		return "DNS Response message currently not supported"
	}
	var r string
	op := m.Header.Flag.OperationCodeString()
	for _, q := range m.Questions {
		line := op + ":\t" + q.Name + "\t" + q.TypeString() + "\t" + q.ClassString()
		if r == "" {
			r = line
		} else {
			r += "\n" + line
		}
	}
	return r
}

func Parse(packet []byte) *DNSMessage {
	var msg DNSMessage
	header, n := parseHeader(packet)
	msg.Header = header
	msg.Questions = make([]Question, int(header.QuestionCount))
	for i := 0; i < int(header.QuestionCount); i++ {
		packet = packet[n:]
		var question Question
		question, n = parseQuestion(packet)
		msg.Questions[i] = question
	}
	return &msg
}

func bytesToU16(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}

func bitTobyte(b byte, s, e int) byte {
	return (b >> (8 - e)) & (1<<(e-s) - 1)
}

func parseHeader(b []byte) (Header, int) {
	var header Header
	header.Identifer = bytesToU16(b[:2])
	header.Flag = parseFlag(b[2:4])
	header.QuestionCount = bytesToU16(b[4:6])
	header.AnswerRecordCount = bytesToU16(b[6:8])
	header.AuthorityRecordCount = bytesToU16(b[8:10])
	header.AdditionalRecordCount = bytesToU16(b[10:12])
	return header, 12
}

func parseFlag(b []byte) Flag {
	var flag Flag
	flag.QueryResponseFlag = bitTobyte(b[0], 0, 1)
	flag.OperationCode = bitTobyte(b[0], 1, 5)
	flag.AuthoritativeAnswerFlag = bitTobyte(b[0], 5, 6)
	flag.TruncationFlag = bitTobyte(b[0], 6, 7)
	flag.RecursionDesired = bitTobyte(b[0], 7, 8)
	flag.RecursionAvailable = bitTobyte(b[1], 0, 1)
	flag.ResponseCode = bitTobyte(b[1], 4, 8)
	return flag
}

func parseQuestion(b []byte) (Question, int) {
	var i int
	var question Question
	for {
		length := b[i]
		i++
		if length == 0 {
			break
		}
		end := i + int(length)
		if question.Name != "" {
			question.Name += "."
		}
		question.Name += string(b[i:end])
		i = end
	}
	question.Type = bytesToU16(b[i : i+2])
	question.Class = bytesToU16(b[i+2 : i+4])
	return question, i + 4
}
