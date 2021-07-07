package tcp

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net"
)

type TcpConnAddr struct {
	SrcIP, DstIP     uint32
	SrcPort, DstPort uint16
}

const (
	TCP_CLOSED = iota
	TCP_SYN_SENT
	TCP_LISTEN
	TCP_SYN_RCVD
	TCP_ESTABLISHED
	TCP_CLOSE_WAIT
	TCP_LAST_ACK
	TCP_FIN_WAIT1
	TCP_FIN_WAIT2
	TCP_TIME_WAIT
	TCP_CLOSING
)

type TcpConn struct {
	Addr  TcpConnAddr
	State byte
}

type tcpFlag struct {
	SYN, FIN, ACK, RST bool
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
func (t tcpFlag) String() string {
	res := ""
	if t.SYN {
		res += "SYN "
	}
	if t.FIN {
		res += "FIN "
	}
	if t.ACK {
		res += "ACK "
	}
	if t.RST {
		res += "RST "
	}
	return res
}

const (
	TCPHeaderSize = 20
	IPHeaderSize  = 20
)

type tCPHeader struct {
	SrcPort, DstPort uint16
	Seq              uint32
	Ack              uint32
	HeaderLen        uint8
	Flags            tcpFlag
	Win              uint16
	Checksum         uint16
	Urgent           uint16
}

type TCPpak struct {
	Header tCPHeader
	Data   []byte
}

func (t *TCPpak) ToBytes() []byte {
	res := make([]byte, 10)
	return res
}

func ParseTcpPak(data []byte) *TCPpak {
	r := TCPpak{}
	r.Header.SrcPort = binary.BigEndian.Uint16(data[:2])
	r.Header.DstPort = binary.BigEndian.Uint16(data[2:4])
	r.Header.Seq = binary.BigEndian.Uint32(data[4:8])
	r.Header.Ack = binary.BigEndian.Uint32(data[8:12])
	r.Header.HeaderLen = (data[12] & 0xf0) >> 4
	flag := data[13]
	if flag&0x01 != 0 {
		r.Header.Flags.FIN = true
	}
	if flag&0x02 != 0 {
		r.Header.Flags.SYN = true
	}
	if flag&0x04 != 0 {
		r.Header.Flags.RST = true
	}
	if flag&0x10 != 0 {
		r.Header.Flags.ACK = true
	}
	r.Header.Win = binary.BigEndian.Uint16(data[14:16])
	r.Header.Checksum = binary.BigEndian.Uint16(data[16:18])
	r.Header.Urgent = binary.BigEndian.Uint16(data[18:20])
	r.Data = data[20:]
	return &r
}

func (t TcpConn) Process(pak *TCPpak) {
	switch t.State {
	case TCP_CLOSED:
		if !pak.Header.Flags.SYN {
			return
		}
		ack := TCPpak{}
		ack.Header.Flags.ACK = true
		ack.Header.Flags.SYN = true
		ack.Header.Ack = pak.Header.Seq + 1
		ack.Header.Seq = uint32(rand.Int31n(math.MaxInt32))
		tcpBytes := ack.ToBytes()
	}
	fmt.Printf("%v : %v    %v : %v  %v  len : %v \n", int2ip(t.Addr.SrcIP), t.Addr.SrcPort, int2ip(t.Addr.DstIP), t.Addr.DstPort, pak.Header.Flags.String(), len(pak.Data)+TCPHeaderSize+IPHeaderSize)
}
