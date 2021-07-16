package tcp

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net"

	IP "github.com/google/netstack/tcpip"
	Header "github.com/google/netstack/tcpip/header"
	"github.com/songgao/packets/ethernet"
)

//   TCP Header Format

//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |          Source Port          |       Destination Port        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                        Sequence Number                        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                    Acknowledgment Number                      |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |  Data |           |U|A|P|R|S|F|                               |
//    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//    |       |           |G|K|H|T|N|N|                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |           Checksum            |         Urgent Pointer        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                    Options                    |    Padding    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                             data                              |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

//                             TCP Header Format

//           Note that one tick mark represents one bit position.

//                                Figure 3.

type TcpConnAddr struct {
	SrcIP, DstIP     IP.Address
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

//   Send Sequence Space

//                    1         2          3          4
//               ----------|----------|----------|----------
//                      SND.UNA    SND.NXT    SND.UNA
//                                           +SND.WND

//         1 - old sequence numbers which have been acknowledged
//         2 - sequence numbers of unacknowledged data
//         3 - sequence numbers allowed for new data transmission
//         4 - future sequence numbers which are not yet allowed

type SendSpace struct {
	una, nxt, wnd, iss uint
}

//   Receive Sequence Space

//                        1          2          3
//                    ----------|----------|----------
//                           RCV.NXT    RCV.NXT
//                                     +RCV.WND

//         1 - old sequence numbers which have been acknowledged
//         2 - sequence numbers allowed for new reception
//         3 - future sequence numbers which are not yet allowed

//                          Receive Sequence Space

//                                Figure 5.

type RecvSpace struct {
	nxt, wnd, irs uint
}

type TcpConn struct {
	Addr  TcpConnAddr
	State byte
	Send  SendSpace
	Recv  RecvSpace
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

func (t *TcpConn) Process(frame *ethernet.Frame, iph *Header.IPv4, tcph *Header.TCP) {
	fmt.Printf("begin processing with state %v\n", t.State)
	switch t.State {
	case TCP_CLOSED:
		return
	case TCP_LISTEN:
		if tcph.Flags()&Header.TCPFlagSyn == 0 {
			return
		}
		ack := Header.TCPFields{}
		ack.Flags |= Header.TCPFlagAck
		ack.Flags |= Header.TCPFlagSyn
		ack.AckNum = tcph.SequenceNumber() + 1
		ack.SeqNum = uint32(rand.Int31n(math.MaxInt32))
		fmt.Printf("ACK : %+v\n", ack)
	default:
		fmt.Println("unknown state")
	}
}
