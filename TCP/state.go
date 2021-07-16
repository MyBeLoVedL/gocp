package tcp

import (
	"encoding/hex"
	"fmt"
	"math"

	IP "github.com/google/netstack/tcpip"
	Header "github.com/google/netstack/tcpip/header"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
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

func hexView(data []byte) {
	col := 0
	for i := 0; i < len(data); i += 2 {
		ch := hex.EncodeToString(data[i : i+2])
		if col < 7 {
			fmt.Printf("%s  ", ch)
			col++
		} else {
			col = 0
			fmt.Printf("%s\n", ch)
		}
	}
	println()
}

// func ip2int(ip net.IP) uint32 {
// 	if len(ip) == 16 {
// 		return binary.BigEndian.Uint32(ip[12:16])
// 	}
// 	return binary.BigEndian.Uint32(ip)
// }

// func int2ip(nn uint32) net.IP {
// 	ip := make(net.IP, 4)
// 	binary.BigEndian.PutUint32(ip, nn)
// 	return ip
// }

func (t *TcpConn) Process(ifce *water.Interface, frameRaw *ethernet.Frame, iph *Header.IPv4, tcph *Header.TCP) {
	fmt.Printf("begin processing with state %v\n", t.State)

	sendAck := func(ack *Header.TCPFields) {
		ack.SrcPort = tcph.DestinationPort()
		ack.DstPort = tcph.SourcePort()
		ack.DataOffset = Header.TCPMinimumSize
		ack.WindowSize = uint16(t.Recv.wnd)
		ack.Checksum = 0
		ackRaw := Header.TCP(make([]byte, 26))
		ackRaw.Encode(ack)
		// ! recheck the checksum
		partialChecksum := Header.PseudoHeaderChecksum(Header.TCPProtocolNumber, iph.SourceAddress(), iph.DestinationAddress(), uint16(len(ackRaw)))
		ackRaw.SetChecksum(^Header.Checksum(ackRaw, partialChecksum))

		ackIP := Header.IPv4Fields{}
		ackIP.SrcAddr = iph.DestinationAddress()
		ackIP.DstAddr = iph.SourceAddress()
		ackIP.Checksum = 0
		ackIP.Protocol = uint8(Header.TCPProtocolNumber)
		ackIP.TTL = 128
		ackIP.TotalLength = uint16(20 + len(ackRaw))
		ackIP.IHL = 20
		ackIPRaw := Header.IPv4(make([]byte, 20))
		ackIPRaw.Encode(&ackIP)
		ackIPRaw.SetChecksum(^(Header.Checksum(ackIPRaw, 0)))

		frame := make([]byte, 14)
		copy(frame[:6], frameRaw.Destination())
		copy(frame[6:12], frameRaw.Source())
		copy(frame[12:14], []byte{0x08, 0x00})

		frame = append(frame, ackIPRaw...)
		frame = append(frame, ackRaw...)
		ifce.Write(frame)
		// hexView(frame)
		// fmt.Printf("write [%v] bytes %v\n", len(ackRaw), hex.EncodeToString(ackRaw))
	}

	switch t.State {
	case TCP_CLOSED:
		return
	case TCP_LISTEN:
		if tcph.Flags()&Header.TCPFlagSyn == 0 {
			return
		}

		//* update send and receive state
		t.Send.iss = 0
		t.Send.una = t.Send.iss
		t.Send.nxt = t.Send.una + 1
		t.Send.wnd = math.MaxUint16

		t.Recv.irs = uint(tcph.SequenceNumber())
		t.Recv.nxt = t.Recv.irs + 1
		t.Recv.wnd = uint(tcph.WindowSize())

		t.State = TCP_SYN_RCVD

		//* construct ACK packet
		ack := Header.TCPFields{}
		ack.Flags |= Header.TCPFlagAck
		ack.Flags |= Header.TCPFlagSyn
		ack.AckNum = uint32(t.Recv.nxt)
		ack.SeqNum = uint32(t.Send.iss)
		sendAck(&ack)
	default:
		fmt.Println("unknown state")
	}
}
