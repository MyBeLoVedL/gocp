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
	una, nxt uint64
	wnd, iss uint32
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

type RecvSpace struct {
	nxt      uint64
	wnd, irs uint32
}

// Transform an "absolute" 64-bit sequence number (zero-indexed) into a uint32,which can be accommodated in an TCP ACK or SEQ field
// \param n The input absolute 64-bit sequence number
// \param isn The initial sequence number
func wrap(n uint64, iss uint32) uint32 {
	n32 := uint32((n << 32) >> 32)
	return n32 + iss
}

// Transform a WrappingInt32 into an "absolute" 64-bit sequence number (zero-indexed)
// \param n The relative sequence number
// \param isn The initial sequence number
// \param checkpoint A recent absolute 64-bit sequence number
// \returns the 64-bit sequence number that wraps to `n` and is closest to `checkpoint`
//
// \note Each of the two streams of the TCP connection has its own ISN. One stream
// runs from the local TCPSender to the remote TCPReceiver and has one ISN,
// and the other stream runs from the remote TCPSender to the local TCPReceiver and
// has a different ISN.
// #define interval (1ul << 32)

func abs(num int64) int64 {
	if num < 0 {
		return -num
	}
	return num
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

//* a hard lesson about overflow

const interval = 1 << 32

func unwrap(n_raw, isn_raw uint32, checkpoint uint64) uint64 {
	var delta uint64
	if n_raw >= isn_raw {
		delta = uint64(n_raw - isn_raw)
	} else {
		delta = uint64(math.MaxUint32 - isn_raw + n_raw + 1)
	}

	base := (checkpoint >> 32) << 32

	var a = abs(int64(base - interval + delta - checkpoint))
	var b = abs(int64(base + delta - checkpoint))
	var c = abs(int64(base + interval + delta - checkpoint))
	min_val := min(b, c)
	if int64(base)-interval >= 0 {
		min_val = min(a, min_val)
	}
	if min_val == a && int64(base-interval) >= 0 {
		return base - interval + delta
	} else if min_val == b {
		return base + delta
	} else if min_val == c {
		return base + interval + delta
	} else {
		panic("unwrapping failed\n")
	}
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

// * SYN and FIN occupy space in order to protect the control information from been lost
func tcpLen(tcph *Header.TCP) int {
	length := 0
	if tcph.Flags()&Header.TCPFlagSyn != 0 {
		length += 1
	}
	if tcph.Flags()&Header.TCPFlagFin != 0 {
		length += 1
	}
	return length + len(tcph.Payload())
}

func validateSegment(t *TcpConn, tcph *Header.TCP) bool {
	seq := unwrap(tcph.SequenceNumber(), t.Recv.irs, t.Recv.nxt)
	if t.Recv.wnd == 0 {
		return tcpLen(tcph) == 0 && seq == t.Recv.nxt
	} else {
		if tcpLen(tcph) == 0 {
			return seq >= t.Recv.nxt && seq < t.Recv.nxt+uint64(t.Recv.wnd)
		} else {
			end := seq + uint64(tcpLen(tcph)) - 1
			return (seq >= t.Recv.nxt && seq < t.Recv.nxt+uint64(t.Recv.wnd)) ||
				(end >= t.Recv.nxt && end < t.Recv.nxt+uint64(t.Recv.wnd))
		}
	}
}

func (t *TcpConn) Process(ifce *water.Interface, frameRaw *ethernet.Frame, iph *Header.IPv4, tcph *Header.TCP) {
	// fmt.Printf("begin processing with state %v\n", t.State)

	// ! check if seq is within the receive window
	if !validateSegment(t, tcph) {
		return
	}

	// ! If this is an ACK packet,check if it ACK something valid , logically : una < ACK <= nxt
	if tcph.Flags()&Header.TCPFlagAck != 0 {
		ackno := unwrap(tcph.AckNumber(), t.Recv.irs, t.Recv.nxt)
		if !(ackno > t.Send.una && ackno <= t.Send.una+t.Send.nxt) {
			return
		}
	}

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

	// ! Why 3-way handshake ?
	// * 1 : exchange initial sequence number
	// * 2 : prevent obselete connection
	println("HI\n")
	switch t.State {
	case TCP_LISTEN:

		if tcph.Flags()&Header.TCPFlagRst != 0 {
			return
		}

		if tcph.Flags()&Header.TCPFlagAck != 0 {
			ack := Header.TCPFields{}
			ack.SeqNum = tcph.AckNumber()
			ack.Flags |= Header.TCPFlagRst
			sendAck(&ack)
			return
		}

		if tcph.Flags()&Header.TCPFlagSyn == 0 {
			return
		}

		//* update send and receive state
		t.Send.iss = 0
		t.Send.una = uint64(t.Send.iss)
		t.Send.nxt = t.Send.una + 1
		t.Send.wnd = math.MaxUint16

		t.Recv.irs = uint32(tcph.SequenceNumber())
		t.Recv.nxt = uint64(t.Recv.irs) + 1
		t.Recv.wnd = uint32(tcph.WindowSize())

		t.State = TCP_SYN_RCVD

		//* construct ACK packet
		ack := Header.TCPFields{}
		ack.Flags |= Header.TCPFlagAck
		ack.Flags |= Header.TCPFlagSyn
		ack.AckNum = uint32(t.Recv.nxt)
		ack.SeqNum = uint32(t.Send.iss)
		sendAck(&ack)
	case TCP_SYN_SENT:
		if tcph.Flags()&Header.TCPFlagAck == 0 || tcph.AckNumber() != uint32(t.Recv.nxt) {
			return
		}
		t.Send.una += 1
		t.Send.wnd = uint32(tcph.WindowSize())

		t.Recv.irs = uint32(tcph.SequenceNumber())
		t.Recv.nxt = unwrap(t.Recv.irs, t.Recv.irs, t.Recv.nxt) + 1
		t.Recv.wnd = uint32(tcph.WindowSize())

		t.State = TCP_ESTABLISHED
		ack := Header.TCPFields{}
		ack.Flags |= Header.TCPFlagAck
		ack.AckNum = uint32(t.Recv.nxt)
		ack.SeqNum = uint32(t.Send.iss)
		ack.WindowSize = uint16(t.Send.wnd)
		sendAck(&ack)

	case TCP_SYN_RCVD:
		if tcph.Flags()&Header.TCPFlagAck == 0 {
			return
		}
		t.Send.una += 1
		t.Send.wnd = uint32(tcph.WindowSize())

		t.State = TCP_ESTABLISHED
	case TCP_FIN_WAIT1:

	default:
		fmt.Println("unknown state")
	}
}
