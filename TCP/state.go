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
	var n32 uint32
	n32 = uint32((n << 32) >> 32)
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
func unwrap(n, isn uint32, checkpoint uint64) uint64 {
	var half_gap uint64 = 1 << 31
	var lower, upper uint64
	if checkpoint <= half_gap {
		lower = 0
		upper = 2 * half_gap
	} else {
		lower = checkpoint - half_gap
		upper = checkpoint + half_gap
	}

	var base uint64 = (checkpoint >> 32) << 32
	t := n - isn
	base += uint64(t)
	if !(base >= lower && base <= upper) {
		base += half_gap * 2
	}
	if !(base >= lower && base <= upper) {
		panic("exam failed")
	}
	return base
#define interval (1ul << 32)

//* a hard lesson about overflow
uint64_t unwrap(WrappingInt32 n, WrappingInt32 isn, uint64_t checkpoint) {
    auto n_raw = n.raw_value();
    auto isn_raw = isn.raw_value();
    uint32_t delta = n_raw >= isn_raw ? n_raw - isn_raw : UINT32_MAX + 1 - isn_raw + n_raw;

    uint64_t base = (checkpoint >> 32) << 32;

    auto a = ABS(int64_t(base - interval + delta - checkpoint));
    auto b = ABS(int64_t(base + delta - checkpoint));
    auto c = ABS(int64_t(base + interval + delta - checkpoint));
    auto min = MIN(b, c);
    if (int64_t(base - interval) >= 0)
        min = MIN(a, min);
    if (min == a && int64_t(base - interval) >= 0) {
        return base - interval + delta;
    } else if (min == b) {
        return base + delta;
    } else if (min == c) {
        return base + interval + delta;
    } else {
        cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    }
    return 0;
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

func (t *TcpConn) Process(ifce *water.Interface, frameRaw *ethernet.Frame, iph *Header.IPv4, tcph *Header.TCP) {
	// fmt.Printf("begin processing with state %v\n", t.State)

	// ! acceptable  ACK check , logically : una < ACK <= nxt

	if tcph.Flags()&Header.TCPFlagAck != 0 {
		ackn := tcph.AckNumber()
		//* No data sent,only accept ACK which equals to nxt.
		if !(t.Send.nxt == t.Send.una && t.Send.nxt == uint(ackn)) {
			return
			//* no wrapping
		} else if t.Send.nxt > t.Send.una {
			if !(ackn > uint32(t.Send.una) && ackn <= uint32(t.Send.nxt)) {
				return
			}
			// * wrapping
		} else {
			if !(ackn > uint32(t.Send.una) || ackn <= uint32(t.Send.nxt)) {
				return
			}
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
	println("HI\n")
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
	case TCP_SYN_SENT:
		if tcph.Flags()&Header.TCPFlagAck == 0 || tcph.AckNumber() != uint32(t.Recv.nxt) {
			return
		}
		t.Send.una += 1
		t.Send.wnd = uint(tcph.WindowSize())

		t.Recv.irs = uint(tcph.SequenceNumber())
		t.Recv.nxt = t.Recv.irs + 1
		t.Recv.wnd = uint(tcph.WindowSize())

		t.State = TCP_ESTABLISHED
		ack := Header.TCPFields{}
		ack.Flags |= Header.TCPFlagAck
		ack.AckNum = uint32(t.Recv.nxt)
		ack.SeqNum = uint32(t.Send.iss)
		ack.WindowSize = uint16(t.Send.wnd)
		sendAck(&ack)

	case TCP_SYN_RCVD:
		if tcph.Flags()&Header.TCPFlagAck == 0 || tcph.AckNumber() != uint32(t.Recv.nxt) {
			return
		}
		t.Send.una += 1
		t.Send.wnd = uint(tcph.WindowSize())

		t.State = TCP_ESTABLISHED
	case TCP_FIN_WAIT1:

	default:
		fmt.Println("unknown state")
	}
}
