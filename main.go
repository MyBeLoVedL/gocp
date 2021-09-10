package main

import (
	. "tigo/TCP"

	Header "github.com/google/netstack/tcpip/header"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

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

func send(ifce *water.Interface, frameRaw *ethernet.Frame, iph *Header.IPv4, tcph *Header.TCP, ack *Header.TCPFields) {
	ack.SrcPort = tcph.DestinationPort()
	ack.DstPort = tcph.SourcePort()
	ack.DataOffset = Header.TCPMinimumSize
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

}

// * map should only store the address of an object

func main() {
	config := water.Config{
		DeviceType: water.TAP,
	}
	config.Name = "tun0"
	ifce, err := water.New(config)
	if err != nil {
		panic("error creating interface")
	}
	var frame ethernet.Frame
	connections := make(map[TcpConnAddr]*TcpConn)
	listenings := make(map[uint16]struct{})
	// * for debugging
	listenings[80] = struct{}{}
	for {
		frame.Resize(1500)
		n, err := ifce.Read([]byte(frame))
		if err != nil {
			panic("error reading ")
		}
		frame = frame[:n]
		if frame.Ethertype() != [2]byte{0x08, 0x00} {
			continue
		}

		iph := Header.IPv4(frame.Payload())
		if iph.Protocol() != 0x06 {
			continue
		}
		tcph := Header.TCP(iph.Payload())
		addr := TcpConnAddr{SrcIP: iph.SourceAddress(), SrcPort: tcph.SourcePort(), DstIP: iph.DestinationAddress(), DstPort: tcph.DestinationPort()}
		conn, pre := connections[addr]
		if !pre {
			// * if no listening port,ignore it.
			_, preInLi := listenings[tcph.DestinationPort()]
			if !preInLi {
				if tcph.Flags()&Header.TCPFlagRst != 0 {
					continue
				} else {
					ack := Header.TCPFields{}
					if tcph.Flags()&Header.TCPFlagAck != 0 {
						ack.SeqNum = tcph.AckNumber()
					} else {
						ack.Flags |= Header.TCPFlagAck
						ack.SeqNum = 0
						ack.AckNum = tcph.SequenceNumber() + uint32(tcpLen(&tcph))
					}
					ack.Flags |= Header.TCPFlagRst
					send(ifce, &frame, &iph, &tcph, &ack)
				}
			}
			connections[addr] = &TcpConn{Addr: addr}
			conn = connections[addr]
			conn.State = TCP_LISTEN
		}
		conn.Process(ifce, &frame, &iph, &tcph)
	}
}
