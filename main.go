package main

import (
	. "tigo/TCP"

	"fmt"

	Header "github.com/google/netstack/tcpip/header"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

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
	connections := make(map[TcpConnAddr]TcpConn)

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
		// src := iph.SourceAddress().To4()
		// fmt.Println(src)
		fmt.Printf("Src : %v:%v    Dst : %v:%v \n", iph.SourceAddress(), tcph.SourcePort(), iph.DestinationAddress(), tcph.DestinationPort())

		// tpak := ParseTcpPak(frame.Payload()[20:])
		// fmt.Printf("frame : %v ip header %v tcp header %v\n", len(frame.Payload()), header.Len, tpak.Header.HeaderLen)
		addr := TcpConnAddr{SrcIP: iph.SourceAddress(), SrcPort: tcph.SourcePort(), DstIP: iph.DestinationAddress(), DstPort: tcph.DestinationPort()}
		conn, pre := connections[addr]
		if !pre {
			connections[addr] = TcpConn{Addr: addr}
			conn = connections[addr]
			conn.State = TCP_LISTEN
		}
		conn.Process(&frame, &iph, &tcph)
	}
}
