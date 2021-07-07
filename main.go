package main

import (
	"encoding/binary"
	"fmt"
	. "tigo/TCP"
	tcp "tigo/TCP"

	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
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
	connections := make(map[tcp.TcpConnAddr]tcp.TcpConn)

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
		header, err := ipv4.ParseHeader(frame.Payload())
		check(err)
		if header.Protocol != 0x06 {
			continue
		}

		tpak := ParseTcpPak(frame.Payload()[20:])
		fmt.Printf("frame : %v ip header %v tcp header %v\n", len(frame.Payload()), header.Len, tpak.Header.HeaderLen)
		addr := TcpConnAddr{SrcIP: binary.BigEndian.Uint32(header.Src.To4()), DstIP: binary.BigEndian.Uint32(header.Dst.To4()), SrcPort: tpak.Header.SrcPort, DstPort: tpak.Header.DstPort}
		conn, pre := connections[addr]
		if !pre {
			connections[addr] = tcp.TcpConn{Addr: addr}
			conn = connections[addr]
		}
		conn.Process(tpak)
	}
}
