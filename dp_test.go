package main

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/iovisor/gobpf/pkg/progtestrun"
)

const (
	XDP_ABORTED  = iota
	XDP_DROP     = iota
	XDP_PASS     = iota
	XDP_TX       = iota
	XDP_REDIRECT = iota
)

func TestDpArp(t *testing.T) {
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		SourceProtAddress: net.IPv4(192, 168, 0, 1),
		DstHwAddress:      net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)

	action, out, err := dpTest(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if action != XDP_PASS {
		t.Fatal(fmt.Errorf("invalid action"))
	}
	if bytes.Compare(out, buf.Bytes()) != 0 {
		t.Fatal(fmt.Errorf("invalid out"))
	}
}

func dpTest(data []byte) (int, []byte, error) {
	spec, err := ebpf.LoadCollectionSpec(config.XdpProg)
	if err != nil {
		return 0, nil, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return 0, nil, err
	}

	dp := coll.Programs["process_rx"]
	if dp == nil {
		return 0, nil, fmt.Errorf("eBPF prog 'process_rx' not found")
	}

	dataOut := make([]byte, 9000)
	action, _, dataOutLen, err := progtestrun.Run(dp.FD(), 1, data, dataOut)
	if err != nil {
		return 0, nil, err
	}
	return action, dataOut[:dataOutLen], nil
}
