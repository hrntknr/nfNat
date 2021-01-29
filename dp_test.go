package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/iovisor/gobpf/pkg/progtestrun"
)

const (
	XDP_ABORTED  = 0
	XDP_DROP     = 1
	XDP_PASS     = 2
	XDP_TX       = 3
	XDP_REDIRECT = 4
)

var xdp_action_string_map map[int]string = map[int]string{
	0: "XDP_ABORTED",
	1: "XDP_DROP",
	2: "XDP_PASS",
	3: "XDP_TX",
	4: "XDP_REDIRECT",
}

func TestDpIPv4(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    net.IPv4(192, 168, 0, 1),
		DstIP:    net.IPv4(192, 168, 0, 2),
	}
	inbuf := gopacket.NewSerializeBuffer()
	outbuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(inbuf, opts, eth, ipv4); err != nil {
		t.Fatal(err)
	}
	if err := gopacket.SerializeLayers(outbuf, opts, eth, ipv4); err != nil {
		t.Fatal(err)
	}

	action, out, err := dpTest(inbuf.Bytes(), Config{XdpProg: "./dp/nfNat_dp.o"})
	if err != nil {
		t.Fatal(err)
	}
	expect := XDP_PASS
	if action != expect {
		t.Fatal(fmt.Errorf("invalid action. expect:%s, actual:%s", xdp_action_string_map[expect], xdp_action_string_map[action]))
	}
	if bytes.Compare(out, outbuf.Bytes()) != 0 {
		t.Fatal(fmt.Errorf("invalid output.\nexpect:\n%s\nactual:\n%s", hex.Dump(outbuf.Bytes()), hex.Dump(out)))
	}
}

func TestDpIPv6(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
	}
	inbuf := gopacket.NewSerializeBuffer()
	outbuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(inbuf, opts, eth, ipv6); err != nil {
		t.Fatal(err)
	}
	if err := gopacket.SerializeLayers(outbuf, opts, eth, ipv6); err != nil {
		t.Fatal(err)
	}

	action, out, err := dpTest(inbuf.Bytes(), Config{XdpProg: "./dp/nfNat_dp.o"})
	if err != nil {
		t.Fatal(err)
	}
	expect := XDP_PASS
	if action != expect {
		t.Fatal(fmt.Errorf("invalid action. expect:%s, actual:%s", xdp_action_string_map[expect], xdp_action_string_map[action]))
	}
	if bytes.Compare(out, outbuf.Bytes()) != 0 {
		t.Fatal(fmt.Errorf("invalid output.\nexpect:\n%s\nactual:\n%s", hex.Dump(outbuf.Bytes()), hex.Dump(out)))
	}
}

func TestDpSRv6IPv6(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Routing,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
	}
	srv6 := &IPv6Routing{
		NextHeader:   layers.IPProtocolIPv6,
		RoutingType:  4,
		SegmentsLeft: 0,
		SourceRoutingIPs: []net.IP{
			net.ParseIP("2001:db8::1"),
		},
	}
	ipv6in := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
	}
	inbuf := gopacket.NewSerializeBuffer()
	outbuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(inbuf, opts, eth, ipv6, srv6, ipv6in); err != nil {
		t.Fatal(err)
	}
	if err := gopacket.SerializeLayers(outbuf, opts, eth, ipv6, srv6, ipv6in); err != nil {
		t.Fatal(err)
	}

	action, out, err := dpTest(inbuf.Bytes(), Config{XdpProg: "./dp/nfNat_dp.o"})
	if err != nil {
		t.Fatal(err)
	}
	expect := XDP_PASS
	if action != expect {
		t.Fatal(fmt.Errorf("invalid action. expect:%s, actual:%s", xdp_action_string_map[expect], xdp_action_string_map[action]))
	}
	if bytes.Compare(out, outbuf.Bytes()) != 0 {
		t.Fatal(fmt.Errorf("invalid output.\nexpect:\n%s\nactual:\n%s", hex.Dump(outbuf.Bytes()), hex.Dump(out)))
	}
}

func TestDnat(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Routing,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
	}
	srv6 := &IPv6Routing{
		NextHeader:   layers.IPProtocolIPv4,
		RoutingType:  4,
		SegmentsLeft: 0,
		SourceRoutingIPs: []net.IP{
			net.ParseIP("2001:db8:0:1::"),
		},
	}
	ipv4in := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(192, 168, 0, 1),
		DstIP:    net.IPv4(192, 168, 0, 2),
	}
	tcp := &layers.TCP{
		SrcPort: 1025,
		DstPort: 80,
		Seq:     0,
		Ack:     0,
	}
	tcp.SetNetworkLayerForChecksum(ipv4in)
	payload := &gopacket.Payload{0x01, 0x02}
	inbuf := gopacket.NewSerializeBuffer()
	outbuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(inbuf, opts, eth, ipv6, srv6, ipv4in, tcp, payload); err != nil {
		t.Fatal(err)
	}
	srv6.SegmentsLeft = 1
	ipv4in.DstIP = net.IPv4(192, 168, 0, 3)
	tcp.DstPort = 81
	opts.ComputeChecksums = false
	if err := gopacket.SerializeLayers(outbuf, opts, eth, ipv6, srv6, ipv4in, tcp, payload); err != nil {
		t.Fatal(err)
	}

	action, out, err := dpTest(inbuf.Bytes(), Config{
		XdpProg: "./dp/nfNat_dp.o",
		SID: map[string]SidConfig{
			"2001:db8:0:1::/128": {
				Dnat:       true,
				Masquerade: false,
			},
		},
		DNat: []DnatConfig{{
			Dst:    "192.168.0.2",
			Port:   80,
			ToDst:  "192.168.0.3",
			ToPort: 81,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	expect := XDP_PASS
	if action != expect {
		t.Fatal(fmt.Errorf("invalid action.\nexpect:%s\nactual:%s", xdp_action_string_map[expect], xdp_action_string_map[action]))
	}
	if bytes.Compare(out, outbuf.Bytes()) != 0 {
		t.Fatal(fmt.Errorf("invalid output.\nexpect:\n%s\nactual:\n%s", hex.Dump(outbuf.Bytes()), hex.Dump(out)))
	}
}

func dpTest(data []byte, config Config) (int, []byte, error) {
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

	dnatRules := coll.Maps["dnat_rules"]
	if dnatRules == nil {
		return 0, nil, fmt.Errorf("eBPF map 'dnat_rules' not found")
	}
	sidConfigs := coll.Maps["sid_configs"]
	if sidConfigs == nil {
		return 0, nil, fmt.Errorf("eBPF map 'sid_configs' not found")
	}

	for _, dnat := range config.DNat {
		key := &dnatRulesKey{
			Dst:   net.ParseIP(dnat.Dst),
			DPort: dnat.Port,
		}
		value := &dnatRulesValue{
			Dst:   net.ParseIP(dnat.ToDst),
			DPort: dnat.ToPort,
		}
		if err := dnatRules.Put(key, value); err != nil {
			return 0, nil, err
		}
	}

	for sid, config := range config.SID {
		_, ipnet, err := net.ParseCIDR(sid)
		if err != nil {
			return 0, nil, err
		}
		size, _ := ipnet.Mask.Size()
		if size != 128 {
			return 0, nil, fmt.Errorf("not supported mask size")
		}
		key := &sidConfigsKey{
			sid: ipnet.IP,
		}
		value := &sidConfigValue{
			Dnat:       config.Dnat,
			Masquerade: config.Masquerade,
		}
		if err := sidConfigs.Put(key, value); err != nil {
			return 0, nil, err
		}
	}

	dataOut := make([]byte, 9000)
	action, _, dataOutLen, err := progtestrun.Run(dp.FD(), 1, data, dataOut)
	if err != nil {
		return 0, nil, err
	}
	return action, dataOut[:dataOutLen], nil
}

type IPv6Routing struct {
	NextHeader       layers.IPProtocol
	HeaderLength     uint8
	RoutingType      uint8
	SegmentsLeft     uint8
	LastEntry        uint8
	Flags            uint8
	Tag              uint16
	SourceRoutingIPs []net.IP
}

func (i *IPv6Routing) LayerType() gopacket.LayerType { return layers.LayerTypeIPv6Routing }
func (i *IPv6Routing) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(8 + 16*len(i.SourceRoutingIPs))
	if err != nil {
		return err
	}
	if opts.FixLengths {
		i.HeaderLength = uint8(2 * len(i.SourceRoutingIPs))
		i.LastEntry = uint8(len(i.SourceRoutingIPs) - 1)
	}
	bytes[0] = byte(i.NextHeader)
	bytes[1] = i.HeaderLength
	bytes[2] = i.RoutingType
	bytes[3] = i.SegmentsLeft
	bytes[4] = i.LastEntry
	bytes[5] = i.Flags
	binary.BigEndian.PutUint16(bytes[6:], i.Tag)
	for i, ip := range i.SourceRoutingIPs {
		copy(bytes[8+(i*16):8+((i+1)*16)], ip)
	}

	return nil
}
