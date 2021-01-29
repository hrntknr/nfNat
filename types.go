package main

import (
	"encoding/binary"
	"net"
)

type dnatRulesKey struct {
	Dst   net.IP
	DPort uint16
}

func (k *dnatRulesKey) MarshalBinary() (data []byte, err error) {
	v4 := k.Dst.To4()
	buf := [8]byte{}
	for i := 0; i < 4; i++ {
		buf[i] = v4[i]
	}
	binary.BigEndian.PutUint16(buf[4:6], k.DPort)
	return buf[:], nil
}

type dnatRulesValue struct {
	Dst   net.IP
	DPort uint16
}

func (k *dnatRulesValue) MarshalBinary() (data []byte, err error) {
	v4 := k.Dst.To4()
	buf := [8]byte{}
	for i := 0; i < 4; i++ {
		buf[i] = v4[i]
	}
	binary.BigEndian.PutUint16(buf[4:6], k.DPort)
	return buf[:], nil
}

type sidConfigsKey struct {
	sid net.IP
}

func (k *sidConfigsKey) MarshalBinary() (data []byte, err error) {
	buf := [16]byte{}
	for i := 0; i < 16; i++ {
		buf[i] = k.sid[i]
	}
	return buf[:], nil
}

type sidConfigValue struct {
	Dnat       bool
	Masquerade bool
}

func (k *sidConfigValue) MarshalBinary() (data []byte, err error) {
	buf := [1]byte{0x00}
	if k.Dnat {
		buf[0] |= 0x01
	}
	if k.Masquerade {
		buf[0] |= 0x02
	}
	return buf[:], nil
}
