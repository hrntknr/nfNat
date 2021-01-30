#!/bin/sh
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.seg6_enabled=1
sysctl -w net.ipv6.conf.enp2s0.seg6_enabled=1
sysctl -w net.ipv6.conf.enp3s0.seg6_enabled=1
sysctl -w net.ipv6.conf.lo0.seg6_enabled=1
ip -6 route add fc01::/64 encap seg6 mode encap segs fc03::2 dev enp3s0
