#!/bin/sh
sed -i 's/ospf6d=no/ospf6d=yes/g' /etc/frr/daemons
systemctl restart frr
vtysh <<EOS
configure terminal
router ospf6
 ospf6 router-id 192.168.100.6
 interface enp2s0 area 0.0.0.0
 interface lo area 0.0.0.0
exit
exit
write memory
EOS

sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.seg6_enabled=1
sysctl -w net.ipv6.conf.enp2s0.seg6_enabled=1
