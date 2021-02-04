#!/bin/sh
git clone git://git.kernel.org/pub/scm/network/iproute2/iproute2-next.git
cd iproute2-next
make
make install
cd ..

wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.11-rc6/amd64/linux-headers-5.11.0-051100rc6_5.11.0-051100rc6.202101312230_all.deb
wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.11-rc6/amd64/linux-headers-5.11.0-051100rc6-generic_5.11.0-051100rc6.202101312230_amd64.deb
wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.11-rc6/amd64/linux-image-unsigned-5.11.0-051100rc6-generic_5.11.0-051100rc6.202101312230_amd64.deb
wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.11-rc6/amd64/linux-modules-5.11.0-051100rc6-generic_5.11.0-051100rc6.202101312230_amd64.deb
apt install ./*.deb

sed -i 's/ospf6d=no/ospf6d=yes/g' /etc/frr/daemons
systemctl restart frr
vtysh <<EOS
configure terminal
router ospf6
 ospf6 router-id 192.168.100.5
 interface enp2s0 area 0.0.0.0
 interface lo area 0.0.0.0
exit
exit
write memory
EOS

# echo "net.ipv6.conf.all.seg6_enabled = 1" >>/etc/sysctl.d/50-seg6.conf
# echo "net.ipv6.conf.default.seg6_enabled = 1" >>/etc/sysctl.d/50-seg6.conf
# echo "net.ipv6.conf.all.forwarding = 1" >>/etc/sysctl.d/50-seg6.conf
# echo "net.ipv6.conf.default.forwarding = 1" >>/etc/sysctl.d/50-seg6.conf
# echo "net.ipv4.conf.all.forwarding = 1" >>/etc/sysctl.d/50-seg6.conf
# echo "net.ipv4.conf.default.forwarding = 1" >>/etc/sysctl.d/50-seg6.conf
# echo "net.ipv4.conf.all.rp_filter = 0" >>/etc/sysctl.d/50-seg6.conf
# echo "net.ipv4.conf.default.rp_filter = 0" >>/etc/sysctl.d/50-seg6.conf

cat <<\EOF >/etc/networkd-dispatcher/routable.d/enp3s0
#!/bin/sh
IP=/usr/sbin/ip
SYSCTL=/usr/sbin/sysctl

test -x $IP || exit 0
[ "$IFACE" = "enp3s0" ] || exit 0

# $SYSCTL -w "net.ipv6.conf.enp3s0.forwarding=1"
# $SYSCTL -w "net.ipv4.conf.enp3s0.forwarding=1"
# $SYSCTL -w "net.ipv6.conf.enp3s0.seg6_enabled=1"
$SYSCTL -w "net.ipv6.conf.all.forwarding=1"
$SYSCTL -w "net.ipv4.conf.all.forwarding=1"
$SYSCTL -w "net.ipv6.conf.all.seg6_enabled=1"

$IP link add dev gw type vrf table 100
$IP link set dev enp3s0 master gw up
$IP link set gw up
$SYSCTL -w "net.vrf.strict_mode=1"
# $SYSCTL -w "net.ipv4.conf.gw.rp_filter=0"
$SYSCTL -w "net.ipv4.conf.all.rp_filter=0"

$IP -6 route add fc15::100/128 encap seg6local action End.DT6 vrftable 100 dev gw
$IP -6 route add fc15::101/128 encap seg6local action End.DT4 vrftable 100 dev gw
EOF
chmod +x /etc/networkd-dispatcher/routable.d/enp3s0

cat <<\EOF >/etc/networkd-dispatcher/routable.d/enp2s0
#!/bin/sh
IP=/usr/sbin/ip

test -x $IP || exit 0
[ "$IFACE" = "enp2s0" ] || exit 0

# $SYSCTL -w "net.ipv6.conf.enp2s0.forwarding=1"
# $SYSCTL -w "net.ipv4.conf.enp2s0.forwarding=1"
# $SYSCTL -w "net.ipv6.conf.enp2s0.seg6_enabled=1"
$SYSCTL -w "net.ipv6.conf.all.forwarding=1"
$SYSCTL -w "net.ipv4.conf.all.forwarding=1"
$SYSCTL -w "net.ipv6.conf.all.seg6_enabled=1"

$IP -6 route add fc02::/64 encap seg6 mode encap segs fc14::100 dev enp2s0 table 100
$IP route add 192.168.2.0/24 encap seg6 mode encap segs fc14::101 dev enp2s0 table 100
EOF
chmod +x /etc/networkd-dispatcher/routable.d/enp2s0

reboot

# ip link add dev gw type vrf table 100
# ip link set gw up
# ip link set dev enp3s0 master gw up

# ip -6 route add fc02::/64 encap seg6 mode encap segs fc14::100 dev enp2s0 table 100
# ip -6 route add fc15::100/128 encap seg6local action End.DT6 vrftable 100 dev gw

# ip route add 192.168.2.0/24 encap seg6 mode encap segs fc14::101 dev enp2s0 table 100
# ip -6 route add fc15::101/128 encap seg6local action End.DT4 vrftable 100 dev gw
