#!/bin/bash -eu
cd $(dirname $0)

# gw1-client: fc01::/64, 192.168.1.0/24
# gw2-server: fc02::/64, 192.168.2.0/24
# rtr-gw1: fc03::/64
# rtr-gw2: fc04::/64
# rtr-nat: fc05::/64

# client: fc00::2
# server: fc00::3
# gw1: fc00::4
# gw2: fc00::5
# nat: fc00::6
# rtr: fc00::7

if [ $# != 1 ]; then
  CFG_DIR=$(pwd)/configs
  IMG_DIR=$(pwd)/images
  DISK_SIZE=10G
  networks=(mgmt gw1-client gw2-server rtr-gw1 rtr-gw2 rtr-nat)
  hosts=(client server gw1 gw2 nat rtr)
else
  case "$1" in
  rtr)
    EXTRA_NET="--network network:rtr-gw1 --network network:rtr-gw2 --network network:rtr-nat"
    ;;
  client)
    EXTRA_NET="--network network:gw1-client"
    ;;
  server)
    EXTRA_NET="--network network:gw2-server"
    ;;
  gw1)
    EXTRA_NET="--network network:gw1-client --network network:rtr-gw1"
    ;;
  gw2)
    EXTRA_NET="--network network:gw2-server --network network:rtr-gw2"
    ;;
  nat)
    EXTRA_NET="--network network:rtr-nat"
    ;;
  *) EXTRA_NET="" ;;
  esac
fi
