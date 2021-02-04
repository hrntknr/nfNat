#!/bin/bash -eu
cd $(dirname $0)

# gw1-client: fc02::/64, 192.168.2.0/24
# gw2-server: fc03::/64, 192.168.3.0/24
# gw1: fc04::1/64
# gw2: fc05::1/64
# nat: fc06::1/64
# rtr: fc07::1/64

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
  networks=(mgmt gw1-client gw2-server bb)
  hosts=(client server gw1 gw2 nat)
else
  case "$1" in
  client)
    EXTRA_NET="--network network:gw1-client"
    ;;
  server)
    EXTRA_NET="--network network:gw2-server"
    ;;
  gw1)
    EXTRA_NET="--network network:bb --network network:gw1-client"
    ;;
  gw2)
    EXTRA_NET="--network network:bb --network network:gw2-server"
    ;;
  nat)
    EXTRA_NET="--network network:bb"
    ;;
  *) EXTRA_NET="" ;;
  esac
fi
