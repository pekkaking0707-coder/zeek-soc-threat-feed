#!/usr/bin/env bash
# Single-VM lab topology: attacker namespace <-> veth pair <-> target namespace.
# Zeek captures on veth-t INSIDE the target namespace (PLAN §4 ingest).
# Usage:   sudo bash benchmarks/topology_veth.sh up    # create
#          sudo bash benchmarks/topology_veth.sh down  # tear down
set -euo pipefail

UP() {
  ip netns add att 2>/dev/null || true
  ip netns add tgt 2>/dev/null || true
  ip link add veth-a type veth peer name veth-t 2>/dev/null || true
  ip link set veth-a netns att
  ip link set veth-t netns tgt
  ip -n att addr add 10.200.0.1/24 dev veth-a 2>/dev/null || true
  ip -n tgt addr add 10.200.0.2/24 dev veth-t 2>/dev/null || true
  ip -n att link set veth-a up
  ip -n tgt link set veth-t up
  ip netns exec att ip neigh flush all 2>/dev/null || true

  cat <<'EOF'
Topology up. Traffic path: att(10.200.0.1) -> veth-a => veth-t -> tgt(10.200.0.2)

Terminal 1 (capture):
  ip netns exec tgt zeek -i veth-t local

Terminal 2 (attack / replay from attacker side):
  ip netns exec att hping3 -S --flood -p 80 10.200.0.2
  ip netns exec att nmap -sT -T4 -p- 10.200.0.2
  ip netns exec att tcpreplay-edit --intf1=veth-a --topspeed datasets/beaconing.pcap

Target services (inside tgt): start iperf3/nginx/etc. as needed:
  ip netns exec tgt iperf3 -s
EOF
}

DOWN() {
  ip -n att link del veth-a 2>/dev/null || true
  ip netns del att 2>/dev/null || true
  ip netns del tgt 2>/dev/null || true
  echo "topology down"
}

case "${1:-up}" in
  up) UP ;;
  down) DOWN ;;
  *) echo "usage: $0 {up|down}"; exit 1 ;;
esac
