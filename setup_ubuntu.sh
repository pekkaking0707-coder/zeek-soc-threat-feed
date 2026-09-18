#!/usr/bin/env bash
# Zeek SOC Threat Feed — Ubuntu VM setup (run inside the VM)
# Usage: sudo ./setup_ubuntu.sh
set -uo pipefail

echo "== [1/4] apt packages =="
apt-get update
apt-get install -y tcpreplay hping3 nmap iperf3 slowhttptest iodine \
  python3-pip python3-venv build-essential ruby-full mergecap 2>/dev/null \
  || apt-get install -y tcpreplay hping3 nmap iperf3 slowhttptest iodine \
     python3-pip python3-venv build-essential ruby-full

echo "== [2/4] Zeek =="
if ! command -v zeek >/dev/null 2>&1; then
  if apt-get install -y zeek; then
    echo "zeek installed via apt"
  else
    cat <<'EOF'
apt has no zeek package on this release. Pick ONE:
  A) OBS repo (Ubuntu 22.04 example):
     echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' > /etc/apt/sources.list.d/zeek.list
     curl -fsSL https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg
     apt update && apt install -y zeek
  B) Docker fallback:  docker pull zeek/zeek-lts   (run with --net=host -v $(pwd):/workdir)
See BUILD_GUIDE.md section 3.3.
EOF
  fi
else
  echo "zeek already present: $(command -v zeek)"
fi

echo "== [3/4] goflow2 (flow tier) =="
if ! command -v goflow2 >/dev/null 2>&1; then
  GF_VER="2.2.4"
  curl -fL -o /tmp/goflow2.tgz \
    "https://github.com/netsampler/goflow2/releases/download/v${GF_VER}/goflow2_${GF_VER}_linux_amd64.tar.gz" \
    && tar -xzf /tmp/goflow2.tgz -C /usr/local/bin goflow2 \
    && chmod +x /usr/local/bin/goflow2 && echo "goflow2 ${GF_VER} installed" \
    || echo "WARN: goflow2 download failed - grab the binary from github.com/netsampler/goflow2/releases"
fi

echo "== [4/4] dnscat2 (optional, tunneling tool) =="
if [ ! -d /opt/dnscat2 ]; then
  git clone --depth 1 https://github.com/iagox86/dnscat2 /opt/dnscat2 2>/dev/null \
    && (cd /opt/dnscat2/server && gem install bundler:2.4.22 && bundle install) \
    || echo "WARN: dnscat2 setup skipped - generators/gen_dns_tunnel.py covers class (c) without it"
fi

echo
echo "== Phase A acceptance checks (BUILD_GUIDE.md section 5) =="
echo "1) veth topology:     sudo bash benchmarks/topology_veth.sh up"
echo "2) capture check:     zeek -i veth-t local   (in another shell)"
echo "3) replay:            tcpreplay-edit --intf1=veth-a --topspeed datasets/beaconing.pcap"
echo "4) confirm dns.log/conn.log rows appear, then Ctrl-C zeek"