from detectors.base import Detector  # noqa: F401

# Build order (PLAN §11): dns_family → port_scan → beaconing → floods → exfil
# → encrypted_malware. Each detector is unit-tested against its own generator
# PCAP in generators/ before the next one starts.
