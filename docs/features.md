# features.md — feature dictionary (PLAN §12)

| Feature key | Source log/record | Feeds detector |
|---|---|---|
| qname_entropy | dns.log qname | c DGA |
| ngram_log_likelihood | dns.log qname (model) | c DGA |
| qname_max_len, txt_ratio, qps | dns.log per-client window | c tunnelling |
| iat_mean_s, iat_cv, samples | conn.log ts deltas per (src,dst) | b beaconing, d sequences |
| syn_pps / udp_pps | conn.log / flow records per src | a floods |
| source_ip_entropy | flow records over window | a spoofed floods |
| fanout_distinct_targets | conn.log per src sliding window | e port scan |
| out_in_ratio, outbound_bytes | flow records per host | f exfiltration |
| ja4_hash, ja3, server_name | ssl.log handshake fields | d encrypted malware |
| packet_size_seq_dev | conn.log byte series vs baseline | d encrypted malware |

Tier dependency: c and d are packet-tier only; a/e/f flow-native; b either.
