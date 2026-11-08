# DNSBench a simple dns benchmarker

this program can find and benchmark dns for you to find your best dns

# Feutuers

- IPv4 and IPv6 DNS servers
- A and AAAA queries
- UDP DNS queries with an actual per-query timeout
- TCP fallback when a DNS response is truncated
- Success, failure and timeout statistics
- Average, minimum, maximum, median, P95 and P99 latency
- Randomized domain order
- CSV export
- Command-line arguments and input-file support

# Install

```bash
git clone https://github.com/ParsaAzima/DNSBench
cd DNSBench
gcc dnsbench.c -o dnsbench \
    -O2 -Wall -Wextra -Wpedantic \
    -std=c11 -lresolv
./dnsbench
```

# Help

```bash
-s, --servers FILE       DNS server list\n
-d, --domains FILE       Domain list\n
-n, --iterations NUM     Number of iterations\n
-t, --timeout SEC        Per-query timeout\n
-p, --port PORT          DNS server port\n
-4, --ipv4               Enable A queries only\n
-6, --ipv6               Enable AAAA queries only\n
-r, --random             Randomize domain order\n
-o, --output FILE        Export results to CSV\n
-v, --verbose            Verbose output\n
-h, --help               Show help\n
-V, --version            Show version\n\n"

```

# Author

ParsaAzima
