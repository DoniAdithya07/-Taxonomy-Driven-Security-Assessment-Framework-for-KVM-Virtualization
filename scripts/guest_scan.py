#!/usr/bin/env python3
"""Run inside VM A: probe VM B over TCP (no ICMP, stdlib only) and write net_scan.txt for M1 check C16.

    python guest_scan.py <vm-b-ip> [out-file]      (default out-file: net_scan.txt)

Its output is only CORROBORATION: it is written inside the VM under test, so a compromised or broken guest
can write anything. M1 check C16 takes its PASS from the host-written net_isolation.txt (python -m
vsec.collect); this file can only add a FAIL ('reachable'), never a PASS.

Result is 'isolated: 0 open ports' or 'reachable: <port>/tcp open'. A refused connection (RST) also proves
the host is reachable, so it is reported as 'reachable: <port>/tcp refused'. Only a timeout/no-route on
every port counts as isolated.
"""
import errno
import ipaddress
import socket
import sys

PORTS = (22, 80, 111, 135, 139, 443, 445, 3306, 3389, 5900, 8080)
TIMEOUT = 1.0


def probe(ip, port, timeout=TIMEOUT):
    """'open', 'refused' or 'filtered' for one TCP connect attempt."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        err = s.connect_ex((ip, port))
    if err == 0:
        return "open"
    return "refused" if err == errno.ECONNREFUSED else "filtered"


def scan(ip, ports=PORTS):
    ipaddress.ip_address(ip)  # reject hostnames and junk
    for port in ports:
        state = probe(ip, port)
        if state != "filtered":
            return f"reachable: {port}/tcp {state}"
    return "isolated: 0 open ports"


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    try:
        result = scan(sys.argv[1])
    except ValueError as e:
        sys.exit(f"bad IP address: {e}")
    with open(sys.argv[2] if len(sys.argv) == 3 else "net_scan.txt", "w", encoding="utf-8") as fh:
        fh.write(result + "\n")
    print(result)
