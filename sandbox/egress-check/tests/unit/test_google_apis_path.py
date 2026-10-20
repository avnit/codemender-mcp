"""Checks that the allowed path to Google APIs is in place.

storage.googleapis.com must resolve into the restricted VIP 199.36.153.4/30
(private Cloud DNS zone on sandbox-vpc), and a TCP connection to it on 443
must work. If this fails, the runner could not have downloaded its inputs.
"""

import ipaddress
import socket

RESTRICTED_VIP = ipaddress.ip_network("199.36.153.4/30")


def test_storage_resolves_to_restricted_vip():
    addrs = {info[4][0] for info in socket.getaddrinfo("storage.googleapis.com", 443, socket.AF_INET)}
    assert addrs, "no IPv4 address for storage.googleapis.com"
    outside = [a for a in addrs if ipaddress.ip_address(a) not in RESTRICTED_VIP]
    assert not outside, f"resolved outside 199.36.153.4/30: {sorted(outside)}"


def test_storage_reachable_on_443():
    with socket.create_connection(("storage.googleapis.com", 443), timeout=5):
        pass
