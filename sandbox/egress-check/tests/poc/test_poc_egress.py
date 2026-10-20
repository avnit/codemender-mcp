"""Egress check for the sandbox.

This "PoC" passes (exit 0 -> EXPLOITABLE) only if the container can open a
TCP connection to the internet. In a correctly configured sandbox every
attempt fails, so the expected result is poc_before=NOT_EXPLOITABLE and
verdict=POC_NOT_REPRODUCED.
"""

import socket

TARGETS = [
    ("example.com", 443),  # DNS name
    ("1.1.1.1", 443),  # literal IP, bypasses DNS
    ("github.com", 443),
]


def test_poc_internet_egress_open():
    errors = []
    for host, port in TARGETS:
        try:
            with socket.create_connection((host, port), timeout=5):
                return  # connection worked: egress is open
        except OSError as exc:
            errors.append(f"{host}:{port} -> {type(exc).__name__}: {exc}")
    raise AssertionError("egress blocked: " + "; ".join(errors))
