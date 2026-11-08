#!/usr/bin/env python3
"""
DiPlay Offline & Online License Key Generator (CLI)
Usage:
  python tools/keygen.py <DEVICE_ID_OR_*> [YYYY-MM-DD|lifetime]
Examples:
  python tools/keygen.py 8F3A-9C2E-4B1D
  python tools/keygen.py 8F3A-9C2E-4B1D 2027-12-31
  python tools/keygen.py "*" lifetime
"""

import datetime
import hashlib
import hmac
import json
import sys

ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
EPOCH_2025_MS = 1735689600000
LIFETIME_DAYS = 0xFFFF


def signing_secret() -> bytes:
    part_a = [0x44, 0x69, 0x50, 0x6C, 0x61, 0x79, 0x2D, 0x4E, 0x65, 0x6F, 0x59, 0x69, 0x72, 0x61, 0x2D, 0x53]
    part_b = [0x65, 0x63, 0x72, 0x65, 0x74, 0x2D, 0x32, 0x30, 0x32, 0x36, 0x2D, 0x56, 0x31, 0x2D, 0x4B, 0x39]
    out = bytearray(32)
    for i in range(16):
        out[i] = part_a[i] ^ 0x5A
    for i in range(16):
        out[16 + i] = part_b[i] ^ 0xA5
    return bytes(out)


def normalize_code(text: str) -> str:
    text = text.upper().replace("0", "2").replace("O", "2").replace("1", "L").replace("I", "L")
    return "".join(ch for ch in text if ch in ALPHABET)


def format_chunks(text: str, length: int) -> str:
    clean = normalize_code(text)[:length]
    return "-".join(clean[i:i + 4] for i in range(0, len(clean), 4))


def encode_base32(data: bytes) -> str:
    out = []
    buffer = 0
    bits_left = 0
    for b in data:
        buffer = (buffer << 8) | (b & 0xFF)
        bits_left += 8
        while bits_left >= 5:
            index = (buffer >> (bits_left - 5)) & 0x1F
            out.append(ALPHABET[index])
            bits_left -= 5
    if bits_left > 0:
        index = (buffer << (5 - bits_left)) & 0x1F
        out.append(ALPHABET[index])
    return "".join(out)


def compute_device_tag(clean_device: str) -> int:
    digest = hashlib.sha256(("DIPLAY-DEV:" + clean_device).encode("utf-8")).digest()
    tag = ((digest[0] & 0xFF) << 8) | (digest[1] & 0xFF)
    return 1 if tag == 0 else tag


def generate_key(device_id: str, expiry: str = "lifetime") -> str:
    universal = device_id.strip() == "*" or normalize_code(device_id) == ""
    clean_dev = "" if universal else normalize_code(device_id)
    if not universal and len(clean_dev) != 12:
        raise ValueError("Device ID must be 12 characters (e.g. 8F3A-9C2E-4B1D) or '*'")

    if expiry.lower() in ("lifetime", "permanent", "never", ""):
        expiry_days = LIFETIME_DAYS
    else:
        dt = datetime.datetime.strptime(expiry.strip(), "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
        expiry_days = int((int(dt.timestamp() * 1000) - EPOCH_2025_MS) // 86400000)
        if not (1 <= expiry_days < LIFETIME_DAYS):
            raise ValueError("Expiry date must be after 2025-01-01")

    device_tag = 0 if universal else compute_device_tag(clean_dev)
    payload = bytes([
        (device_tag >> 8) & 0xFF,
        device_tag & 0xFF,
        (expiry_days >> 8) & 0xFF,
        expiry_days & 0xFF,
    ])
    target = "UNIVERSAL" if universal else clean_dev
    sig = hmac.new(signing_secret(), payload + target.encode("utf-8"), hashlib.sha256).digest()[:6]
    raw = bytearray(10)
    for i in range(4):
        raw[i] = payload[i] ^ sig[i]
    for i in range(6):
        raw[4 + i] = sig[i]
    return format_chunks(encode_base32(bytes(raw)), 16)


if __name__ == "__main__":
    dev = sys.argv[1] if len(sys.argv) > 1 else "*"
    exp = sys.argv[2] if len(sys.argv) > 2 else "lifetime"
    key = generate_key(dev, exp)
    print(f"Device ID   : {'* (Universal)' if dev.strip() == '*' else format_chunks(dev, 12)}")
    print(f"Expires     : {exp}")
    print(f"License Key : {key}")
