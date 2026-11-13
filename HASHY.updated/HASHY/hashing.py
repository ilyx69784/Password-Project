# hashing.py
"""
Reference hash functions used ONLY to build documented, reproducible sample
breach data and test fixtures.

NTLM = MD4(UTF-16LE(password)). hashlib's MD4 is often unavailable on
OpenSSL 3 builds, so a small pure-Python MD4 (RFC 1320) is included.
Nothing here is used to crack or reverse hashes.
"""
import hashlib
import struct


def _rotl(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def md4(data: bytes) -> bytes:
    msg = bytearray(data)
    bit_len = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    f = lambda x, y, z: (x & y) | (~x & z)
    g = lambda x, y, z: (x & y) | (x & z) | (y & z)
    h = lambda x, y, z: x ^ y ^ z

    for off in range(0, len(msg), 64):
        X = struct.unpack("<16I", msg[off:off + 64])
        aa, bb, cc, dd = a, b, c, d
        for i in (0, 4, 8, 12):
            a = _rotl(a + f(b, c, d) + X[i], 3)
            d = _rotl(d + f(a, b, c) + X[i + 1], 7)
            c = _rotl(c + f(d, a, b) + X[i + 2], 11)
            b = _rotl(b + f(c, d, a) + X[i + 3], 19)
        for i in (0, 1, 2, 3):
            a = _rotl(a + g(b, c, d) + X[i] + 0x5A827999, 3)
            d = _rotl(d + g(a, b, c) + X[i + 4] + 0x5A827999, 5)
            c = _rotl(c + g(d, a, b) + X[i + 8] + 0x5A827999, 9)
            b = _rotl(b + g(c, d, a) + X[i + 12] + 0x5A827999, 13)
        for i in (0, 2, 1, 3):
            a = _rotl(a + h(b, c, d) + X[i] + 0x6ED9EBA1, 3)
            d = _rotl(d + h(a, b, c) + X[i + 8] + 0x6ED9EBA1, 9)
            c = _rotl(c + h(d, a, b) + X[i + 4] + 0x6ED9EBA1, 11)
            b = _rotl(b + h(c, d, a) + X[i + 12] + 0x6ED9EBA1, 15)
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d)


def ntlm_hex(password: str) -> str:
    return md4(password.encode("utf-16-le")).hex().upper()


def md5_hex(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest().upper()
