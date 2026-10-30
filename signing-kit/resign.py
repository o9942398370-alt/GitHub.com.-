#!/usr/bin/env python3
"""Rename app label inside servers.apk and re-sign (APK Signature Scheme v2)."""
import struct, zipfile, zlib, hashlib, sys, io
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

SRC, DST, P12, PW, NEW = sys.argv[1:6]

# ---------- 1) patch binary AndroidManifest.xml string pool ----------
def patch_manifest(d, old, new):
    d = bytearray(d)
    p = 8
    t, hs, sz, n, sn, fl, so, sto = struct.unpack('<HHIIIIII', d[p:p+28])
    assert t == 1 and not (fl & 0x100), "expected UTF-16 pool"
    offs = struct.unpack('<%dI' % n, d[p+28:p+28+4*n])
    base = p + so
    strs = []
    for o in offs:
        q = base + o
        l = struct.unpack('<H', d[q:q+2])[0]
        strs.append(d[q+2:q+2+2*l].decode('utf-16le'))
    assert strs.count(old) == 1
    strs[strs.index(old)] = new
    blob = bytearray(); new_offs = []
    for s in strs:
        new_offs.append(len(blob))
        blob += struct.pack('<H', len(s)) + s.encode('utf-16le') + b'\0\0'
    while len(blob) % 4: blob += b'\0'
    new_so = 28 + 4*n
    new_sz = new_so + len(blob)
    pool = struct.pack('<HHIIIIII', 1, 28, new_sz, n, 0, fl, new_so, 0)
    pool += struct.pack('<%dI' % n, *new_offs) + blob
    rest = d[p+sz:]
    out = bytearray(struct.pack('<HHI', 3, 8, 8 + len(pool) + len(rest)))
    return bytes(out + pool + rest)

zin = zipfile.ZipFile(SRC)
entries = []
for zi in zin.infolist():
    data = zin.read(zi.filename)
    if zi.filename == 'AndroidManifest.xml':
        data = patch_manifest(data, 'servers', NEW)
    entries.append((zi.filename, data, zi.compress_type))

# ---------- 2) write aligned zip ----------
out = io.BytesIO(); cd = io.BytesIO()
for name, data, ct in entries:
    nb = name.encode()
    crc = zlib.crc32(data) & 0xffffffff
    if ct == zipfile.ZIP_DEFLATED:
        c = zlib.compressobj(9, zlib.DEFLATED, -15); comp = c.compress(data) + c.flush(); method = 8
    else:
        comp = data; method = 0
    off = out.tell()
    extra = b''
    if method == 0:
        pad = (-(off + 30 + len(nb))) % 4
        extra = b'\0' * pad
    out.write(struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, 0x0800, method, 0, 0x21, crc, len(comp), len(data), len(nb), len(extra)))
    out.write(nb); out.write(extra); out.write(comp)
    cd.write(struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 0x0314, 20, 0x0800, method, 0, 0x21, crc, len(comp), len(data), len(nb), 0, 0, 0, 0, 0, off))
    cd.write(nb)
sections_1 = out.getvalue()
cd_bytes = cd.getvalue()
def eocd(cd_off):
    return struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, len(entries), len(entries), len(cd_bytes), cd_off, 0)

# ---------- 3) v2 signature ----------
key, cert, _ = pkcs12.load_key_and_certificates(open(P12, 'rb').read(), PW.encode())
cert_der = cert.public_bytes(Encoding.DER)
pub_der = cert.public_key().public_bytes(Encoding.DER, __import__('cryptography').hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo)

def chunked_digest(parts):
    chunk_digs = []
    for part in parts:
        for i in range(0, len(part), 1 << 20):
            c = part[i:i + (1 << 20)]
            chunk_digs.append(hashlib.sha256(b'\xa5' + struct.pack('<I', len(c)) + c).digest())
    return hashlib.sha256(b'\x5a' + struct.pack('<I', len(chunk_digs)) + b''.join(chunk_digs)).digest()

def lp(b): return struct.pack('<I', len(b)) + b

def sign_block(sec1_len):
    # EOCD for digest uses cd offset == start of signing block == len(sections_1)
    digest = chunked_digest([sections_1, cd_bytes, eocd(len(sections_1))])
    ALG = 0x0103  # RSASSA-PKCS1-v1_5 with SHA2-256
    digests = lp(struct.pack('<I', ALG) + lp(digest))
    signed_data = lp(digests) + lp(lp(cert_der)) + lp(b'')
    sig = key.sign(signed_data if False else lp(digests) + lp(lp(cert_der)) + lp(b''), padding.PKCS1v15(), hashes.SHA256())
    signer = lp(signed_data) + lp(lp(struct.pack('<I', ALG) + lp(sig))) + lp(pub_der)
    v2 = lp(lp(signer))
    pair = struct.pack('<Q', 4 + len(v2)) + struct.pack('<I', 0x7109871a) + v2
    size = len(pair) + 24
    return struct.pack('<Q', size) + pair + struct.pack('<Q', size) + b'APK Sig Block 42'

block = sign_block(len(sections_1))
final = sections_1 + block + cd_bytes + eocd(len(sections_1) + len(block))
open(DST, 'wb').write(final)
print('wrote', DST, len(final))
