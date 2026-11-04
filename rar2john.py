#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rar2john.py - Python port of John the Ripper's rar2john.c (1.9.0-Jumbo-1)
Extracts hashcat-compatible hash lines from encrypted RAR archives.

Output formats (same as JtR rar2john):
  RAR5          : <name>:$rar5$16$<salt-hex32>$<lg2count>$<iv-hex32>$8$<check-hex16>
  RAR3 -hp      : <name>:$RAR3$*0*<salt-hex16>*<endblock-hex32>:0::::<name>
  RAR3 -p       : <name>:$RAR3$*1*<salt-hex16>*<crc-hex8>*<pack>*<unp>*1*<data-hex>*<method>:1::<file>

hashcat modes: RAR5=13000, RAR3-hp=12500, RAR3-p=23700(uncompressed)/23800(compressed)

Usage: python rar2john.py <file.rar> [more.rar ...]
"""

import sys
import os

# ---- RAR5 constants (from rar2john.h) ----
HFL_EXTRA = 1
HFL_DATA = 2
CRYPT_VERSION = 0
CHFL_CRYPT_PSWCHECK = 1
CRYPT5_KDF_LG2_COUNT_MAX = 24
SIZE_SALT50 = 16
SIZE_PSWCHECK = 8
SIZE_PSWCHECK_CSUM = 4
SIZE_INITV = 16
HEAD_MAIN = 0x01
HEAD_FILE = 0x02
HEAD_SERVICE = 0x03
HEAD_CRYPT = 0x04
HEAD_ENDARC = 0x05
FHEXTRA_CRYPT = 0x01
FHEXTRA_CRYPT_PSWCHECK = 0x01
FHFL_UTIME = 0x0002
FHFL_CRC32 = 0x0004

# ---- RAR3 constants ----
RAR3_MAGIC = b"Rar!\x1a\x07\x00"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"
RAR_OLD_MAGIC = b"\x52\x45\x7e\x5e"


class RarReader:
    """Binary cursor with helpers mirroring rar2john.c fread-style reads."""
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.len = len(data)

    def read_u32_le(self):
        if self.pos + 4 > self.len:
            return None
        v = int.from_bytes(self.data[self.pos:self.pos + 4], 'little')
        self.pos += 4
        return v

    def read_u8(self):
        if self.pos + 1 > self.len:
            return None
        v = self.data[self.pos]
        self.pos += 1
        return v

    def read_buf(self, n):
        if self.pos + n > self.len:
            return None
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def read_vuint(self):
        """RAR5 variable-length integer (LE, 7 bits/byte, high bit = more)."""
        n = 0
        shift = 0
        for _ in range(10):
            c = self.read_u8()
            if c is None:
                return None
            n += (c & 0x7f) << shift
            shift += 7
            if (c & 0x80) == 0:
                return n
        return None

    def seek(self, n):
        self.pos += n
        if self.pos > self.len:
            self.pos = self.len


def sha256_hex(b):
    import hashlib
    return hashlib.sha256(b).digest()


# ----------------------------------------------------------------------
# RAR5
# ----------------------------------------------------------------------
def process_file5(archive_name, data):
    found = 0
    encrypted = 0
    rar5_salt = b""
    rar5_iterations = 0
    pswcheck = b""

    if data[:2] == b"MZ":
        # SFX archive: scan for RAR5 magic
        idx = data.find(RAR5_MAGIC)
        if idx < 0:
            return 0
        r = RarReader(data[idx + len(RAR5_MAGIC):])
    elif data[:8] == RAR5_MAGIC:
        r = RarReader(data[8:])
    else:
        return 0

    # ------------------------------------------------------------------
    # Walk RAR5 extra fields, look for FHEXTRA_CRYPT (mirror ProcessExtra50)
    # FieldSize vint is followed by FieldType vint + data; FieldSize value
    # covers FieldType + data (JtR: bytes_left -= vlen; bytes_left -= FieldSize).
    # ------------------------------------------------------------------
    def walk_extra_v2(extra_buf, header_type):
        nonlocal found
        er = RarReader(extra_buf)
        while er.pos < len(extra_buf):
            fsize_vint_len_start = er.pos
            flen = er.read_vuint()
            if flen is None:
                return
            ftype = er.read_vuint()
            if ftype is None:
                return
            if header_type in (HEAD_FILE, HEAD_SERVICE) and ftype == FHEXTRA_CRYPT:
                enc_version = er.read_vuint()
                flags = er.read_vuint()
                if enc_version is None or flags is None:
                    return
                if (flags & FHEXTRA_CRYPT_PSWCHECK) == 0:
                    return
                lg2count = er.read_u8()
                if lg2count is None or lg2count >= CRYPT5_KDF_LG2_COUNT_MAX:
                    return
                salt = er.read_buf(SIZE_SALT50)
                iv = er.read_buf(SIZE_INITV)
                check = er.read_buf(SIZE_PSWCHECK)
                if salt is None or iv is None or check is None:
                    return
                found += 1
                print("%s:$rar5$%d$%s$%d$%s$%d$%s" % (
                    os.path.basename(archive_name),
                    SIZE_SALT50, salt.hex(),
                    lg2count, iv.hex(),
                    SIZE_PSWCHECK, check.hex()))
                return
            # JtR: bytes_left -= FieldSize-vint-len; bytes_left -= FieldSize
            # so the next field starts after (FieldSize-vint-len + FieldSize) bytes
            vlen = er.pos - fsize_vint_len_start
            er.pos = fsize_vint_len_start + vlen + flen
            if er.pos > len(extra_buf):
                return

    # ------------------------------------------------------------------
    # read_rar5_header equivalent
    # ------------------------------------------------------------------
    def read_rar5_header():
        nonlocal encrypted, rar5_salt, rar5_iterations, pswcheck, found
        if encrypted:
            # header is encrypted: read IV directly and emit
            iv = r.read_buf(SIZE_INITV)
            if iv is None:
                return 0
            found += 1
            print("%s:$rar5$%d$%s$%d$%s$%d$%s" % (
                os.path.basename(archive_name),
                SIZE_SALT50, rar5_salt.hex(),
                rar5_iterations, iv.hex(),
                SIZE_PSWCHECK, pswcheck.hex()))
            return 0
        block_start = r.pos  # position of this header block's CRC field
        head_crc = r.read_u32_le()
        if head_crc is None:
            return 0
        bsize_vint_start = r.pos
        block_size = r.read_vuint()
        if block_size is None:
            return 0
        sizeof_vint = r.pos - bsize_vint_start
        head_size = block_size + 4 + sizeof_vint
        header_type = r.read_u8()
        if header_type is None:
            return 0
        flags = r.read_vuint()
        if flags is None:
            return 0
        extra_size = 0
        data_size = 0
        if (flags & HFL_EXTRA) != 0:
            extra_size = r.read_vuint()
            if extra_size is None:
                return 0
        if (flags & HFL_DATA) != 0:
            data_size = r.read_vuint()
            if data_size is None:
                return 0

        if header_type == HEAD_CRYPT:
            crypt_version = r.read_vuint()
            if crypt_version is None:
                return 0
            if crypt_version > CRYPT_VERSION:
                return 0
            enc_flags = r.read_vuint()
            if enc_flags is None:
                return 0
            use_pswcheck = (enc_flags & CHFL_CRYPT_PSWCHECK) != 0
            lg2count = r.read_u8()
            if lg2count is None or lg2count > CRYPT5_KDF_LG2_COUNT_MAX:
                return 0
            rar5_iterations = lg2count
            salt = r.read_buf(SIZE_SALT50)
            if salt is None:
                return 0
            rar5_salt = salt
            if use_pswcheck:
                pw = r.read_buf(SIZE_PSWCHECK)
                chk = r.read_buf(SIZE_PSWCHECK_CSUM)
                if pw is None or chk is None:
                    return 0
                if sha256_hex(pw)[:4] == chk:
                    pswcheck = pw
            encrypted = 1
        elif header_type == HEAD_MAIN:
            arc_flags = r.read_vuint()
            if arc_flags is None:
                return 0
            if (arc_flags & 0x0002) != 0:  # MHFL_VOLNUMBER
                if r.read_vuint() is None:
                    return 0
        elif header_type in (HEAD_FILE, HEAD_SERVICE):
            file_flags = r.read_vuint()
            if file_flags is None:
                return 0
            unp_size = r.read_vuint()
            if unp_size is None:
                return 0
            file_attr = r.read_vuint()
            if file_attr is None:
                return 0
            if (file_flags & FHFL_UTIME) != 0:
                if r.read_u32_le() is None:
                    return 0
            if (file_flags & FHFL_CRC32) != 0:
                if r.read_u32_le() is None:
                    return 0
            comp_info = r.read_vuint()
            if comp_info is None:
                return 0
            host_os = r.read_vuint()
            if host_os is None:
                return 0
            name_size = r.read_vuint()
            if name_size is None:
                return 0
            r.seek(name_size)
            if extra_size != 0:
                extra_buf = r.read_buf(extra_size)
                if extra_buf is not None:
                    walk_extra_v2(extra_buf, header_type)
        elif header_type == HEAD_ENDARC:
            return 0
        return block_start + head_size + data_size

    while True:
        next_pos = read_rar5_header()
        if not next_pos:
            break
        if next_pos > r.len:
            break
        r.pos = next_pos
    return 1 if found else 0


# ----------------------------------------------------------------------
# RAR3
# ----------------------------------------------------------------------
def process_file3(archive_name, data):
    """Port of rar2john.c process_file() for RAR 3.x."""
    if data[:4] == RAR_OLD_MAGIC:
        return 0
    r = RarReader(data)
    if data[:2] == b"MZ":
        idx = data.find(RAR3_MAGIC)
        if idx < 0:
            return 0
        r = RarReader(data[idx + len(RAR3_MAGIC):])
    elif data[:7] == RAR3_MAGIC:
        r = RarReader(data[7:])
    else:
        return 0

    base_aname = os.path.basename(archive_name)

    # archive header block (13 bytes)
    ah = r.read_buf(13)
    if ah is None:
        return 0
    if ah[2] != 0x73:
        return 0
    ah_flags = int.from_bytes(ah[3:5], 'little')
    ah_head_size = int.from_bytes(ah[5:7], 'little')
    if ah_flags & 0x0080:
        rtype = 0  # -hp
    else:
        rtype = 1
    if ah_head_size > 13:
        r.seek(ah_head_size - 13)

    # candidate selection (mirror JtR bestsize logic)
    class Best:
        pass
    best = Best()
    best.pack = None
    best.unp = None
    best.method = None
    best.salt = b""
    best.crc = b""
    best.data = b""
    best.fname = ""

    # -hp mode: only once, use end-of-archive block trick
    if rtype == 0:
        if len(data) < 24:
            return 0
        buf = data[-24:]
        salt = buf[:8]
        block = buf[8:24]
        print("%s:$RAR3$*%d*%s*%s:%d::::%s" % (base_aname, rtype, salt.hex(), block.hex(), rtype, archive_name))
        return 1

    while True:
        fh = r.read_buf(32)
        if fh is None:
            break
        ftype = fh[2]
        fh_flags = int.from_bytes(fh[3:5], 'little')
        fh_head_size = int.from_bytes(fh[5:7], 'little')

        if ftype != 0x74:
            # comment (0x7a) or unknown -> bail (JtR: goto BailOut)
            break

        if not (fh_flags & 0x8000):
            break  # LONG_BLOCK flag unset

        pack_size = int.from_bytes(fh[7:11], 'little')
        unp_size = int.from_bytes(fh[11:15], 'little')
        ext_time_size = fh_head_size - 32

        if fh_flags & 0x100:
            # high pack/unp sizes
            hi = r.read_buf(4)
            if hi is None:
                break
            pack_size += int.from_bytes(hi, 'little') << 32
            ext_time_size -= 4
            hi2 = r.read_buf(4)
            if hi2 is None:
                break
            unp_size += int.from_bytes(hi2, 'little') << 32
            ext_time_size -= 4

        name_size = int.from_bytes(fh[26:28], 'little')
        fname = r.read_buf(name_size)
        if fname is None:
            break
        ext_time_size -= name_size

        salt = b""
        if fh_flags & 0x400:
            ext_time_size -= 8
            salt = r.read_buf(8)
            if salt is None:
                break

        if fh_flags & 0x1000:  # EXT_TIME
            if ext_time_size > 0:
                r.seek(ext_time_size)

        # solid -> skip (JtR skips; we just continue but solid first-file rare)
        if fh_flags & 0x10:
            r.seek(pack_size)
            continue

        # directory
        if ((fh_flags & 0xe0) >> 5) == 7:
            r.seek(pack_size)
            continue

        # not encrypted
        if not (fh_flags & 0x04):
            r.seek(pack_size)
            continue

        if fh[24] < 29:
            r.seek(pack_size)
            continue

        method = fh[25]
        file_crc = fh[16:20]

        # best-candidate selection (mirror JtR)
        if best.pack is not None:
            better = False
            if best.pack < pack_size and best.unp >= (4 if best.method > 0x30 else 1):
                pass
            elif best.unp > unp_size and unp_size < (4 if method > 0x30 else 1):
                pass
            elif best.pack == pack_size:
                if best.unp > unp_size and unp_size < 8:
                    pass
                elif best.unp <= unp_size and best.unp >= 8:
                    pass
                else:
                    better = True
            else:
                better = True
            if better:
                best.pack = pack_size
                best.unp = unp_size
                best.method = method
                best.salt = salt
                best.crc = file_crc
                best.fname = fname
                cdata = r.read_buf(pack_size)
                best.data = cdata if cdata is not None else b""
                continue
            r.seek(pack_size)
            continue
        else:
            best.pack = pack_size
            best.unp = unp_size
            best.method = method
            best.salt = salt
            best.crc = file_crc
            best.fname = fname
            cdata = r.read_buf(pack_size)
            best.data = cdata if cdata is not None else b""
            continue

    if best.pack is not None:
        print("%s:$RAR3$*1*%s*%s*%d*%d*1*%s*%02x:1::%s" % (
            base_aname,
            best.salt.hex(), best.crc.hex(),
            best.pack, best.unp,
            best.data.hex(), best.method,
            best.fname.decode('utf-8', 'replace')))
        return 1
    return 0


def main():
    if len(sys.argv) < 2:
        print("Usage: python rar2john.py <file.rar> [more.rar ...]")
        return 1
    for fn in sys.argv[1:]:
        try:
            with open(fn, 'rb') as f:
                data = f.read()
        except OSError as e:
            sys.stderr.write("! %s: %s\n" % (fn, e))
            continue
        if data[:8] == RAR5_MAGIC or data[:2] == b"MZ":
            if process_file5(fn, data) == 0:
                # not RAR5 (or SFX w/o rar5 magic) - try RAR3
                if not (data[:7] == RAR3_MAGIC or (data[:2] == b"MZ" and RAR3_MAGIC in data)):
                    sys.stderr.write("! %s: Not a RAR file\n" % fn)
        else:
            process_file3(fn, data)
    return 0


if __name__ == '__main__':
    sys.exit(main())
