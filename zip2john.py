# -*- coding: utf-8 -*-
"""
zip2john.py — Python port of John the Ripper's zip2john.c
Produces hashcat-compatible hashes:
  * $pkzip$  -> hashcat mode 17200 (ZipCrypto / traditional PKZIP)
  * $zip2$   -> hashcat modes 17210/17220/17225 (WinZip AES 128/192/256)
  * $zip3$   -> hashcat mode 17230 (PKWARE strong encryption, rare)
Authoritative reference: src/zip2john.c (john jumbo 1.9.0-jumbo-1+git20261011)
"""

import os
import struct
import sys

MAX_PKZ_FILES = 8
AES_EXTRA_DATA_LENGTH = 7
AES_AUTHENTICATION_CODE_LENGTH = 10
AES_PASSWORD_VERIFICATION_LENGTH = 2
MAX_BLOB_INLINE_SIZE = 0x400000000  # 16 GB

FLAG_ENCRYPTED = 1
FLAG_LOCAL_SIZE_UNKNOWN = 8
FLAG_STRONG_ENCRYPTION = 64


class ZipPtr(object):
    __slots__ = ("version", "flags", "cmptype", "hash_data", "file_name",
                 "offset", "offex", "cmp_len", "decomp_len", "crc", "cs",
                 "zip64", "lastmod_date", "lastmod_time", "extrafield_length",
                 "aes_vendor_version", "aes_vendor_id", "aes_strength",
                 "aes_cmptype", "aes_found")

    def __init__(self):
        self.version = 0
        self.flags = 0
        self.cmptype = 0
        self.hash_data = None
        self.file_name = None
        self.offset = 0
        self.offex = 0
        self.cmp_len = 0
        self.decomp_len = 0
        self.crc = 0
        self.cs = ""
        self.zip64 = 0
        self.lastmod_date = 0
        self.lastmod_time = 0
        self.extrafield_length = 0
        self.aes_vendor_version = 0
        self.aes_vendor_id = 0
        self.aes_strength = 0
        self.aes_cmptype = 0
        self.aes_found = 0


class ZipArchive(object):
    def __init__(self, fname, data):
        self.fname = fname
        self.data = data  # whole file bytes
        self.pos = 0
        self.basename = fname.replace("\\", "/").split("/")[-1]
        self.check_bytes = 2
        self.zip64 = 0

    def seek(self, off, whence=0):
        if whence == 0:
            self.pos = off
        elif whence == 1:
            self.pos += off
        elif whence == 2:
            self.pos = len(self.data) + off
        if self.pos < 0 or self.pos > len(self.data):
            raise ValueError("seek out of range %d" % self.pos)

    def getc(self):
        if self.pos >= len(self.data):
            return -1
        c = self.data[self.pos]
        self.pos += 1
        return c

    def expect(self, c):
        d = self.getc()
        if d == -1:
            return False
        if d != c:
            self.pos -= 1
        return d == c

    def read(self, n):
        b = self.data[self.pos:self.pos + n]
        if len(b) != n:
            raise ValueError("short read (%d/%d) at %d" % (len(b), n, self.pos))
        self.pos += n
        return b

    def u16(self):
        return struct.unpack("<H", self.read(2))[0]

    def u32(self):
        return struct.unpack("<I", self.read(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.read(8))[0]


def handle_zip64_ef(zip, p, length, is_local):
    """fp expected right after tag+size of the extra field header."""
    decomp_len = 0xFFFFFFFFFFFFFFFF
    cmp_len = 0xFFFFFFFFFFFFFFFF
    offset = 0xFFFFFFFFFFFFFFFF
    rem_len = length
    if p.zip64:
        zip.seek(length, 1)
        return
    if p.decomp_len == 0xFFFFFFFF or is_local:
        decomp_len = zip.u64()
        if p.decomp_len != 0xFFFFFFFF and decomp_len == 0:
            decomp_len = 0xFFFFFFFFFFFFFFFF
        rem_len -= 8
    if p.cmp_len == 0xFFFFFFFF or is_local:
        cmp_len = zip.u64()
        if p.cmp_len != 0xFFFFFFFF and cmp_len == 0:
            cmp_len = 0xFFFFFFFFFFFFFFFF
        rem_len -= 8
    if p.offset == 0xFFFFFFFF:
        offset = zip.u64()
        if p.offset != 0xFFFFFFFF and offset == 0:
            offset = 0xFFFFFFFFFFFFFFFF
        rem_len -= 8
    if rem_len >= 0:
        p.zip64 = 1
        if decomp_len != 0xFFFFFFFFFFFFFFFF:
            p.decomp_len = decomp_len
        if cmp_len != 0xFFFFFFFFFFFFFFFF:
            p.cmp_len = cmp_len
        if offset != 0xFFFFFFFFFFFFFFFF:
            p.offset = offset
    else:
        sys.stderr.write("Ignoring short zip64 extended field for %s\n" % p.file_name)
    zip.seek(rem_len, 1)


def handle_aes_ef(zip, p, length):
    if length != AES_EXTRA_DATA_LENGTH:
        sys.stderr.write("AES_EXTRA_DATA_LENGTH is not 7 for %s, please report this to us!\n" % p.file_name)
        zip.seek(length, 1)
        return
    p.aes_found = 1
    p.aes_vendor_version = zip.u16()
    p.aes_vendor_id = zip.u16()
    p.aes_strength = zip.getc()
    p.aes_cmptype = zip.u16()


def scan_for_data_descriptor(zip, p):
    saved_pos = zip.pos
    if p.cmp_len and p.decomp_len and p.crc:
        return
    if p.cmp_len == 0 and p.decomp_len == 0 and not (p.flags & FLAG_LOCAL_SIZE_UNKNOWN):
        return
    if (p.cmp_len or p.decomp_len or p.crc) and not (p.flags & FLAG_LOCAL_SIZE_UNKNOWN):
        return
    crc = 0
    cmp_len = 0
    decomp_len = 0
    found = False
    while zip.pos < len(zip.data):
        if zip.getc() != 0x50 or not zip.expect(0x4b):
            continue
        if zip.expect(0x07) and zip.expect(0x08):
            crc = zip.u32()
            if zip.zip64:
                cmp_len = zip.u64()
                decomp_len = zip.u64()
            else:
                cmp_len = zip.u32()
                decomp_len = zip.u32()
            found = True
            break
        if (zip.expect(0x03) and zip.expect(0x04)) or (zip.expect(0x01) and zip.expect(0x02)):
            if zip.zip64:
                zip.seek(-24, 1)
            else:
                zip.seek(-16, 1)
            crc = zip.u32()
            if zip.zip64:
                cmp_len = zip.u64()
                decomp_len = zip.u64()
            else:
                cmp_len = zip.u32()
                decomp_len = zip.u32()
            found = True
            break
    if found:
        if cmp_len > zip.pos - p.offset:
            sys.stderr.write("!? Compressed len stored after compressed data (%d) is larger than offset "
                             "between current and next file (%d)\n" % (cmp_len, zip.pos - p.offset))
        if p.cmp_len == 0:
            p.cmp_len = cmp_len
        if p.decomp_len == 0:
            p.decomp_len = decomp_len
        if p.crc == 0:
            p.crc = crc
    zip.seek(saved_pos)


def load_local_header(zip, p):
    p.offset = zip.pos - 4
    p.version = zip.u16() & 0xff
    p.flags = zip.u16()
    p.cmptype = zip.u16()
    p.lastmod_time = zip.u16()
    p.lastmod_date = zip.u16()
    if not (p.flags & FLAG_LOCAL_SIZE_UNKNOWN):
        crc = zip.u32()
        cmp_len = zip.u32()
        decomp_len = zip.u32()
        if not p.zip64:
            if crc == 0 and p.crc != 0:
                sys.stderr.write("Local CRC field is 0, but central one is %08x. Weird.\n" % p.crc)
            else:
                p.crc = crc
            if cmp_len == 0 and p.cmp_len != 0:
                sys.stderr.write("Local cmp_len field is 0, but central one is %x. Weird.\n" % p.cmp_len)
            else:
                p.cmp_len = cmp_len
            if decomp_len == 0 and p.decomp_len != 0:
                sys.stderr.write("Local decomp_len field is 0, but central one is %x. Weird.\n" % p.decomp_len)
            else:
                p.decomp_len = decomp_len
    else:
        zip.seek(12, 1)
    filename_length = zip.u16()
    p.extrafield_length = zip.u16()
    if p.file_name is not None:
        zip.seek(filename_length, 1)
    else:
        p.file_name = zip.read(filename_length).decode("utf-8", "replace")
    p.offex = 30 + filename_length + p.extrafield_length
    return 1


def process_aes(zip, p):
    if p.cmptype == 99:
        ef_remaining = p.extrafield_length
        while zip.pos < len(zip.data) and ef_remaining > 0:
            efh_id = zip.u16()
            efh_datasize = zip.u16()
            ef_remaining -= 2 + 2 + efh_datasize
            if efh_id == 0x9901:
                handle_aes_ef(zip, p, efh_datasize)
            elif efh_id == 0x0001:
                handle_zip64_ef(zip, p, efh_datasize, 1)
            else:
                zip.seek(efh_datasize, 1)
        if not p.aes_found:
            sys.stderr.write("Couldn't find (valid) extra header for type 99 AES entry for %s in %s.\n"
                             % (p.file_name, zip.fname))
            return 0
        bname = zip.basename
        if p.aes_vendor_version < 1 or p.aes_vendor_version > 2:
            sys.stderr.write("! Unknown AES encryption version: %d\n" % p.aes_vendor_version)
            return 0
        if p.aes_strength < 1 or p.aes_strength > 3:
            sys.stderr.write("! Unknown AES encryption strength: %d\n" % p.aes_strength)
            return 0
        if p.cmp_len == 0 and (p.flags & FLAG_LOCAL_SIZE_UNKNOWN):
            scan_for_data_descriptor(zip, p)
        salt_length = 4 + 4 * p.aes_strength
        salt = zip.read(salt_length)
        out = []
        out.append("%s/%s:$zip2$*0*%x*0*" % (bname, p.file_name, p.aes_strength))
        out.append(salt.hex())
        out.append("*")
        pv = zip.read(2) if zip.pos + 2 <= len(zip.data) else b""
        out.append(pv.hex())
        if p.cmp_len <= AES_PASSWORD_VERIFICATION_LENGTH + salt_length + AES_AUTHENTICATION_CODE_LENGTH:
            real_cmpr_len = 0
            sys.stderr.write("!? compressed length of AES entry too short.\n")
        else:
            real_cmpr_len = p.cmp_len - AES_PASSWORD_VERIFICATION_LENGTH - salt_length - AES_AUTHENTICATION_CODE_LENGTH
        out.append("*%x*" % real_cmpr_len)
        if real_cmpr_len > MAX_BLOB_INLINE_SIZE:
            out.append("ZFILE*%s*%x*%x" % (zip.fname, p.offset, zip.pos))
            zip.seek(real_cmpr_len, 1)
        else:
            data = zip.read(real_cmpr_len) if real_cmpr_len > 0 else b""
            out.append(data.hex())
        out.append("*")
        auth = zip.read(AES_AUTHENTICATION_CODE_LENGTH) if zip.pos + AES_AUTHENTICATION_CODE_LENGTH <= len(zip.data) else b""
        out.append(auth.hex())
        out.append("*$/zip2$:%s:%s:%s" % (p.file_name, bname, zip.fname))
        sys.stdout.write("".join(out) + "\n")
        return 1
    if (p.flags & FLAG_ENCRYPTED) and ((p.flags & FLAG_STRONG_ENCRYPTION) or p.version in (51, 52) or p.version >= 61):
        bname = zip.basename
        iv_size = zip.u16()
        if iv_size > 16:
            sys.stderr.write("No (IV too long: %d)\n" % iv_size)
            return 0
        iv = zip.read(iv_size) if iv_size else b""
        zip.u32()  # Size
        fmt = zip.u16()
        if fmt != 3:
            sys.stderr.write("No (Format == %d)\n" % fmt)
            return 0
        alg_id = zip.u16()
        if alg_id in (0x660E, 0x660F, 0x6610):
            alg_id = 1
        elif alg_id in (0x6603, 0x6609, 0x6720, 0x6721, 0x6801):
            sys.stderr.write("AlgId (%x) is currently unsupported, please report this to us!\n" % alg_id)
            return 0
        else:
            sys.stderr.write("No (Unknown AlgId)\n")
            return 0
        if iv_size == 0:
            crc = p.crc
            decomp_len = p.decomp_len
            iv = (struct.pack("<I", crc) + struct.pack("<Q", decomp_len))
            iv_size = 12
        bitlen = zip.u16()
        zip.u16()  # Flags
        erd_size = zip.u16()
        if erd_size > 256:
            sys.stderr.write("No (ErdSize too large: %d)\n" % erd_size)
            return 0
        erd = zip.read(erd_size)
        reserved1 = zip.u32()
        if reserved1 != 0:
            sys.stderr.write("Reserved1 is %d (non-zero), please report this bug to us!\n" % reserved1)
            return 0
        v_size = zip.u16()
        zip.seek(v_size, 1)
        sys.stdout.write("%s:$zip3$*0*%d*%d*0*%s*%s*0*0*0*%s\n"
                         % (bname, alg_id, bitlen, iv.hex(), erd.hex(), p.file_name))
        return 1
    return 0


def process_legacy(zip, p):
    sys.stderr.write("ver %d.%d " % (p.version // 10, p.version % 10))
    if (p.flags & FLAG_ENCRYPTED) and (p.version in (10, 20, 45)):
        extra_len_used = 0
        while extra_len_used < p.extrafield_length:
            efh_id = zip.u16()
            efh_datasize = zip.u16()
            sys.stderr.write("efh %04x " % efh_id)
            if efh_id == 0x0001:
                handle_zip64_ef(zip, p, efh_datasize, 1)
                extra_len_used += efh_datasize
                efh_datasize = 0
            zip.seek(efh_datasize, 1)
            extra_len_used += 4 + efh_datasize
        if p.version >= 20:
            zip.check_bytes = 1
        elif zip.check_bytes == 1:
            sys.stderr.write("** 2b ** ")
        scan_for_data_descriptor(zip, p)
        if p.cmptype not in (0, 8):
            sys.stderr.write("%s/%s is not encrypted, or stored with non-handled compression type=%d\n"
                             % (zip.fname, p.file_name, p.cmptype))
            return 0
        if p.flags & FLAG_LOCAL_SIZE_UNKNOWN:
            p.cs = "%02x%02x" % ((p.lastmod_time >> 8) & 0xFF, p.lastmod_time & 0xFF)
        else:
            p.cs = "%02x%02x" % ((p.crc >> 24) & 0xFF, (p.crc >> 16) & 0xFF)
        sys.stderr.write("%s/%s PKZIP%s Encr: %s%scmplen=%x, decmplen=%x, crc=%08X ts=%04X cs=%s type=%d\n"
                         % (zip.basename, p.file_name, "64" if zip.zip64 else "",
                            "2b chk, " if zip.check_bytes == 2 else "",
                            "TS_chk, " if p.flags & FLAG_LOCAL_SIZE_UNKNOWN else "",
                            p.cmp_len, p.decomp_len, p.crc, p.lastmod_time, p.cs, p.cmptype))
        p.hash_data = zip.read(p.cmp_len)
        return 1
    scan_for_data_descriptor(zip, p)
    sys.stderr.write("%s/%s is not encrypted, or stored with non-handled compression type\n"
                     % (zip.fname, p.file_name))
    zip.seek(p.extrafield_length, 1)
    zip.seek(p.cmp_len, 1)
    return 0


def move_entry(dst, src):
    dst.__init__()
    for s in ZipPtr.__slots__:
        setattr(dst, s, getattr(src, s))
    src.file_name = None
    src.hash_data = None


def handle_file_entry(ctx):
    p = ctx["curzip"]
    if not load_local_header(ctx["zip"], p):
        return
    if p.cmptype == 99:
        process_aes(ctx["zip"], p)
        return
    if not process_legacy(ctx["zip"], p):
        return
    if p.decomp_len < 4:
        sys.stderr.write("Skipping short file %s\n" % p.file_name)
        return
    best = ctx["best"]
    i = 0
    while i < len(best) and p.cmp_len >= best[i].cmp_len:
        i += 1
    if i < MAX_PKZ_FILES:
        best.insert(i, p.__copy())
        if len(best) > MAX_PKZ_FILES:
            best.pop()


def print_and_cleanup(ctx):
    best = ctx["best"]
    if len(best) == 0:
        return
    bname = ctx["zip"].basename
    filenames = best[0].file_name
    if len(best) == 1:
        fname_san = best[0].file_name.replace(":", " ")
        sys.stdout.write("%s/%s:$pkzip$%x*%x*" % (bname, fname_san, len(best), ctx["zip"].check_bytes))
    else:
        sys.stdout.write("%s:$pkzip$%x*%x*" % (bname, len(best), ctx["zip"].check_bytes))
    i = 1
    for i in range(1, len(best)):
        p = best[i]
        length = min(36, p.cmp_len)
        sys.stdout.write("1*0*%x*%x*%s*" % (p.cmptype, length, p.cs))
        sys.stdout.write(p.hash_data[:length].hex() + "*")
        if i != 0:
            filenames = filenames + ", " + p.file_name
    p = best[0]
    sys.stdout.write("2*0*%x*%x*%x*%x*%x*%x*" % (p.cmp_len, p.decomp_len, p.crc, p.offset, p.offex, p.cmptype))
    sys.stdout.write("%x*%s*" % (p.cmp_len, p.cs))
    sys.stdout.write(p.hash_data.hex() + "*")
    filenames_san = filenames.replace(":", " ")
    if len(best) > 1:
        sys.stdout.write("$/pkzip$::%s:%s:%s\n" % (bname, filenames_san, ctx["zip"].fname))
    else:
        sys.stdout.write("$/pkzip$:%s:%s::%s\n" % (filenames_san, bname, ctx["zip"].fname))


def scan_central_index(fname, data):
    zip = ZipArchive(fname, data)
    filesize = len(data)
    # find EOCD
    eocd_pos = -1
    start = max(0, filesize - (22 + 65535))
    i = filesize - 22
    while i >= start:
        if data[i] == 0x50 and i + 4 <= filesize and data[i + 1] == 0x4b and data[i + 2] == 0x05 and data[i + 3] == 0x06:
            eocd_pos = i
            break
        i -= 1
    if eocd_pos == -1:
        sys.stderr.write("Did not find End Of Central Directory.\n")
        return
    zip64 = False
    this_disk = struct.unpack_from("<H", data, eocd_pos + 4)[0]
    cd_start_disk = struct.unpack_from("<H", data, eocd_pos + 6)[0]
    if this_disk != 0 or cd_start_disk != 0:
        sys.stderr.write("Found EOCD header, but this is either a multipart archive (which are not supported), or false positive.\n")
        # fall back to scanning whole file for a valid EOCD
        eocd_pos = -1
        for j in range(len(data) - 22, max(0, len(data) - 70000) - 1, -1):
            if data[j] == 0x50 and data[j + 1] == 0x4b and data[j + 2] == 0x05 and data[j + 3] == 0x06:
                if struct.unpack_from("<H", data, j + 4)[0] == 0 and struct.unpack_from("<H", data, j + 6)[0] == 0:
                    eocd_pos = j
                    break
        if eocd_pos == -1:
            return
    # check zip64 eocd locator: 20 bytes before eocd: sig 0x07064b50
    z64loc = eocd_pos - 20
    if z64loc >= 0 and data[z64loc:z64loc + 4] == b"\x50\x4b\x06\x07":
        z64eocd_off = struct.unpack_from("<Q", data, z64loc + 8)[0]
        if data[z64eocd_off:z64eocd_off + 4] == b"\x50\x4b\x06\x06":
            zip64 = True
            num_records = struct.unpack_from("<Q", data, z64eocd_off + 32)[0]
            cd_size = struct.unpack_from("<Q", data, z64eocd_off + 40)[0]
            cd_start_offset = struct.unpack_from("<Q", data, z64eocd_off + 48)[0]
        else:
            return
    else:
        num_records = struct.unpack_from("<H", data, eocd_pos + 8)[0]
        num_records_total = struct.unpack_from("<H", data, eocd_pos + 10)[0]
        cd_size = struct.unpack_from("<I", data, eocd_pos + 12)[0]
        cd_start_offset = struct.unpack_from("<I", data, eocd_pos + 16)[0]
    zip.zip64 = 1 if zip64 else 0
    if cd_start_offset + 4 > len(data):
        sys.stderr.write("Central directory offset out of range.\n")
        return
    if data[cd_start_offset:cd_start_offset + 4] != b"\x50\x4b\x01\x02":
        sys.stderr.write("Did not find a Central Directory File Header at expected file offset %x\n" % cd_start_offset)
        return
    best = []
    ctx = {"zip": zip, "curzip": ZipPtr(), "best": best}
    pos = cd_start_offset
    n = num_records
    while n > 0:
        n -= 1
        if data[pos:pos + 4] != b"\x50\x4b\x01\x02":
            sys.stderr.write("No more Central Directory File Headers, but expected %d more.\n" % n + 1)
            return
        zip.seek(pos + 4)
        zip.u16()  # version made by
        cur = ZipPtr()
        cur.version = zip.u16() & 0xff
        cur.flags = zip.u16()
        cur.cmptype = zip.u16()
        zip.u16()  # filemtime
        zip.u16()  # filemdate
        cur.crc = zip.u32()
        cur.cmp_len = zip.u32()
        cur.decomp_len = zip.u32()
        fn_len = zip.u16()
        extra_len = zip.u16()
        comment_len = zip.u16()
        zip.u16()  # disk
        zip.u16()  # internal attrs
        zip.u32()  # external attrs
        cur.offset = zip.u32()
        cur.file_name = zip.read(fn_len).decode("utf-8", "replace")
        while extra_len >= 4:
            efh_id = zip.u16()
            efh_len = zip.u16()
            extra_len -= 4
            if efh_id == 0x0001:
                handle_zip64_ef(zip, cur, efh_len, 0)
            elif efh_id == 0x9901:
                handle_aes_ef(zip, cur, efh_len)
            else:
                zip.seek(efh_len, 1)
            extra_len -= efh_len
        old_pos = zip.pos
        zip.seek(cur.offset)
        if zip.u32() != 0x04034b50:
            sys.stderr.write("! Did not find local file header for %s at %x\n" % (cur.file_name, cur.offset))
        else:
            cur.__class__  # placeholder
            p = ZipPtr()
            for s in ZipPtr.__slots__:
                setattr(p, s, getattr(cur, s))
            ctx["curzip"] = p
            handle_file_entry(ctx)
        pos = old_pos + extra_len + comment_len
    print_and_cleanup(ctx)


# monkey-patch: copy helper
def _copy(self):
    p = ZipPtr()
    for s in ZipPtr.__slots__:
        setattr(p, s, getattr(self, s))
    if self.hash_data is not None:
        p.hash_data = self.hash_data
    return p


ZipPtr.__copy = _copy


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python zip2john.py [zip file(s)]\n")
        return 1
    for fname in sys.argv[1:]:
        try:
            with open(fname, "rb") as f:
                data = f.read()
        except OSError as e:
            sys.stderr.write("! %s : %s\n" % (fname, e))
            continue
        scan_central_index(fname, data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
