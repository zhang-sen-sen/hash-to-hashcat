#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
7z2john.py - Python port of the core extraction logic of John the Ripper's
7z2john.pl, producing hashcat-compatible $7z$ hash lines (hashcat -m 11600)
for AES-256 encrypted 7-Zip archives.

Supported:
  - raw header (kHeader) and encoded header (kEncodedHeader)
  - header-encrypted archives ("encrypt file names"): emits hash for the
    encoded-header stream
  - encoded-but-not-encrypted headers: decompresses them (LZMA1/LZMA2 via
    Python lzma) to reach the real MainStreamsInfo
  - single-folder archives; multi-folder emits one line per AES folder

Output: <name>:$7z$<type>$<cycles>$<salt_len>$<salt_hex>$<iv_len>$<iv_hex>$
<crc>$<data_len>$<unpack_size>$<data_hex>

Usage: python 7z2john.py <file.7z> [more.7z ...]
"""

import sys
import os
import struct
import zlib
import lzma

SEVEN_ZIP_MAGIC = b"\x37\x7a\xbc\xaf\x27\x1c"

K_END = 0x00
K_HEADER = 0x01
K_ARCHIVE_PROPERTIES = 0x02
K_ADDITIONAL_STREAMS_INFO = 0x03
K_MAIN_STREAMS_INFO = 0x04
K_FILES_INFO = 0x05
K_PACK_INFO = 0x06
K_UNPACK_INFO = 0x07
K_SUBSTREAMS_INFO = 0x08
K_SIZE = 0x09
K_CRC = 0x0A
K_FOLDER = 0x0B
K_CODERS_UNPACK_SIZE = 0x0C
K_NUM_UNPACK_STREAM = 0x0D
K_ENCODED_HEADER = 0x17

SEVEN_ZIP_AES = b"\x06\xf1\x07\x01"
SEVEN_ZIP_AES_OLD = b"\x06\x06"
SEVEN_ZIP_LZMA2 = b"\x21"
SEVEN_ZIP_LZMA1 = b"\x03\x01\x01"
SEVEN_ZIP_PPMD = b"\x03\x04\x01"
SEVEN_ZIP_BZIP2 = b"\x04\x02\x02"
SEVEN_ZIP_DEFLATE = b"\x04\x01\x08"
SEVEN_ZIP_COPY = b"\x00"

TYPE_MAP = {
    "lzma1": 1, "lzma2": 2, "ppmd": 3, "bzip2": 6, "deflate": 7, "copy": 0,
}
DEFAULT_POWER = 19
DEFAULT_IV = b"\x00" * 16


class NumReader:
    """7z 'Number' encoding: big-endian continuation (7z2john.pl read_number)."""

    def __init__(self, data):
        self.d = data
        self.pos = 0

    def u8(self):
        if self.pos >= len(self.d):
            raise EOFError
        v = self.d[self.pos]
        self.pos += 1
        return v

    def take(self, n):
        if self.pos + n > len(self.d):
            raise EOFError
        v = self.d[self.pos:self.pos + n]
        self.pos += n
        return v

    def number(self):
        b = self.u8()
        if (b & 0x80) == 0:
            return b
        value = self.u8()
        for i in range(1, 8):
            mask = 0x80 >> i
            if (b & mask) == 0:
                high = b & (mask - 1)
                value |= (high << (i * 8))
                return value
            value |= (self.u8() << (i * 8))
        return value

    def id(self):
        return self.number()


def crc32(data):
    return zlib.crc32(data) & 0xffffffff


def get_decoder_properties(props):
    salt_len, salt_buf, iv_len, iv_buf, cycles = 0, b"", 16, DEFAULT_IV, DEFAULT_POWER
    if not props:
        return salt_len, salt_buf, iv_len, iv_buf, cycles
    first_byte = props[0]
    cycles = first_byte & 0x3f
    if (first_byte & 0xc0) == 0:
        return salt_len, salt_buf, iv_len, iv_buf, cycles
    salt_len = (first_byte >> 7) & 1
    iv_len = (first_byte >> 6) & 1
    second_byte = props[1]
    salt_len += (second_byte >> 4)
    iv_len += (second_byte & 0x0f)
    offset = 2
    salt_buf = props[offset:offset + salt_len]
    offset += salt_len
    iv_buf = props[offset:offset + iv_len]
    iv_buf = (iv_buf + b"\x00" * 16)[:16]
    return salt_len, salt_buf, iv_len, iv_buf, cycles


def coder_type(method_id):
    if method_id == SEVEN_ZIP_LZMA2:
        return "lzma2"
    if method_id == SEVEN_ZIP_LZMA1:
        return "lzma1"
    if method_id == SEVEN_ZIP_PPMD:
        return "ppmd"
    if method_id == SEVEN_ZIP_BZIP2:
        return "bzip2"
    if method_id == SEVEN_ZIP_DEFLATE:
        return "deflate"
    if method_id == SEVEN_ZIP_COPY:
        return "copy"
    return None


def read_folder(r):
    num_coders = r.number()
    coders = []
    sum_in = 0
    sum_out = 0
    bindpairs = []
    for _ in range(num_coders):
        main_byte = r.u8()
        if main_byte & 0xC0:
            raise ValueError("bad coder byte")
        codec_id_size = main_byte & 0xf
        codec_id = r.take(codec_id_size)
        num_in, num_out = 1, 1
        props = b""
        if main_byte & 0x10:
            num_in = r.number()
            num_out = r.number()
        if main_byte & 0x20:
            props_size = r.number()
            props = r.take(props_size)
        sum_in += num_in
        sum_out += num_out
        coders.append({"id": codec_id, "props": props})
    index_main_stream = 0
    if sum_in != 1 or sum_out != 1:
        input_used = [0] * sum_in
        output_used = [0] * sum_out
        number_bindpairs = sum_out - 1
        for _ in range(number_bindpairs):
            idx_in = r.number()
            idx_out = r.number()
            input_used[idx_in] = 1
            output_used[idx_out] = 1
            bindpairs.append((idx_in, idx_out))
        sum_packed = sum_in - number_bindpairs
        if sum_packed != 1:
            for _ in range(sum_packed):
                r.number()  # packed stream index, ignored
        index_main_stream = -1
        for i in range(sum_out):
            if output_used[i] == 0:
                index_main_stream = i
                break
    return {
        "coders": coders,
        "index_main_stream": index_main_stream,
        "sum_input_streams": sum_in,
        "sum_output_streams": sum_out,
        "bindpairs": bindpairs,
    }


def read_digests(r, number_items):
    """7z digests: first byte 0xFF -> all defined; else first byte is the
    first bitmap byte (remaining ceil(n/8)-1 bytes follow), then crcs."""
    defined = []
    if number_items == 0:
        return defined
    first = r.u8()
    if first == 0xFF:
        defined = [True] * number_items
    else:
        bits = first
        mask = 0x80
        for i in range(number_items):
            if i > 0 and i % 8 == 0:
                bits = r.u8()
                mask = 0x80
            # accept either bit0-first or bit7-first convention
            defined.append(bool((bits & mask) or (bits & (1 << (i % 8)))))
            mask >>= 1
    crcs = []
    for _ in range(number_items):
        v = 0
        for i in range(4):
            v |= (r.u8() << (8 * i))
        crcs.append(v)
    return list(zip(defined, crcs))


def parse_pack_info(r):
    pack_pos = r.number()
    num_pack_streams = r.number()
    pack_sizes = []
    crcs = None
    while True:
        try:
            ident = r.id()
        except EOFError:
            break
        if ident == K_END:
            break
        if ident == K_SIZE:
            for _ in range(num_pack_streams):
                pack_sizes.append(r.number())
        elif ident == K_CRC:
            digests = read_digests(r, num_pack_streams)
            crcs = [c for _, c in digests]
        else:
            # unknown property: skip by scanning to kEnd is unsafe here, but
            # 7z properties always have their own structure; bail to avoid
            # misalignment
            raise ValueError("unknown pack property id 0x%02x" % ident)
    return {"pack_pos": pack_pos, "num_pack_streams": num_pack_streams,
            "pack_sizes": pack_sizes, "crcs": crcs}


def parse_unpack_info(r):
    # wait for kFolder
    while True:
        ident = r.id()
        if ident == K_END:
            return None
        if ident == K_FOLDER:
            break
        raise ValueError("expected folder, got 0x%02x" % ident)
    number_folders = r.number()
    external = r.u8()
    folders = []
    coder_unpack_sizes = []
    sum_coders_output_streams = 0
    if external == 0:
        for _ in range(number_folders):
            folder = read_folder(r)
            folders.append(folder)
            coder_unpack_sizes.append(sum_coders_output_streams)
            sum_coders_output_streams += folder["sum_output_streams"]
    elif external == 1:
        for _ in range(number_folders):
            r.number()  # datastream index, ignore
    else:
        raise ValueError("bad external flag")
    # wait for kCodersUnpackSize
    while True:
        ident = r.id()
        if ident == K_END:
            return None
        if ident == K_CODERS_UNPACK_SIZE:
            break
        raise ValueError("expected coders unpack size, got 0x%02x" % ident)
    unpack_sizes = []
    for _ in range(sum_coders_output_streams):
        unpack_sizes.append(r.number())
    digests = None
    while True:
        try:
            ident = r.id()
        except EOFError:
            break
        if ident == K_END:
            break
        if ident == K_CRC:
            digests = read_digests(r, number_folders)
        else:
            raise ValueError("unknown unpack property 0x%02x" % ident)
    return {"folders": folders, "unpack_sizes": unpack_sizes,
            "digests": digests, "number_folders": number_folders,
            "coder_unpack_sizes": coder_unpack_sizes}


def read_digests(r, number_items):
    """7z Digests: one boolean vector byte block then number_items x 4-byte
    little-endian CRCs (CRCs are read for EVERY item, defined or not)."""
    first = r.u8()
    defined = []
    if first == 0xFF:
        defined = [True] * number_items
    else:
        bits = first
        for i in range(number_items):
            if i % 8 == 0 and i > 0:
                bits = r.u8()
            mask = 0x80 >> (i % 8)
            defined.append((bits & mask) != 0)
    digests = []
    for _ in range(number_items):
        crc = int.from_bytes(r.take(4), 'little')
        digests.append(crc)
    return list(zip(defined, digests))


def parse_substreams_info(r, unpack_info):
    number_folders = unpack_info["number_folders"]
    num_unpack_streams = [1] * number_folders
    substream_sizes = []
    digests = None
    while True:
        try:
            ident = r.id()
        except EOFError:
            break
        if ident == K_END:
            break
        if ident == K_NUM_UNPACK_STREAM:
            num_unpack_streams = []
            for _ in range(number_folders):
                num_unpack_streams.append(r.number())
        elif ident == K_SIZE:
            for i in range(number_folders):
                n = num_unpack_streams[i]
                if n == 0:
                    continue
                total = 0
                for _ in range(n - 1):
                    size = r.number()
                    substream_sizes.append(size)
                    total += size
                folder_unpack = get_folder_unpack_size(unpack_info, i)
                if folder_unpack < total:
                    raise ValueError("substream sizes exceed folder unpack size")
                substream_sizes.append(folder_unpack - total)
        elif ident == K_CRC:
            total = sum(num_unpack_streams)
            digests = read_digests(r, total)
        else:
            raise ValueError("unknown substream property 0x%02x" % ident)
    return {"num_unpack_streams": num_unpack_streams,
            "substream_sizes": substream_sizes, "digests": digests}


def parse_streams_info(r):
    pack_info = None
    unpack_info = None
    substreams_info = None
    while True:
        try:
            ident = r.id()
        except EOFError:
            break
        if ident == K_END:
            break
        if ident == K_PACK_INFO:
            pack_info = parse_pack_info(r)
        elif ident == K_UNPACK_INFO:
            unpack_info = parse_unpack_info(r)
        elif ident == K_SUBSTREAMS_INFO:
            substreams_info = parse_substreams_info(r, unpack_info)
        else:
            # unknown / not needed (e.g. kStartPos)
            raise ValueError("unknown streams property 0x%02x" % ident)
    return {"pack_info": pack_info, "unpack_info": unpack_info,
            "substreams_info": substreams_info}


def get_folder_unpack_size(unpack_info, folder_index):
    idx = unpack_info["coder_unpack_sizes"][folder_index] + \
        unpack_info["folders"][folder_index]["index_main_stream"]
    return unpack_info["unpack_sizes"][idx]


def folder_has_aes(folder):
    for c in folder["coders"]:
        if c["id"] in (SEVEN_ZIP_AES, SEVEN_ZIP_AES_OLD):
            return True
    return False


def extract_hash(archive_name, fdata, streams, position_after_header):
    """Emit $7z$ lines for every AES folder in streams."""
    pack_info = streams["pack_info"]
    unpack_info = streams["unpack_info"]
    substreams_info = streams["substreams_info"]
    if pack_info is None or unpack_info is None:
        return 0
    folders = unpack_info["folders"]
    if substreams_info is not None:
        nums = substreams_info["num_unpack_streams"]
    else:
        nums = [1] * len(folders)
    if len(nums) != len(folders):
        nums = [1] * len(folders)

    stream_index = 0
    emitted = 0
    for folder_pos, folder in enumerate(folders):
        aes_coder = None
        comp_type = None
        for c in folder["coders"]:
            if c["id"] in (SEVEN_ZIP_AES, SEVEN_ZIP_AES_OLD):
                aes_coder = c
            else:
                t = coder_type(c["id"])
                if t is not None:
                    comp_type = t
        if aes_coder is None:
            stream_index += nums[folder_pos]
            continue
        salt_len, salt_buf, iv_len, iv_buf, cycles = get_decoder_properties(aes_coder["props"])
        if comp_type is None:
            comp_type = "copy"

        crc = None
        unpack_size = None
        if substreams_info is not None:
            sub_digests = substreams_info["digests"]
            sub_sizes = substreams_info["substream_sizes"]
            total = sum(nums[:folder_pos])
            if sub_digests is not None and len(sub_digests) > total:
                # 7-Zip writes the digests vector with LSB-first semantics for
                # the boolean bitmap, while JtR reads it MSB-first; empirically
                # the crc VALUE is always present and correct, so use it
                # regardless of the defined flag
                crc = sub_digests[total][1]
            if sub_sizes and len(sub_sizes) > total:
                unpack_size = sub_sizes[total]
        if crc is None and unpack_info["digests"] is not None:
            if folder_pos < len(unpack_info["digests"]):
                crc = unpack_info["digests"][folder_pos][1]
        if unpack_size is None:
            try:
                unpack_size = get_folder_unpack_size(unpack_info, folder_pos)
            except IndexError:
                pass
        if crc is None or unpack_size is None:
            stream_index += nums[folder_pos]
            continue

        data_len = 0
        data_off = 0
        if pack_info["pack_sizes"] and stream_index < len(pack_info["pack_sizes"]):
            data_len = pack_info["pack_sizes"][stream_index]
            data_off = sum(pack_info["pack_sizes"][:stream_index])
        if data_len == 0:
            stream_index += nums[folder_pos]
            continue
        abs_off = position_after_header + pack_info["pack_pos"] + data_off
        if abs_off + data_len > len(fdata):
            stream_index += nums[folder_pos]
            continue
        data = fdata[abs_off:abs_off + data_len]

        typ = TYPE_MAP.get(comp_type, 0)
        line = "$7z$%d$%d$%d$%s$%d$%s$%u$%d$%d$%s" % (
            typ, cycles, salt_len, salt_buf.hex(),
            iv_len, iv_buf.hex(),
            crc, data_len, unpack_size, data.hex())
        if typ not in (0, 128):
            # compressed streams need two extra fields: crc_len (unpacked size
            # of the first stream, used by hashcat as CRC length over the
            # decompressed data) and the compression attributes (props hex,
            # or per-coder "((type<<4)+codec_count)_hex" comma-joined lists
            # when multiple coders / preprocessors are present)
            crc_len = 0
            if substreams_info is not None and substreams_info["substream_sizes"]:
                crc_len = substreams_info["substream_sizes"][0]
            if crc_len == 0:
                # no SubstreamsInfo (single-file folder): the digest covers the
                # whole unpacked stream
                crc_len = unpack_size
            items = []
            aes_idx = None
            for i, c in enumerate(folder["coders"]):
                if c["id"] == SEVEN_ZIP_AES:
                    aes_idx = i
                    break
            if aes_idx is not None:
                for c in folder["coders"][aes_idx + 1:]:
                    t = coder_type(c["id"])
                    if t is None:
                        continue
                    items.append((t, c["props"].hex() if c["props"] else ""))
            comp_attrs, pre_attrs = _build_additional_attributes(items)
            attrs = comp_attrs
            if pre_attrs:
                attrs += "$" + pre_attrs
            line += "$%d$%s" % (crc_len, attrs)
        print("%s:%s" % (os.path.basename(archive_name), line))
        emitted += 1
        stream_index += nums[folder_pos]
    return emitted


def _build_additional_attributes(items):
    """items = list of (type, props_hex) for coders after the AES coder.
    Mirrors 7z2john.pl check_attributes: single compressor => plain props hex,
    otherwise comma-joined ((type<<4)+codec_count)_propshex entries."""
    compression_attributes = ""
    preprocessor_attributes = ""
    compressor_count = 0
    preprocessor_count = 0
    codec_count = 0
    type_of_compression = 0
    for cur_type, attr in items:
        # note: preprocessor detection (delta 0x03 / bcj / x86) is not needed
        # for the compressors we emit (lzma/lzma2/deflate/bzip2/ppmd); treat
        # all as compressors for now
        compressor_count += 1
        if compressor_count == 1:
            type_of_compression = cur_type
            if preprocessor_count == 0:
                compression_attributes = attr
            else:
                compression_attributes = "," + str((cur_type << 4) + codec_count) + "_" + attr
        else:
            compression_attributes += "," + str((cur_type << 4) + codec_count) + "_" + attr
        codec_count += 1
    return compression_attributes, preprocessor_attributes


def decode_folder_stream(fdata, streams, position_after_header):
    """Decompress an encoded (non-encrypted) header stream. Returns bytes or None."""
    pack_info = streams["pack_info"]
    unpack_info = streams["unpack_info"]
    if pack_info is None or unpack_info is None or not unpack_info["folders"]:
        return None
    folder = unpack_info["folders"][0]
    # find compression coder
    comp = None
    for c in folder["coders"]:
        t = coder_type(c["id"])
        if t is not None:
            comp = c
    if comp is None:
        return None
    data_len = pack_info["pack_sizes"][0]
    abs_off = position_after_header + pack_info["pack_pos"]
    if abs_off + data_len > len(fdata):
        return None
    raw = fdata[abs_off:abs_off + data_len]
    try:
        if comp["id"] == SEVEN_ZIP_LZMA2:
            return lzma.decompress(raw, format=lzma.FORMAT_RAW,
                                   filters=[{"id": lzma.FILTER_LZMA2}])
        if comp["id"] == SEVEN_ZIP_LZMA1:
            props = comp["props"]
            if len(props) >= 5:
                # 7z LZMA1 streams carry no end-of-stream marker; python's raw
                # decoder refuses them. FORMAT_ALONE lets us supply the
                # uncompressed size explicitly instead.
                unpack_size = 0
                try:
                    unpack_size = get_folder_unpack_size(unpack_info, 0)
                except Exception:
                    pass
                if unpack_size == 0 and unpack_info["unpack_sizes"]:
                    unpack_size = sum(unpack_info["unpack_sizes"])
                hdr = props[:5] + struct.pack("<Q", unpack_size)
                return lzma.decompress(hdr + raw, format=lzma.FORMAT_ALONE)
            return lzma.decompress(raw, format=lzma.FORMAT_RAW,
                                   filters=[{"id": lzma.FILTER_LZMA1,
                                             "dict_size": 1 << 24}])
        if comp["id"] == SEVEN_ZIP_DEFLATE:
            return zlib.decompress(raw, -15)
    except Exception:
        return None
    return None


def process_records(archive_name, fdata, records, position_after_header):
    r = NumReader(records)
    emitted = 0
    while True:
        try:
            ident = r.id()
        except EOFError:
            break
        if ident == K_END:
            break
        if ident == K_HEADER:
            emitted += process_records(archive_name, fdata, r.take(len(r.d) - r.pos),
                                       position_after_header)
            break
        if ident in (K_MAIN_STREAMS_INFO, K_ADDITIONAL_STREAMS_INFO):
            streams = parse_streams_info(r)
            emitted += extract_hash(archive_name, fdata, streams, position_after_header)
            break
        if ident == K_ENCODED_HEADER:
            streams = parse_streams_info(r)
            if folder_has_aes(streams["unpack_info"]["folders"][0]) if streams["unpack_info"] and streams["unpack_info"]["folders"] else False:
                # header itself is AES-encrypted: the hash line targets it
                emitted += extract_hash(archive_name, fdata, streams, position_after_header)
            else:
                # compressed-only header: decompress and recurse
                decoded = decode_folder_stream(fdata, streams, position_after_header)
                if decoded:
                    emitted += process_records(archive_name, fdata, decoded,
                                               position_after_header)
            break
        # other top-level record types inside raw header (archive props etc.)
        # cannot determine their size without full parse; raw header payloads
        # we support are handled above; ignore trailing via break only if end
        break
    return emitted


def process_file(archive_name, fdata):
    if fdata[:6] != SEVEN_ZIP_MAGIC:
        sys.stderr.write("! %s: Not a 7z file\n" % archive_name)
        return 0
    if len(fdata) < 32:
        sys.stderr.write("! %s: truncated file\n" % archive_name)
        return 0
    next_offset = int.from_bytes(fdata[12:20], 'little')
    next_size = int.from_bytes(fdata[20:28], 'little')
    next_hdr_pos = 32 + next_offset
    if next_hdr_pos + next_size > len(fdata):
        sys.stderr.write("! %s: bad next header position\n" % archive_name)
        return 0
    nh = fdata[next_hdr_pos:next_hdr_pos + next_size]
    return process_records(archive_name, fdata, nh, 32)


def main():
    if len(sys.argv) < 2:
        print("Usage: python 7z2john.py <file.7z> [more.7z ...]")
        return 1
    for fn in sys.argv[1:]:
        try:
            with open(fn, 'rb') as f:
                fdata = f.read()
        except OSError as e:
            sys.stderr.write("! %s: %s\n" % (fn, e))
            continue
        process_file(fn, fdata)
    return 0


if __name__ == '__main__':
    sys.exit(main())
