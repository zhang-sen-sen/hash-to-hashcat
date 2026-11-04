# -*- coding: utf-8 -*-
"""
一键转 Hash 工具（单文件绿色版）
================================
把加密的 Office(Word/Excel/PPT)、PDF、ZIP、RAR、7Z 文件转成
hashcat 可直接加载的哈希行，自动写入 <文件名>.hash.txt。

用法：
    1) 直接把一个或多个文件拖到「转Hash工具.exe」上，松开鼠标即可；
    2) 或命令行：转Hash工具.exe <文件1> [文件2 ...]

本程序为自包含单文件，不需要安装 Python，也不需要安装任何库。

支持格式与 hashcat 模式：
    .doc/.docx/.xls/.xlsx/.ppt/.pptx   ->  $office$   ( -m 9600/9400 等 )
    .pdf                               ->  $pdf$     ( -m 10400/10500/10600/10700 )
    .zip                               ->  $pkzip$   ( -m 17200/17210/17220/17225/17230 )
    .rar                               ->  $rar5$/$RAR3$ ( -m 13000/12500/23700/23800 )
    .7z                                ->  $7z$      ( -m 11600 )

说明：
    - 只有【加密】文件才会产出可爆破的哈希行；未加密的文件会提示"无需密码"。
    - 7z 固实压缩（多文件一个压缩块）能产出行，但部分 hashcat 版本无法校验，
      属于 hashcat 模块限制，行本身是有效的。
"""

import contextlib
import importlib
import io
import os
import re
import sys

OFFICE_EXT = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp"}
PDF_EXT = {".pdf"}
ZIP_EXT = {".zip", ".cbz", ".jar"}
RAR_EXT = {".rar"}
SZ_EXT = {".7z"}

MODE_HINT = {
    "office": "hashcat -m 9400/9600（2007+ AES）；老格式 .doc 用 -m 9600",
    "pdf": "hashcat -m 10400/10500/10600/10700（不同 PDF 加密版本自动区分）",
    "zip": "hashcat -m 17200（ZipCrypto）/ 17220-17225（AES）",
    "rar": "hashcat -m 13000（RAR5）/ 12500（RAR3 -hp）/ 23700（RAR3 存储）/ 23800（RAR3 压缩）",
    "7z": "hashcat -m 11600",
}


def which_kind(fn):
    ext = os.path.splitext(fn)[1].lower()
    if ext in OFFICE_EXT:
        return "office"
    if ext in PDF_EXT:
        return "pdf"
    if ext in ZIP_EXT:
        return "zip"
    if ext in RAR_EXT:
        return "rar"
    if ext in SZ_EXT:
        return "7z"
    return None


def convert_inproc(kind, fn):
    """进程内调用对应转换器，返回 (stdout 文本, stderr 文本)。"""
    buf = io.StringIO()
    errs = []
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            if kind == "office":
                import office2john
                office2john.process_file(fn)
            elif kind == "pdf":
                from pdf2john import PdfHashExtractor
                h = PdfHashExtractor(fn).parse()
                if h:
                    print(h)
            elif kind == "zip":
                import zip2john
                with open(fn, "rb") as f:
                    data = f.read()
                zip2john.scan_central_index(fn, data)
            elif kind == "rar":
                import rar2john
                with open(fn, "rb") as f:
                    data = f.read()
                if data[:8] == rar2john.RAR5_MAGIC or data[:2] == b"MZ":
                    if rar2john.process_file5(fn, data) == 0:
                        if not (data[:7] == rar2john.RAR3_MAGIC or
                                (data[:2] == b"MZ" and rar2john.RAR3_MAGIC in data)):
                            errs.append("! %s: Not a RAR file" % fn)
                else:
                    rar2john.process_file3(fn, data)
            elif kind == "7z":
                m = importlib.import_module("7z2john")
                with open(fn, "rb") as f:
                    fdata = f.read()
                m.process_file(fn, fdata)
    except Exception as e:
        errs.append("! 转换失败: %s: %s" % (type(e).__name__, e))
    return buf.getvalue(), "\n".join(errs)


def strip_line(kind, text):
    """把 JtR 风格的 name: 前缀 / :尾巴 剥掉，只留 hashcat 能加载的部分。"""
    text = text.strip()
    if not text:
        return None
    if kind in ("office", "pdf", "7z"):
        return text.split(":", 1)[1] if ":" in text else text
    if kind == "zip":
        m = re.search(r"\$pkzip\$.*?\$/pkzip\$", text)
        if m:
            return m.group(0)
        m = re.search(r"\$zip[23]\$.*", text)
        if m:
            return m.group(0).split(":", 1)[0]
        return text.split(":", 1)[1] if ":" in text else text
    if kind == "rar":
        if "$RAR3$" in text:
            return text.split(":", 1)[0]
        return text.split(":", 1)[1] if ":" in text else text
    return text


def main(argv):
    files = argv[1:]
    if not files:
        print(__doc__)
        if sys.stdin.isatty():
            input("按回车键退出...")
        return 1
    total_ok = 0
    for fn in files:
        base = os.path.basename(fn)
        if not os.path.exists(fn):
            print("! 文件不存在：%s" % fn)
            continue
        kind = which_kind(fn)
        if kind is None:
            print("! 不支持的类型：%s（支持 Office/PDF/ZIP/RAR/7Z）" % base)
            continue
        print("=" * 70)
        print("[%s] %s" % (kind.upper(), fn))
        out, errs = convert_inproc(kind, fn)
        lines = [strip_line(kind, ln) for ln in out.splitlines() if ln.strip()]
        lines = [ln for ln in lines if ln and ln.startswith("$")]
        if not lines:
            print("! 未产出哈希行（文件可能未加密，或转换器报错）。")
            if errs:
                for e in errs.splitlines():
                    print("   ", e)
            continue
        hash_path = os.path.splitext(fn)[0] + ".hash.txt"
        with open(hash_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
        print("  hashcat 模式：%s" % MODE_HINT[kind])
        print("  哈希行 %d 条，已写入：%s" % (len(lines), hash_path))
        for ln in lines:
            print("   > %s" % ln)
        total_ok += 1
    print("=" * 70)
    print("完成：%d 个文件成功转出哈希。" % total_ok)
    print("下一步：打开 hashcatGUI -> 哈希类型选对应模式号 -> 载入 .hash.txt 文件 -> 配置攻击/掩码 -> 开跑。")
    if sys.stdin.isatty():
        input("按回车键退出...")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
