# 一键转Hash工具 (Hash-to-Hashcat Converter)

把**加密的** Office 文档、PDF、ZIP、RAR、7Z 压缩包，一键转成
[hashcat](https://hashcat.net/) / hashcatGUI 可直接加载的哈希行（`.hash.txt`），
之后在 hashcatGUI 里选好模式号，配置字典或掩码即可 GPU 爆破密码。

**Windows 免安装绿色版**：单个 21MB 的 `转Hash工具.exe`，无需 Python、无需任何库。

## 快速使用

1. 把要破解的文件**拖到 `转Hash工具.exe` 图标上**松手（可一次拖多个）；
2. 每个文件旁边自动生成同名 `.hash.txt`；
3. 打开 hashcatGUI：哈希类型填下表模式号 → 哈希文件选 `.hash.txt` → 配置字典/掩码 → 开跑。

也支持命令行：`转Hash工具.exe <文件1> [文件2 ...]`

## 支持格式与 hashcat 模式号

| 格式 | 哈希前缀 | hashcat -m | 备注 |
|---|---|---|---|
| .docx/.doc/.xls/.xlsx | `$office$` | 9400 | Office 2007+ AES |
| .ppt/.pptx | `$office$` | 9600 | 旧版 RC4 |
| .pdf | `$pdf$` | 10400/10500/10600/10700 | 按 PDF 加密版本自动区分 |
| .zip (ZipCrypto) | `$pkzip$` | 17200 | |
| .zip (AES) | `$zip2$`/`$zip3$` | 17220–17225 | |
| .rar (RAR5) | `$rar5$` | 13000 | |
| .rar (RAR3 -hp) | `$RAR3$` | 12500 | 文件头加密 |
| .rar (RAR3 仅文件密) | `$RAR3$` | 23700/23800 | 存储/压缩 |
| .7z | `$7z$` | 11600 | |

## 已知限制

- **7z 固实压缩**（多文件压成一坨）能产出行、能正常加载，但部分 hashcat 版本无法校验该行（不命中），属 hashcat 模块限制，非行错误；单文件与非固实 7z 均正常。
- `.hash.txt` 请勿用记事本另存修改（会加 BOM 导致 hashcat 报错）；直接用本工具生成的文件。

## 源码运行

- 需 Python 3.8+；
- 全部转换器零第三方依赖，仅 PDF 转换需要 `pyhanko`：`pip install pyhanko`；
- 入口：`python tohash.py <文件...>`，或拖拽到 `转Hash.bat`。

## 目录结构

```
转Hash工具.exe    Windows 绿色主程序（通过 Releases 发布：/releases/latest，不入库）
tohash.py         主入口（进程内调用各转换器）
office2john.py    Office -> $office$
pdf2john.py       PDF    -> $pdf$
zip2john.py       ZIP    -> $pkzip$（按 zip2john.c 移植）
rar2john.py       RAR    -> $rar5$/$RAR3$（按 rar2john.c 移植）
7z2john.py        7Z     -> $7z$（按 7z2john.pl 移植）
转Hash.bat        启动器（有 exe 用 exe，否则用 Python 跑源码）
使用说明.txt       中文使用说明
```

## 来源与许可

- `office2john.py`、`pdf2john.py` 取自 [John the Ripper](https://www.openwall.com/john/) 官方工具集；
- `zip2john.py`、`rar2john.py`、`7z2john.py` 为按 JtR 官方 C/Perl 实现逐行移植的 Python 版本；
- 本项目整体采用 **GPL-2.0-or-later**（与上游 John the Ripper 一致），详见 [LICENSE](LICENSE)；
- 本工具仅用于**恢复自己遗失的文档密码**等合法用途。
