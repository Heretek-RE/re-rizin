# re-rizin

MCP server exposing the [rizin](https://rizin.org/) (radare2 successor) CLI for static binary analysis.

## Tools

| Tool | What it does |
|---|---|
| `check_rizin` | Confirm rizin + rz-bin are installed |
| `get_file_info` | `rz-bin -I` — arch, bits, type, pic, canary, nx, etc. |
| `list_imports_exports` | `rz-bin -i` / `-E` — symbol tables |
| `list_strings` | `rz-bin -z`/`-zz`/`-zzz` — ASCII / UTF-16 / all |
| `analyze_function` | `aa` + `afl` — list all functions |
| `disassemble_function` | `pdf` — full disassembly of one function |
| `decompile_function` | `pdc` — pseudo-C decompile (lower quality than IDA/Ghidra) |
| `get_xrefs` | `axt` / `axf` — cross-references |
| `search_bytes` | `/x` — hex pattern search |
| `find_crypto_constants` | Detect AES / SHA / CRC tables |
| `emulate_esil` | `aefi` — ESIL emulation |
| `get_cfg_graph` | `agf` — DOT-format CFG |

## Install

```bash
# System dependency
apt install rizin       # Debian/Ubuntu
brew install rizin       # macOS
scoop install rizin      # Windows

# Python
pip install -e ./servers/re-rizin
```

## Run

```bash
re-rizin
```

## Deprecation note

v1 `re-ai` had no rizin wrapper — it tried to do all this with pefile + capstone + a hand-rolled RAG store. That's exactly the kind of complexity Claude Code is bad at, and the re-ai team (us) was bad at. This server just lets Claude Code ask rizin to do its thing.
