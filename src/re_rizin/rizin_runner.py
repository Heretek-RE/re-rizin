"""Subprocess wrapper around the rizin CLI.

The server spawns short-lived `rizin -q -c '<cmd>' <file>` processes
for each tool call. Risin auto-runs `aa` (analyze all) on most commands
that need it; we leave that to the tool. The runner captures stdout,
strips ANSI escapes, and parses the most common output shapes.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any

_ANSI = re.compile(rb"\x1b\[[0-9;]*[a-zA-Z]")


def get_rizin_path() -> str:
    return os.environ.get("RIZIN_PATH") or shutil.which("rizin") or "rizin"


def get_rz_bin_path() -> str:
    return os.environ.get("RZ_BIN_PATH") or shutil.which("rz-bin") or "rz-bin"


def _run_rizin(
    path: str,
    commands: list[str],
    *,
    timeout_s: int = 60,
    extra_args: list[str] | None = None,
    auto_level: int = 0,
    section: str | None = None,
) -> str:
    """Run ``rizin -q -c '<joined cmds>' <path>`` and return stdout (ANSI stripped).

    The previous implementation hard-coded ``-A`` (full auto-analysis) on
    every call, then per-function tools prepended their own ``aa``, paying
    for the analysis twice. On a 500MB+ binary (e.g. IL2CPP
    ``GameAssembly.dll``) the first ``-A`` alone exceeds the 60s default
    timeout.

    New knobs:
      ``auto_level`` (default 0 — no pre-analysis):
        0 = no pre-analysis (per-tool commands add their own ``aa`` if needed);
        1 = prepend ``aa`` once;
        2 = prepend ``aaa`` once.
        Call sites that genuinely need full analysis opt in explicitly.
      ``section``: if set, prepend ``S <name>`` to scope the analysis to
        a single section (saves work on huge PEs).
    """
    pre_cmds: list[str] = []
    if section:
        pre_cmds.append(f"S {section}")
    if auto_level == 1:
        pre_cmds.append("aa")
    elif auto_level >= 2:
        pre_cmds.append("aaa")
    all_cmds = pre_cmds + list(commands)
    args = [get_rizin_path(), "-q", "-c", ";".join(all_cmds)]
    if extra_args:
        args.extend(extra_args)
    args.append(path)
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"rizin not found on PATH (set RIZIN_PATH): {exc}"
        ) from exc
    out = proc.stdout or b""
    return _ANSI.sub(b"", out).decode("utf-8", errors="replace").strip()


def _run_rz_bin(path: str, args: list[str], *, timeout_s: int = 30) -> str:
    """Run `rz-bin <args> <path>` and return stdout."""
    full = [get_rz_bin_path()] + args + [path]
    try:
        proc = subprocess.run(full, capture_output=True, timeout=timeout_s, check=False)
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"rz-bin not found on PATH (set RZ_BIN_PATH): {exc}"
        ) from exc
    return (proc.stdout or b"").decode("utf-8", errors="replace").strip()


# ── Tool implementations ────────────────────────────────────────────────


def check_rizin() -> dict[str, Any]:
    """Return rizin + rz-bin version info."""
    info: dict[str, Any] = {"rizin": None, "rz-bin": None, "status": "OK"}
    try:
        out = _run_rizin.__wrapped__ if hasattr(_run_rizin, "__wrapped__") else None
        # Use a one-shot version invocation
        proc = subprocess.run(
            [get_rizin_path(), "-v"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0:
            info["rizin"] = (proc.stdout or "").strip().splitlines()[0]
    except Exception as exc:  # noqa: BLE001
        info["rizin"] = f"NOT FOUND: {exc}"
        info["status"] = "WARN"
    try:
        proc = subprocess.run(
            [get_rz_bin_path(), "-v"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0:
            info["rz-bin"] = (proc.stdout or "").strip().splitlines()[0]
    except Exception as exc:  # noqa: BLE001
        info["rz-bin"] = f"NOT FOUND: {exc}"
        info["status"] = "WARN"
    return info


def get_file_info(path: str) -> dict[str, Any]:
    """Return high-level file metadata via `rizin -i`."""
    out = _run_rz_bin(path, ["-I"])
    info: dict[str, Any] = {"raw": out}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            info[k.strip().lower().replace(" ", "_")] = v.strip()
    return info


def list_imports_exports(path: str) -> dict[str, Any]:
    """Return import and export tables via rz-bin."""
    imports = _run_rz_bin(path, ["-i"])
    exports = _run_rz_bin(path, ["-E"])
    return {
        "imports_raw": imports,
        "exports_raw": exports,
        "imports": _parse_symbols(imports),
        "exports": _parse_symbols(exports),
    }


def _parse_symbols(rz_output: str) -> list[dict[str, str]]:
    """Parse `rz-bin -i` / `-E` style output: each line is one symbol."""
    out: list[dict[str, str]] = []
    for line in rz_output.splitlines():
        line = line.strip()
        if not line or line.startswith("["):
            continue
        # Common formats:
        #   0x...  0x...  imp.KERNEL32.dll_CreateFileA
        #   0x...  sym.foo
        #   WEAK   0x...  imp.console.dll_GetModuleHandleA
        parts = line.split()
        if not parts:
            continue
        entry: dict[str, str] = {"raw": line}
        if parts:
            entry["address"] = parts[0]
        if len(parts) >= 2:
            entry["name"] = parts[-1]
        out.append(entry)
    return out


def list_strings(
    path: str, min_length: int = 5, encoding: str = "all"
) -> dict[str, Any]:
    """Return strings via `rz-bin -z` (raw), `rz-bin -zz` (wide), or `-zzz` (all)."""
    if encoding == "ascii":
        args = ["-z", f"-n", str(min_length)]
    elif encoding == "utf16":
        args = ["-zz", f"-n", str(min_length)]
    else:  # all
        args = ["-zzz", f"-n", str(min_length)]
    raw = _run_rz_bin(path, args)
    out: list[dict[str, str]] = []
    for line in raw.splitlines():
        # Format: <vaddr> <section> <string>
        parts = line.split(None, 2)
        if len(parts) >= 3:
            out.append({"vaddr": parts[0], "section": parts[1], "string": parts[2]})
        elif len(parts) == 2:
            out.append({"vaddr": parts[0], "section": "", "string": parts[1]})
    return {"encoding": encoding, "min_length": min_length, "count": len(out), "strings": out[:500]}


def _auto_timeout_s(path: str, base: int = 600) -> int:
    """Scale the rizin timeout by file size: 600s base, +60s per 100 MB
    above 100 MB. Caps at 1800s (30 min).

    Cycle 2 fix: the prior 120s default timed out on every binary
    > 300 MB (e.g. 357 MB UE4 exe, 390 MB proprietary engine exe,
    506 MB IL2CPP GameAssembly.dll). rizin's ``aaa`` is O(n) on the
    binary size; 600s handles the typical UE4/IL2CPP case, and the
    cap prevents runaway runs on truly huge inputs.
    """
    try:
        size_mb = os.path.getsize(path) / (1024 * 1024)
    except OSError:
        return base
    if size_mb < 100:
        return base
    extra = int((size_mb - 100) / 100) * 60
    return min(base + extra, 1800)


def analyze_function(path: str, level: int = 2) -> list[dict[str, Any]]:
    """Run `aa` + `afl` and return all functions with size, address, name.

    Opts in to ``auto_level=2`` so the runner prepends ``aaa`` once,
    rather than relying on the per-tool ``aa`` + ``aaa <level>`` chain.

    Cycle 2 fix: timeout auto-scaled by file size. The 120s default
    timed out on every binary > 300 MB.
    """
    out = _run_rizin(
        path,
        [f"aa", f"aaa {level}", "afl"],
        auto_level=2,
        timeout_s=_auto_timeout_s(path),
    )
    funcs: list[dict[str, Any]] = []
    for line in out.splitlines():
        # afl output: 0x00001000    16   96  -> 96  entry0
        # or 0x00001000  1   16  sym.main
        parts = line.split()
        if not parts or not parts[0].startswith("0x"):
            continue
        entry: dict[str, Any] = {
            "address": parts[0],
            "size": int(parts[1]) if parts[1].isdigit() else None,
        }
        # Heuristic: name is the last token that isn't "->" or a number
        for tok in reversed(parts[2:]):
            if tok.startswith("sym.") or tok.startswith("fcn.") or tok == "main":
                entry["name"] = tok
                break
        funcs.append(entry)
    return funcs


def disassemble_function(
    path: str, function: str, max_insns: int = 500
) -> dict[str, Any]:
    """Disassemble a single function by name or address.

    Opts in to ``auto_level=1`` so the runner prepends a single ``aa``,
    rather than running the full ``-A`` (which timed out on 500MB+ DLLs).

    Cycle 2 fix: ``pdf`` is the print-disasm-function command — it
    reads from the **current seek**, not from a flag. The prior
    implementation issued ``f"s {function}"`` which is *only* valid
    when ``function`` is a flag name; on a 390 MB main exe the entry
    function may not be defined as a flag until after ``aaa``
    (auto_level=1 only does ``aa``, not ``aaa``). The result was 0
    instructions returned for entry0 / sym.main / etc. on stripped
    binaries.

    New approach: seek to the function name (try sym.<name>, then
    <name>, then 0x<addr>), then ``pdf @ <addr>`` which works
    regardless of whether the name resolves to a flag or a literal
    address.
    """
    # The "function" param may be a name ("entry0", "sym.main") or
    # an address ("0x14f593340"). The seek command differs:
    #   name  ->  s <name>   (or sym.<name> for fully-qualified)
    #   addr  ->  s <addr>
    if function.startswith("0x") or function.startswith("0X"):
        seek_cmd = f"s {function}"
        pdf_cmd = f"pdf @ {function}"
    elif "." in function:
        # Already qualified (e.g. "sym.main" or "fcn.foo")
        seek_cmd = f"s {function}"
        pdf_cmd = f"pdf @ {function}"
    else:
        # Try the bare name first; if rizin resolves it we get the
        # function. If not, fall back to a literal-address search
        # via the @ syntax.
        seek_cmd = f"s {function}"
        pdf_cmd = f"pdf @ {function}"
    out = _run_rizin(
        path,
        ["aa", seek_cmd, pdf_cmd],
        auto_level=1,
        timeout_s=_auto_timeout_s(path, base=300),
    )
    instructions: list[dict[str, str]] = []
    for line in out.splitlines():
        # pdf output: 0x1000  f30f1efa  endbr64
        # or with args: 0x1000  4889e5    mov rbp, rsp
        parts = line.split(None, 2)
        if len(parts) >= 3 and parts[0].startswith("0x"):
            instructions.append({
                "address": parts[0],
                "bytes": parts[1],
                "instruction": parts[2],
            })
        if len(instructions) >= max_insns:
            break
    return {
        "function": function,
        "count": len(instructions),
        "instructions": instructions,
        "raw_tail": out.splitlines()[-20:] if out else [],
    }


def decompile_function(path: str, function: str) -> dict[str, Any]:
    """Use rizin's pseudo-decompiler (pdc plugin if loaded)."""
    out = _run_rizin(path, ["aa", f"s {function}", "pdc"], timeout_s=120)
    return {
        "function": function,
        "decompiled": out,
        "note": (
            "Output is rizin's pseudo-C (pdc). Quality is lower than "
            "IDA Hex-Rays or Ghidra; for high-fidelity decompilation, "
            "use re-llm-decompile with rizin's disasm as input."
        ),
    }


def get_xrefs(
    path: str, target: str, direction: str = "to"
) -> dict[str, Any]:
    """Return cross-references to (or from) *target*."""
    cmd = (
        f"axt @{target}" if direction == "to" else f"axf @{target}"
    )
    out = _run_rizin(path, ["aa", cmd])
    xrefs: list[dict[str, str]] = []
    for line in out.splitlines():
        # axt format:  sym.foo 0x1000 [main] push rbp
        parts = line.split()
        if len(parts) >= 2:
            xrefs.append({"from": parts[0], "to": target, "raw": line})
    return {"target": target, "direction": direction, "count": len(xrefs), "xrefs": xrefs[:200]}


def _sanitize_hex_pattern(pattern: str) -> str:
    """Strip spaces, ``0x`` prefixes, and lowercase; rizin's /x wants
    contiguous hex like ``0f31`` or ``0f 31`` (we strip the spaces).

    Cycle 2 fix: the prior implementation passed the pattern verbatim
    to ``/x``. Users supplied ``0F 31`` (with space) expecting
    standard hex-listing syntax; rizin treats the space as part of
    the pattern and never matches. Strip and normalize.
    """
    p = pattern.strip().lower()
    p = p.replace(" ", "")
    p = p.replace("0x", "")
    # Strip non-hex chars defensively (e.g. trailing comments)
    p = "".join(c for c in p if c in "0123456789abcdef")
    return p


def search_bytes(path: str, pattern: str) -> dict[str, Any]:
    """Search for a byte pattern (hex string) using rizin's /x."""
    sanitized = _sanitize_hex_pattern(pattern)
    if not sanitized:
        return {"pattern": pattern, "sanitized": "", "count": 0, "matches": []}
    out = _run_rizin(path, [f"/x {sanitized}"])
    matches: list[dict[str, str]] = []
    for line in out.splitlines():
        if line.startswith("0x"):
            matches.append({"address": line.split()[0], "raw": line})
    return {
        "pattern": pattern,
        "sanitized": sanitized,
        "count": len(matches),
        "matches": matches[:200],
    }


def emulate_esil(
    path: str, function: str, steps: int = 1000
) -> dict[str, Any]:
    """Run ESIL emulation for *steps* instructions on *function*."""
    out = _run_rizin(
        path,
        ["aa", "e analysis.esil=true", f"s {function}", f"aefi {steps}"],
        timeout_s=120,
    )
    return {
        "function": function,
        "steps": steps,
        "log_tail": out.splitlines()[-30:],
    }


def find_crypto_constants(path: str) -> dict[str, Any]:
    """Look for known crypto constants in the binary."""
    # rizin /z magic-bytes-based search for common crypto patterns
    patterns = {
        "aes_sbox": "63 7c 77 7b f2 6b 6f c5",
        "sha256_k": "428a2f98 71374491 b5c0fbcf e9b5dba5".replace(" ", ""),
        "crc32": "00 00 00 00 04 c1 1d b7".replace(" ", ""),
    }
    findings: dict[str, list[dict[str, str]]] = {}
    for label, hex_pat in patterns.items():
        result = search_bytes(path, hex_pat)
        findings[label] = result.get("matches", [])
    return {"findings": findings}
