"""MCP server entry point for re-rizin.

Exposes the rizin CLI's static-analysis capabilities to Claude Code.
All tools are thin wrappers around `rizin -q -A -c '<cmd>'` and
`rz-bin` invocations.
"""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from re_rizin import rizin_runner

logger = logging.getLogger("re_rizin")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-rizin")


# ── Health ──────────────────────────────────────────────────────────────


@mcp.tool()
def check_rizin() -> dict:
    """Return rizin + rz-bin version info.

    Confirms the binary is on PATH (or RIZIN_PATH / RZ_BIN_PATH).
    """
    return rizin_runner.check_rizin()


# ── File-level ─────────────────────────────────────────────────────────


@mcp.tool()
def get_file_info(path: str) -> dict:
    """Return high-level file metadata via `rz-bin -I`."""
    return rizin_runner.get_file_info(path)


@mcp.tool()
def list_imports_exports(path: str) -> dict:
    """Return parsed import and export tables (and raw text)."""
    return rizin_runner.list_imports_exports(path)


@mcp.tool()
def list_strings(
    path: str, min_length: int = 5, encoding: str = "all"
) -> dict:
    """Return strings via `rz-bin -z`/`-zz`/`-zzz`.

    Args:
        path: file to scan
        min_length: minimum string length (default 5)
        encoding: "ascii" (narrow), "utf16" (wide), or "all"
    """
    return rizin_runner.list_strings(path, min_length, encoding)


# ── Functions / disasm / decompile ──────────────────────────────────────


@mcp.tool()
def analyze_function(path: str, level: int = 2) -> list[dict]:
    """Run auto-analysis (`aa` + `aaa`) and return all functions.

    Args:
        path: file to analyze
        level: analysis depth — 0 = aaa, 1 = aaaa, 2 = aa+aaaa (default).
            Higher levels are slower but find more functions.
    """
    return rizin_runner.analyze_function(path, level)


@mcp.tool()
def list_functions_with_metadata(path: str, level: int = 2) -> list[dict]:
    """Return the function list with per-function category hints.

    Wraps :func:`analyze_function` and attaches a ``category`` field
    to each record based on a name-pattern catalog:

    - ``control-flow-guard-related`` for ``__security_cookie``,
      ``__guard_*``, ``_guard_dispatch_icall_fptr``.
    - ``language-runtime`` for ``__cxx_*``, ``__stdcall_*``,
      ``_initterm``, ``_initterm_e``.
    - ``anti-debug`` for ``IsDebuggerPresent``,
      ``CheckRemoteDebuggerPresent``, ``NtQueryInformationProcess``.
    - ``rtti`` for ``_Xlength_error``, ``_Xout_of_range``,
      ``type_info``.
    - ``compiler-runtime`` for ``__report_rangecheckfailure``,
      ``__chkstk``, ``__chkstk_ms``, ``__guard_dispatch_icall``.
    - ``unknown`` when no pattern matches.

    The catalog is vendored at ``data/compiler-fingerprints.json``
    (only the section-prefix entries are used here). The
    ``compiled_by`` field is set to the matching compiler
    category (msvc, gcc, clang, icc, rustc, go, delphi) when
    the demangled name matches the canonical pattern.
    """
    funcs = rizin_runner.analyze_function(path, level)
    try:
        catalog = _load_compiler_catalog()
    except Exception:
        catalog = {"fingerprints": []}
    out: list[dict] = []
    for fn in funcs:
        name = (fn.get("name") or "").strip()
        record = dict(fn)
        record["category"] = _categorize_function(name)
        record["compiled_by"] = _compiled_by(name, catalog)
        out.append(record)
    return out


def _load_compiler_catalog() -> dict:
    """Load the vendored compiler-fingerprints.json catalog."""
    import json
    from pathlib import Path
    here = Path(__file__).resolve()
    candidates = [
        here.parents[4] / "data" / "compiler-fingerprints.json",  # plugin-root
        here.parents[3] / "data" / "compiler-fingerprints.json",
        here.parents[2] / "data" / "compiler-fingerprints.json",
    ]
    for p in candidates:
        if p.is_file():
            return json.loads(p.read_text())
    return {"fingerprints": []}


def _categorize_function(name: str) -> str:
    """Best-effort category hint from a function name."""
    if not name:
        return "unknown"
    n = name.lower()
    if any(t in n for t in ("__security_cookie", "__guard_", "guard_dispatch_icall")):
        return "control-flow-guard-related"
    if any(t in n for t in ("isdebuggerpresent", "checkremotedebugger", "ntqueryinformationprocess")):
        return "anti-debug"
    if any(t in n for t in ("__cxx_", "__stdcall_", "_initterm", "__report_rangecheckfailure",
                            "__chkstk", "type_info", "_xlength_error", "_xout_of_range",
                            "throw_bad_alloc", "throw_out_of_range")):
        if "type_info" in n or "_xlength" in n or "_xout_of_range" in n:
            return "rtti"
        return "language-runtime"
    return "unknown"


def _compiled_by(name: str, catalog: dict) -> str | None:
    """Match a function name against the compiler-fingerprints catalog.

    Returns the ``compiler`` key from the matching fingerprint, or
    ``None`` when no pattern fires. The match is on the
    ``match_pattern`` field, which is a regex (RE2-style) string.
    """
    import re
    if not name:
        return None
    for fp in catalog.get("fingerprints", []):
        pat = fp.get("match_pattern", "")
        if not pat:
            continue
        try:
            if re.search(pat, name):
                return fp.get("compiler")
        except re.error:
            # Bad regex in the catalog — skip; not the caller's problem.
            continue
    return None


@mcp.tool()
def disassemble_function(path: str, function: str, max_insns: int = 500) -> dict:
    """Disassemble a single function by name (e.g. ``sym.main``) or address.

    Returns a list of ``{address, bytes, instruction}`` dicts.
    """
    return rizin_runner.disassemble_function(path, function, max_insns)


@mcp.tool()
def decompile_function(path: str, function: str) -> dict:
    """Decompile a function to pseudo-C via rizin's ``pdc`` command.

    Quality is much lower than IDA Hex-Rays or Ghidra's decompiler.
    For high-fidelity decompilation, use ``re-llm-decompile`` with
    ``disassemble_function`` as input.
    """
    return rizin_runner.decompile_function(path, function)


@mcp.tool()
def get_xrefs(path: str, target: str, direction: str = "to") -> dict:
    """Return cross-references to (or from) *target*.

    Args:
        path: file
        target: function name (``sym.main``), address (``0x1000``),
            or symbol
        direction: "to" (default) or "from"
    """
    return rizin_runner.get_xrefs(path, target, direction)


# ── Search / patterns ──────────────────────────────────────────────────


@mcp.tool()
def search_bytes(path: str, pattern: str) -> dict:
    """Search for a hex byte pattern in the binary.

    Args:
        path: file
        pattern: hex bytes, space-separated. Example: ``"90 90 90"``
    """
    return rizin_runner.search_bytes(path, pattern)


@mcp.tool()
def find_crypto_constants(path: str) -> dict:
    """Look for common crypto constants (AES S-box, SHA-256 K, CRC32)."""
    return rizin_runner.find_crypto_constants(path)


# ── Dynamic emulation ──────────────────────────────────────────────────


@mcp.tool()
def emulate_esil(path: str, function: str, steps: int = 1000) -> dict:
    """Run ESIL emulation for *steps* instructions on *function*.

    Useful for understanding state at a given point in a function
    without running the binary. Output is a tail of the emulation log.
    """
    return rizin_runner.emulate_esil(path, function, steps)


# ── Control-flow graph ────────────────────────────────────────────────


@mcp.tool()
def get_cfg_graph(path: str, function: str) -> dict:
    """Return the basic-block CFG of *function* in DOT format.

    Useful for visualizing function structure. Pair with `disassemble_function`
    for per-instruction details.
    """
    out = rizin_runner._run_rizin(
        path,
        ["aa", f"s {function}", "agf"],
        timeout_s=60,
    )
    return {"function": function, "dot": out}


# ── Entrypoint ─────────────────────────────────────────────────────────


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
