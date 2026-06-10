# re-rizin

MCP server exposing rizin (radare2 successor) for static binary analysis: functions, disassembly, xrefs, strings, decompilation, ESIL emulation, CFG.

Version: 0.1.0 | License: MIT

## Structure

```
re-rizin/
  pyproject.toml                    # build config (setuptools, mcp[cli] + deps)
  src/re_rizin/
    __init__.py
    __main__.py                     # entry: from server import main; main()
    server.py                       # FastMCP app with @mcp.tool() functions
  README.md
  LICENSE
  SECURITY.md


```

## Build

```bash
pip install -e .                    # install with deps
re-rizin                         # start MCP server on stdio
```



## Tools

This server exposes these MCP tools: `check_rizin,get_file_info,list_imports_exports,list_strings,analyze_function,list_functions_with_metadata,disassemble_function,decompile_function,get_xrefs,search_bytes,find_crypto_constants,emulate_esil,get_cfg_graph`

## Usage (standalone)

Register this server in your `.mcp.json`:

```json
{
  "mcpServers": {
    "re-rizin": {
      "command": "uv",
      "args": ["--directory", "/path/to/re-rizin", "run", "re-rizin"]
    }
  }
}
```

Or use via the [RE-AI agent-space](https://github.com/Heretek-RE/RE-AI): `./install.sh` clones all servers at pinned versions.
