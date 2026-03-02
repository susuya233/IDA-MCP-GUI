"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
支持 IDA 7.x / 8.x / 9.x（含 9.2）。
"""

# 加载时打印，便于确认插件是否被 IDA 加载（看 Output 窗口）
try:
    print("[ida_mcp] Loading plugin...")
except Exception:
    pass

import sys
from typing import TYPE_CHECKING

# IDA 9 中 plugin_t 与 PLUGIN_* 可能在 ida_idaapi，兼容旧版 idaapi
try:
    import ida_idaapi
    _plugin_t = getattr(ida_idaapi, "plugin_t", None)
    _PLUGIN_KEEP = getattr(ida_idaapi, "PLUGIN_KEEP", None)
    _PLUGIN_HIDE = getattr(ida_idaapi, "PLUGIN_HIDE", None)
    _PLUGIN_FIX = getattr(ida_idaapi, "PLUGIN_FIX", None)
except ImportError:
    ida_idaapi = None
    _plugin_t = _PLUGIN_KEEP = _PLUGIN_HIDE = _PLUGIN_FIX = None

import idaapi
if _plugin_t is None:
    _plugin_t = idaapi.plugin_t
if _PLUGIN_KEEP is None:
    _PLUGIN_KEEP = idaapi.PLUGIN_KEEP
if _PLUGIN_HIDE is None:
    _PLUGIN_HIDE = getattr(idaapi, "PLUGIN_HIDE", 0)
if _PLUGIN_FIX is None:
    _PLUGIN_FIX = getattr(idaapi, "PLUGIN_FIX", 0)

if TYPE_CHECKING:
    from . import ida_mcp


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


class MCP(_plugin_t):
    flags = _PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    # TODO: make these configurable
    HOST = "127.0.0.1"
    BASE_PORT = 13337
    MAX_PORT_TRIES = 10

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        return _PLUGIN_KEEP

    def run(self, arg):
        if self.mcp:
            self.mcp.stop()
            self.mcp = None

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler
            from .ida_mcp import ida_gui
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler
            from ida_mcp import ida_gui

        # Initialize GUI (register actions and menu items)
        ida_gui.init_gui()

        for i in range(self.MAX_PORT_TRIES):
            port = self.BASE_PORT + i
            try:
                MCP_SERVER.serve(
                    self.HOST, port, request_handler=IdaMcpHttpRequestHandler
                )
                print(f"  Config: http://{self.HOST}:{port}/config.html")
                print(f"  危险函数扫描: http://{self.HOST}:{port}/dangerous.html")
                print(f"  命令注入扫描: http://{self.HOST}:{port}/cmdi.html")
                self.mcp = MCP_SERVER
                break
            except OSError as e:
                if e.errno in (48, 98, 10048):  # Address already in use
                    if i == self.MAX_PORT_TRIES - 1:
                        print(
                            f"[MCP] Error: Could not find available port in range {self.BASE_PORT}-{self.BASE_PORT + self.MAX_PORT_TRIES - 1}"
                        )
                        return
                    continue
                raise

    def term(self):
        if self.mcp:
            self.mcp.stop()
        # Cleanup GUI
        try:
            from ida_mcp import ida_gui
            ida_gui.term_gui()
        except:
            pass


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags（供部分版本使用）
PLUGIN_FLAGS = _PLUGIN_HIDE | _PLUGIN_FIX
