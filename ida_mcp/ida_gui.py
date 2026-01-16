"""IDA GUI - Built-in IDA Pro windows for vulnerability scanning results"""

import ida_kernwin
import ida_funcs
import idaapi

from .api_dangerous import find_dangerous_calls, DANGEROUS_FUNCTIONS
from .api_taint import scan_command_injection, SOURCE_FUNCTIONS, SINK_FUNCTIONS


# ============================================================================
# Dangerous Functions Viewer
# ============================================================================

class DangerousFunctionsChooser(ida_kernwin.Choose):
    """IDA Chooser window for displaying dangerous function calls"""
    
    def __init__(self, title="危险函数扫描结果"):
        self.items = []
        self.icon = 0
        
        # Column definitions: (name, width)
        columns = [
            ["危险函数", 15],
            ["地址", 12],
            ["类别", 12],
            ["调用函数", 25],
            ["调用地址", 12],
            ["反汇编", 40],
        ]
        
        ida_kernwin.Choose.__init__(
            self,
            title,
            columns,
            flags=ida_kernwin.Choose.CH_MULTI | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        
        self.Refresh()
    
    def OnInit(self):
        return True
    
    def OnGetSize(self):
        return len(self.items)
    
    def OnGetLine(self, n):
        if n < len(self.items):
            return self.items[n]
        return ["", "", "", "", "", ""]
    
    def OnSelectLine(self, sel):
        """Handle Enter key - jump to address"""
        if isinstance(sel, list):
            n = sel[0] if sel else -1
        else:
            n = sel
        self._jump_to_line(n)
    
    def OnDblClick(self, sel):
        """Handle double-click - jump to address"""
        if isinstance(sel, list):
            n = sel[0] if sel else -1
        else:
            n = sel
        self._jump_to_line(n)
        return True
    
    def _jump_to_line(self, n):
        """Jump to the address of the selected line"""
        try:
            if n >= 0 and n < len(self.items):
                item = self.items[n]
                # Jump to call site address (column 4)
                addr_str = item[4]
                if addr_str:
                    if addr_str.startswith("0x"):
                        addr = int(addr_str, 16)
                    else:
                        addr = int(addr_str)
                    print(f"[MCP] 跳转到: {hex(addr)}")
                    ida_kernwin.jumpto(addr)
        except Exception as e:
            print(f"[MCP] 跳转失败: {e}, n={n}, type={type(n)}")
    
    def OnRefresh(self, n):
        self.Refresh()
        return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(n)
    
    def OnGetIcon(self, n):
        # Return different icons based on category
        if n < len(self.items):
            category = self.items[n][2]
            if category in ("内存拷贝", "命令执行"):
                return 59  # Red icon
            elif category in ("格式化字符串", "文件操作"):
                return 60  # Orange icon
            else:
                return 61  # Yellow icon
        return 0
    
    def Refresh(self):
        """Refresh the data from scanning"""
        self.items = []
        
        try:
            results = find_dangerous_calls()
            
            for result in results:
                func_name = result["name"]
                func_addr = result["addr"]
                category = result["category"]
                callers = result["callers"]
                
                # Category display names
                category_names = {
                    "memory_copy": "内存拷贝",
                    "format_string": "格式化字符串",
                    "input": "输入函数",
                    "command_exec": "命令执行",
                    "file_operation": "文件操作",
                }
                cat_display = category_names.get(category, category)
                
                for caller in callers:
                    caller_func = caller.get("caller_func_name") or "<unknown>"
                    call_addr = caller.get("call_addr", "")
                    disasm = caller.get("disasm", "")
                    
                    self.items.append([
                        func_name,
                        func_addr,
                        cat_display,
                        caller_func,
                        call_addr,
                        disasm,
                    ])
        except Exception as e:
            print(f"[MCP] 扫描危险函数时出错: {e}")
        
        return True
    
    def show_window(self):
        """Show the chooser window"""
        return ida_kernwin.Choose.Show(self)


# ============================================================================
# Command Injection Viewer
# ============================================================================

class CommandInjectionChooser(ida_kernwin.Choose):
    """IDA Chooser window for displaying command injection vulnerabilities"""
    
    def __init__(self, title="命令注入扫描结果"):
        self.items = []
        self.raw_results = []  # Store full results for detail view
        self.icon = 0
        
        # Column definitions
        columns = [
            ["#", 4],
            ["风险", 6],
            ["Sink函数", 15],
            ["调用函数", 25],
            ["调用地址", 12],
            ["可控性", 8],
            ["输入源数", 8],
            ["反汇编", 35],
        ]
        
        ida_kernwin.Choose.__init__(
            self,
            title,
            columns,
            flags=ida_kernwin.Choose.CH_MULTI | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        
        self.Refresh()
    
    def OnInit(self):
        return True
    
    def OnGetSize(self):
        return len(self.items)
    
    def OnGetLine(self, n):
        if n < len(self.items):
            return self.items[n]
        return ["", "", "", "", "", "", "", ""]
    
    def OnSelectLine(self, sel):
        """Handle Enter key - jump to address"""
        # sel can be a list in multi-select mode or an integer
        if isinstance(sel, list):
            n = sel[0] if sel else -1
        else:
            n = sel
        self._jump_to_line(n)
    
    def OnDblClick(self, sel):
        """Handle double-click - jump to address"""
        if isinstance(sel, list):
            n = sel[0] if sel else -1
        else:
            n = sel
        self._jump_to_line(n)
        return True
    
    def _jump_to_line(self, n):
        """Jump to the address of the selected line"""
        try:
            if n >= 0 and n < len(self.items):
                item = self.items[n]
                # Jump to call site address (column 4)
                addr_str = item[4]
                if addr_str:
                    if addr_str.startswith("0x"):
                        addr = int(addr_str, 16)
                    else:
                        addr = int(addr_str)
                    print(f"[MCP] 跳转到: {hex(addr)}")
                    ida_kernwin.jumpto(addr)
        except Exception as e:
            print(f"[MCP] 跳转失败: {e}, n={n}, type={type(n)}")
    
    def OnRefresh(self, n):
        self.Refresh()
        return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(n)
    
    def OnGetIcon(self, n):
        # Return different icons based on risk level
        if n < len(self.items):
            risk = self.items[n][1]
            if "严重" in risk:
                return 59  # Red
            elif "高危" in risk:
                return 60  # Orange
            elif "中危" in risk:
                return 61  # Yellow
            else:
                return 62  # Green
        return 0
    
    def Refresh(self):
        """Refresh the data from scanning"""
        self.items = []
        self.raw_results = []
        
        try:
            results = scan_command_injection(max_depth=8)
            self.raw_results = results
            
            risk_display = {
                "critical": "🔴严重",
                "high": "🟠高危",
                "medium": "🟡中危",
                "low": "🟢低危",
            }
            
            ctrl_display = {
                "high": "高",
                "medium": "中",
                "low": "低",
                "unknown": "未知",
            }
            
            for vuln in results:
                vuln_id = str(vuln["id"])
                risk_level = vuln["risk_level"]
                sink_func = vuln["sink_func"]
                caller_func = vuln["caller_func"]
                call_site = vuln["call_site"]
                controllability = vuln["controllability"]
                sources = vuln["sources"]
                disasm = vuln["disasm"]
                
                self.items.append([
                    vuln_id,
                    risk_display.get(risk_level, risk_level),
                    sink_func,
                    caller_func,
                    call_site,
                    ctrl_display.get(controllability, controllability),
                    str(len(sources)),
                    disasm or "",
                ])
        except Exception as e:
            print(f"[MCP] 扫描命令注入时出错: {e}")
        
        return True
    
    def show_window(self):
        """Show the chooser window"""
        return ida_kernwin.Choose.Show(self)


# ============================================================================
# Source Functions Viewer
# ============================================================================

class SourceFunctionsChooser(ida_kernwin.Choose):
    """IDA Chooser window for displaying found source (input) functions"""
    
    def __init__(self, title="输入源函数 (Source)"):
        self.items = []
        
        columns = [
            ["函数名", 20],
            ["地址", 12],
            ["类别", 15],
            ["调用次数", 10],
        ]
        
        ida_kernwin.Choose.__init__(
            self,
            title,
            columns,
            flags=ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        
        self.Refresh()
    
    def OnInit(self):
        return True
    
    def OnGetSize(self):
        return len(self.items)
    
    def OnGetLine(self, n):
        if n < len(self.items):
            return self.items[n]
        return ["", "", "", ""]
    
    def OnSelectLine(self, sel):
        """Handle Enter key - jump to address"""
        if isinstance(sel, list):
            n = sel[0] if sel else -1
        else:
            n = sel
        self._jump_to_line(n)
    
    def OnDblClick(self, sel):
        """Handle double-click - jump to address"""
        if isinstance(sel, list):
            n = sel[0] if sel else -1
        else:
            n = sel
        self._jump_to_line(n)
        return True
    
    def _jump_to_line(self, n):
        """Jump to the address of the selected line"""
        try:
            if n >= 0 and n < len(self.items):
                item = self.items[n]
                # Jump to function address (column 1)
                addr_str = item[1]
                if addr_str:
                    if addr_str.startswith("0x"):
                        addr = int(addr_str, 16)
                    else:
                        addr = int(addr_str)
                    print(f"[MCP] 跳转到: {hex(addr)}")
                    ida_kernwin.jumpto(addr)
        except Exception as e:
            print(f"[MCP] 跳转失败: {e}, n={n}, type={type(n)}")
    
    def OnRefresh(self, n):
        self.Refresh()
        return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(n)
    
    def Refresh(self):
        self.items = []
        
        import ida_name
        import idautils
        
        category_names = {
            "network": "网络输入",
            "user_input": "用户输入",
            "file_input": "文件输入",
            "web_input": "Web输入",
        }
        
        for category, func_list in SOURCE_FUNCTIONS.items():
            for func_name in func_list:
                # Try to find this function
                ea = ida_name.get_name_ea(idaapi.BADADDR, func_name)
                if ea == idaapi.BADADDR:
                    ea = ida_name.get_name_ea(idaapi.BADADDR, f"_{func_name}")
                
                if ea != idaapi.BADADDR:
                    # Count references
                    xref_count = sum(1 for _ in idautils.XrefsTo(ea, 0))
                    if xref_count > 0:
                        self.items.append([
                            func_name,
                            hex(ea),
                            category_names.get(category, category),
                            str(xref_count),
                        ])
        
        # Sort by xref count
        self.items.sort(key=lambda x: int(x[3]), reverse=True)
        return True
    
    def show_window(self):
        """Show the chooser window"""
        return ida_kernwin.Choose.Show(self)


# ============================================================================
# Exploit Chain Detail Viewer
# ============================================================================

class ExploitChainViewer(ida_kernwin.simplecustviewer_t):
    """Custom viewer for displaying exploit chain details"""
    
    def __init__(self):
        ida_kernwin.simplecustviewer_t.__init__(self)
        self.vuln_data = None
    
    def Create(self, title="利用链详情"):
        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            return False
        
        # Add keyboard shortcut hints
        self.AddLine("按 Enter 跳转到选中的地址")
        self.AddLine("按 R 刷新数据")
        self.AddLine("-" * 60)
        
        return True
    
    def SetData(self, vuln):
        """Set vulnerability data to display"""
        self.vuln_data = vuln
        self.ClearLines()
        
        if not vuln:
            self.AddLine("无数据")
            return
        
        # Header
        risk_icons = {
            "critical": "🔴 严重",
            "high": "🟠 高危", 
            "medium": "🟡 中危",
            "low": "🟢 低危",
        }
        
        self.AddLine(f"漏洞 #{vuln['id']} - {risk_icons.get(vuln['risk_level'], vuln['risk_level'])}")
        self.AddLine("=" * 60)
        self.AddLine("")
        
        # Sink info
        self.AddLine(f"[Sink 危险函数]")
        self.AddLine(f"  函数: {vuln['sink_func']}")
        self.AddLine(f"  地址: {vuln['sink_addr']}")
        self.AddLine("")
        
        # Caller info
        self.AddLine(f"[调用位置]")
        self.AddLine(f"  函数: {vuln['caller_func']}")
        self.AddLine(f"  地址: {vuln['caller_addr']}")
        self.AddLine(f"  调用点: {vuln['call_site']}")
        self.AddLine(f"  反汇编: {vuln['disasm']}")
        self.AddLine(f"  可控性: {vuln['controllability'].upper()}")
        self.AddLine("")
        
        # Sources
        sources = vuln.get("sources", [])
        if sources:
            self.AddLine(f"[输入源 - 共 {len(sources)} 个]")
            for i, src in enumerate(sources, 1):
                location = src.get("location", "")
                via = src.get("via_function", "")
                loc_str = "同函数" if location == "same_function" else f"经由 {via}" if via else ""
                self.AddLine(f"  {i}. {src['name']} ({src['category']}) {loc_str}")
                self.AddLine(f"     地址: {src['addr']}")
            self.AddLine("")
        
        # Exploit paths
        paths = vuln.get("exploit_paths", [])
        if paths:
            self.AddLine(f"[利用链路径 - 共 {len(paths)} 条]")
            for i, path in enumerate(paths, 1):
                self.AddLine(f"  路径 {i}: {path['source_func']} -> ... -> {path['sink_func']}")
                self.AddLine(f"    长度: {path['path_length']} 步")
                
                # Show path nodes
                nodes = path.get("path", [])
                if nodes:
                    path_str = " → ".join(n["name"] for n in nodes)
                    self.AddLine(f"    {path['source_func']} → {path_str}")
                self.AddLine("")
        
        self.Refresh()
    
    def OnKeydown(self, vkey, shift):
        # R - Refresh
        if vkey == ord('R'):
            if self.vuln_data:
                self.SetData(self.vuln_data)
            return True
        return False


# ============================================================================
# Main Window Manager
# ============================================================================

class VulnScannerWindow:
    """Manager class for vulnerability scanner windows"""
    
    _dangerous_chooser = None
    _cmdi_chooser = None
    _source_chooser = None
    _chain_viewer = None
    
    @classmethod
    def show_dangerous_functions(cls):
        """Show dangerous functions scanner window"""
        if cls._dangerous_chooser is None:
            cls._dangerous_chooser = DangerousFunctionsChooser()
        cls._dangerous_chooser.show_window()
        return cls._dangerous_chooser
    
    @classmethod
    def show_command_injection(cls):
        """Show command injection scanner window"""
        if cls._cmdi_chooser is None:
            cls._cmdi_chooser = CommandInjectionChooser()
        cls._cmdi_chooser.show_window()
        return cls._cmdi_chooser
    
    @classmethod
    def show_source_functions(cls):
        """Show source functions window"""
        if cls._source_chooser is None:
            cls._source_chooser = SourceFunctionsChooser()
        cls._source_chooser.show_window()
        return cls._source_chooser
    
    @classmethod
    def show_all(cls):
        """Show all scanner windows"""
        cls.show_dangerous_functions()
        cls.show_command_injection()
    
    @classmethod
    def refresh_all(cls):
        """Refresh all open windows"""
        if cls._dangerous_chooser:
            cls._dangerous_chooser.Refresh()
        if cls._cmdi_chooser:
            cls._cmdi_chooser.Refresh()
        if cls._source_chooser:
            cls._source_chooser.Refresh()


# ============================================================================
# Action Handlers for IDA Menu
# ============================================================================

class DangerousFunctionsAction(ida_kernwin.action_handler_t):
    """Action handler for showing dangerous functions window"""
    
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        VulnScannerWindow.show_dangerous_functions()
        return 1
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class CommandInjectionAction(ida_kernwin.action_handler_t):
    """Action handler for showing command injection window"""
    
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        VulnScannerWindow.show_command_injection()
        return 1
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class SourceFunctionsAction(ida_kernwin.action_handler_t):
    """Action handler for showing source functions window"""
    
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        VulnScannerWindow.show_source_functions()
        return 1
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class ShowAllScannersAction(ida_kernwin.action_handler_t):
    """Action handler for showing all scanner windows"""
    
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        VulnScannerWindow.show_all()
        return 1
    
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


# ============================================================================
# Menu Registration
# ============================================================================

# Action descriptors
ACTION_DANGEROUS = "mcp:dangerous_functions"
ACTION_CMDI = "mcp:command_injection"
ACTION_SOURCES = "mcp:source_functions"
ACTION_ALL = "mcp:show_all_scanners"


def register_actions():
    """Register all IDA actions"""
    
    # Dangerous functions action
    action_desc = ida_kernwin.action_desc_t(
        ACTION_DANGEROUS,
        "MCP: 危险函数扫描",
        DangerousFunctionsAction(),
        "Ctrl+Shift+D",
        "扫描并显示所有危险函数调用",
        -1
    )
    ida_kernwin.register_action(action_desc)
    
    # Command injection action
    action_desc = ida_kernwin.action_desc_t(
        ACTION_CMDI,
        "MCP: 命令注入扫描",
        CommandInjectionAction(),
        "Ctrl+Shift+I",
        "扫描命令注入漏洞并追踪利用链",
        -1
    )
    ida_kernwin.register_action(action_desc)
    
    # Source functions action
    action_desc = ida_kernwin.action_desc_t(
        ACTION_SOURCES,
        "MCP: 输入源函数",
        SourceFunctionsAction(),
        "Ctrl+Shift+S",
        "显示所有找到的输入源函数",
        -1
    )
    ida_kernwin.register_action(action_desc)
    
    # Show all action
    action_desc = ida_kernwin.action_desc_t(
        ACTION_ALL,
        "MCP: 打开所有扫描窗口",
        ShowAllScannersAction(),
        "Ctrl+Shift+A",
        "打开所有漏洞扫描窗口",
        -1
    )
    ida_kernwin.register_action(action_desc)


def attach_to_menu():
    """Attach actions to IDA menu"""
    
    # Create MCP submenu under View
    ida_kernwin.attach_action_to_menu(
        "View/MCP 漏洞扫描/",
        ACTION_DANGEROUS,
        ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        "View/MCP 漏洞扫描/",
        ACTION_CMDI,
        ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        "View/MCP 漏洞扫描/",
        ACTION_SOURCES,
        ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        "View/MCP 漏洞扫描/",
        ACTION_ALL,
        ida_kernwin.SETMENU_APP
    )


def unregister_actions():
    """Unregister all IDA actions"""
    ida_kernwin.unregister_action(ACTION_DANGEROUS)
    ida_kernwin.unregister_action(ACTION_CMDI)
    ida_kernwin.unregister_action(ACTION_SOURCES)
    ida_kernwin.unregister_action(ACTION_ALL)


def init_gui():
    """Initialize GUI components"""
    register_actions()
    attach_to_menu()
    print("[MCP] GUI 已注册:")
    print("  Ctrl+Shift+D - 危险函数扫描")
    print("  Ctrl+Shift+I - 命令注入扫描")
    print("  Ctrl+Shift+S - 输入源函数")
    print("  Ctrl+Shift+A - 打开所有扫描窗口")


def term_gui():
    """Cleanup GUI components"""
    unregister_actions()

