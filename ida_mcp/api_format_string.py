"""Format String Vulnerability Analysis API"""

from typing import Annotated, Optional, TypedDict
import idaapi
import idautils
import idc
import ida_funcs
import ida_name
import ida_hexrays
import ida_lines
import re

from .rpc import tool
from .sync import idaread

# ============================================================================
# Format String Functions
# ============================================================================

# Printf-like functions (format string is an argument)
PRINTF_LIKE_FUNCS = {
    # func_name: format_arg_index
    "printf": 0,
    "fprintf": 1,
    "dprintf": 1,
    "sprintf": 1,
    "snprintf": 2,
    "vprintf": 0,
    "vfprintf": 1,
    "vsprintf": 1,
    "vsnprintf": 2,
    "asprintf": 1,
    "vasprintf": 1,
}

# Syslog-like functions
SYSLOG_LIKE_FUNCS = {
    "syslog": 1,
    "vsyslog": 1,
    "openlog": 0,
}

# Custom/embedded format string functions
CUSTOM_FORMAT_FUNCS = {
    "printk": 0,  # Linux kernel
    "TRACE": 0,
    "LOG": 0,
    "DBG": 0,
    "debug_printf": 0,
    "log_printf": 0,
    "error_printf": 0,
    "warn_printf": 0,
}

ALL_FORMAT_FUNCS = {**PRINTF_LIKE_FUNCS, **SYSLOG_LIKE_FUNCS, **CUSTOM_FORMAT_FUNCS}


class FormatStringVuln(TypedDict):
    """Format string vulnerability information"""
    id: int
    severity: str  # critical, high, medium, low
    vuln_type: str  # user_controlled, partial_controlled, potential
    func_name: str
    func_addr: str
    call_site: str
    format_func: str
    format_arg_idx: int
    disasm: str
    pseudocode_snippet: str
    source_trace: list[dict]
    controllability: str
    exploitation_notes: str


class FormatStringChain(TypedDict):
    """Format string exploitation chain"""
    sink_func: str
    sink_addr: str
    entry_point: str
    entry_addr: str
    chain: list[dict]
    chain_length: int
    user_input_source: str
    risk_level: str


# ============================================================================
# Helper Functions
# ============================================================================


def _find_function_address(func_name: str) -> Optional[int]:
    """Find the address of a function by name"""
    ea = ida_name.get_name_ea(idaapi.BADADDR, func_name)
    if ea != idaapi.BADADDR:
        return ea
    
    ea = ida_name.get_name_ea(idaapi.BADADDR, f"_{func_name}")
    if ea != idaapi.BADADDR:
        return ea
    
    import ida_nalt
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        result = []
        def callback(ea, name, ordinal):
            if name and (name == func_name or name == f"_{func_name}" or
                        name.lower() == func_name.lower()):
                result.append(ea)
                return False
            return True
        ida_nalt.enum_import_names(i, callback)
        if result:
            return result[0]
    return None


def _analyze_format_string_controllability(func_addr: int, format_func: str) -> dict:
    """Analyze if the format string is user-controllable"""
    result = {
        "controllability": "unknown",
        "pseudocode_snippet": "",
        "source_trace": [],
        "notes": "",
    }
    
    try:
        cfunc = ida_hexrays.decompile(func_addr)
        if not cfunc:
            return result
        
        # Get pseudocode as text
        sv = cfunc.get_pseudocode()
        lines = []
        for sl in sv:
            lines.append(ida_lines.tag_remove(sl.line))
        pseudocode = "\n".join(lines)
        
        result["pseudocode_snippet"] = pseudocode[:2000]  # Limit size
        
        # User input patterns that indicate controllable format string
        dangerous_patterns = [
            # Direct user input to format function
            (rf'{format_func}\s*\([^,]*,?\s*(argv|getenv|gets|fgets|scanf|recv|read|input|buf|data|param|query)\b', "high"),
            (rf'{format_func}\s*\([^,]*,?\s*\w*[Bb]uf\w*', "high"),
            (rf'{format_func}\s*\([^,]*,?\s*\w*[Ii]nput\w*', "high"),
            (rf'{format_func}\s*\([^,]*,?\s*\w*[Dd]ata\w*', "medium"),
            # Format string from variable (needs tracing)
            (rf'{format_func}\s*\([^,]*,?\s*[a-z_][a-z0-9_]*\s*[,)]', "medium"),
        ]
        
        # Check for static format strings (safe)
        static_pattern = rf'{format_func}\s*\([^,]*,?\s*"[^"]*"'
        if re.search(static_pattern, pseudocode, re.IGNORECASE):
            result["controllability"] = "low"
            result["notes"] = "格式化字符串是静态字符串，风险较低"
            return result
        
        for pattern, level in dangerous_patterns:
            match = re.search(pattern, pseudocode, re.IGNORECASE)
            if match:
                result["controllability"] = level
                result["notes"] = f"发现可能的用户可控格式化字符串: {match.group()}"
                return result
        
        # Check for user input functions in the same function
        user_input_funcs = ["getenv", "gets", "fgets", "scanf", "recv", "read", "argv"]
        for input_func in user_input_funcs:
            if input_func in pseudocode.lower():
                result["source_trace"].append({
                    "type": "user_input",
                    "func": input_func,
                    "in_same_function": True,
                })
                result["controllability"] = "medium"
                result["notes"] = f"函数中存在用户输入函数 {input_func}"
        
        if not result["source_trace"]:
            result["controllability"] = "low"
            result["notes"] = "未发现明显的用户可控输入"
            
    except Exception as e:
        result["notes"] = f"分析失败: {e}"
    
    return result


def _get_exploitation_notes(controllability: str, format_func: str) -> str:
    """Get exploitation notes based on the vulnerability"""
    notes = []
    
    if controllability == "high":
        notes.append("【危险】格式化字符串可能完全由用户控制")
        notes.append("可以使用 %n 写入任意内存地址")
        notes.append("可以使用 %s 读取任意内存")
        notes.append("可以使用 %x 泄露栈数据")
    elif controllability == "medium":
        notes.append("【警告】格式化字符串可能部分受用户影响")
        notes.append("需要进一步分析数据流确认可控性")
    else:
        notes.append("【低风险】格式化字符串看起来是静态的")
    
    if format_func in ["sprintf", "vsprintf"]:
        notes.append("此外，sprintf/vsprintf 还可能导致缓冲区溢出")
    
    return "\n".join(notes)


# ============================================================================
# API Functions
# ============================================================================


@tool
@idaread
def scan_format_string_vulns() -> list[FormatStringVuln]:
    """Scan for format string vulnerabilities.
    
    Identifies:
    - Calls to printf-like functions with non-constant format strings
    - User-controllable format strings
    - Potential exploitation paths
    """
    vulnerabilities = []
    vuln_id = 0
    
    for format_func, fmt_arg_idx in ALL_FORMAT_FUNCS.items():
        func_addr = _find_function_address(format_func)
        if func_addr is None:
            continue
        
        for xref in idautils.XrefsTo(func_addr, 0):
            if not xref.iscode:
                continue
            
            caller_addr = xref.frm
            caller_func = idaapi.get_func(caller_addr)
            if not caller_func:
                continue
            
            caller_name = ida_funcs.get_func_name(caller_func.start_ea)
            disasm = idc.generate_disasm_line(caller_addr, 0)
            disasm = ida_lines.tag_remove(disasm) if disasm else ""
            
            # Analyze controllability
            analysis = _analyze_format_string_controllability(
                caller_func.start_ea, format_func
            )
            
            controllability = analysis.get("controllability", "unknown")
            
            # Determine severity
            if controllability == "high":
                severity = "critical"
                vuln_type = "user_controlled"
            elif controllability == "medium":
                severity = "high"
                vuln_type = "partial_controlled"
            else:
                severity = "low"
                vuln_type = "potential"
            
            # Skip low-risk ones unless they're important
            if severity == "low" and format_func not in ["printf", "sprintf"]:
                continue
            
            vuln_id += 1
            
            vulnerabilities.append(FormatStringVuln(
                id=vuln_id,
                severity=severity,
                vuln_type=vuln_type,
                func_name=caller_name,
                func_addr=hex(caller_func.start_ea),
                call_site=hex(caller_addr),
                format_func=format_func,
                format_arg_idx=fmt_arg_idx,
                disasm=disasm,
                pseudocode_snippet=analysis.get("pseudocode_snippet", "")[:500],
                source_trace=analysis.get("source_trace", []),
                controllability=controllability,
                exploitation_notes=_get_exploitation_notes(controllability, format_func),
            ))
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"], 4))
    
    return vulnerabilities


@tool
@idaread
def trace_format_string_chain(
    call_site: Annotated[str, "Call site address of the format string vulnerability"],
    max_depth: Annotated[int, "Maximum depth to trace"] = 10,
) -> FormatStringChain:
    """Trace the exploitation chain for a format string vulnerability.
    
    Traces backwards from the vulnerable call site to find:
    - Entry points where user input enters
    - Data flow through the program
    - Intermediate processing functions
    """
    try:
        addr = int(call_site, 16) if call_site.startswith("0x") else int(call_site)
    except:
        return {"error": f"Invalid address: {call_site}"}
    
    func = idaapi.get_func(addr)
    if not func:
        return {"error": "No function at address"}
    
    func_name = ida_funcs.get_func_name(func.start_ea)
    
    # Build the chain by tracing callers
    chain = [{
        "func_name": func_name,
        "func_addr": hex(func.start_ea),
        "call_addr": hex(addr),
        "role": "sink",
    }]
    
    # BFS to find entry points
    from collections import deque
    visited = {func.start_ea}
    queue = deque([(func.start_ea, chain)])
    
    user_input_source = None
    entry_point = None
    entry_addr = None
    
    while queue and len(chain) < max_depth:
        current_addr, current_chain = queue.popleft()
        
        # Get callers
        for xref in idautils.XrefsTo(current_addr, 0):
            if not xref.iscode:
                continue
            
            caller_func = idaapi.get_func(xref.frm)
            if not caller_func or caller_func.start_ea in visited:
                continue
            
            visited.add(caller_func.start_ea)
            caller_name = ida_funcs.get_func_name(caller_func.start_ea)
            
            new_entry = {
                "func_name": caller_name,
                "func_addr": hex(caller_func.start_ea),
                "call_addr": hex(xref.frm),
                "role": "propagator",
            }
            
            new_chain = [new_entry] + current_chain
            
            # Check if this is an entry point (has user input)
            try:
                cfunc = ida_hexrays.decompile(caller_func.start_ea)
                if cfunc:
                    pseudocode = str(cfunc).lower()
                    
                    input_patterns = [
                        ("main", "program entry"),
                        ("cgi_", "CGI handler"),
                        ("http_", "HTTP handler"),
                        ("handle_", "request handler"),
                        ("process_", "data processor"),
                        ("getenv", "environment variable"),
                        ("recv", "network input"),
                        ("read", "file/socket input"),
                        ("scanf", "user input"),
                        ("argv", "command line"),
                    ]
                    
                    for pattern, source_type in input_patterns:
                        if pattern in pseudocode or pattern in caller_name.lower():
                            entry_point = caller_name
                            entry_addr = hex(caller_func.start_ea)
                            user_input_source = source_type
                            new_entry["role"] = "entry_point"
                            chain = new_chain
                            break
            except:
                pass
            
            queue.append((caller_func.start_ea, new_chain))
    
    # If no clear entry point found, use the top of the chain
    if not entry_point and len(chain) > 1:
        entry_point = chain[0]["func_name"]
        entry_addr = chain[0]["func_addr"]
        user_input_source = "unknown"
    
    risk_level = "critical" if user_input_source in ["CGI handler", "HTTP handler", "network input"] else "high"
    
    return FormatStringChain(
        sink_func=func_name,
        sink_addr=hex(func.start_ea),
        entry_point=entry_point or func_name,
        entry_addr=entry_addr or hex(func.start_ea),
        chain=chain,
        chain_length=len(chain),
        user_input_source=user_input_source or "需要进一步分析",
        risk_level=risk_level,
    )


@tool
@idaread
def analyze_format_string_call(
    call_site: Annotated[str, "Address of the call to analyze"],
) -> dict:
    """Detailed analysis of a specific format string call.
    
    Provides:
    - Decompiled code around the call
    - Argument analysis
    - Exploitation potential assessment
    """
    try:
        addr = int(call_site, 16) if call_site.startswith("0x") else int(call_site)
    except:
        return {"error": f"Invalid address: {call_site}"}
    
    func = idaapi.get_func(addr)
    if not func:
        return {"error": "No function at address"}
    
    func_name = ida_funcs.get_func_name(func.start_ea)
    
    result = {
        "func_name": func_name,
        "func_addr": hex(func.start_ea),
        "call_site": hex(addr),
        "disasm": "",
        "pseudocode": "",
        "format_specifiers_found": [],
        "exploitation_potential": {},
    }
    
    # Get disassembly
    disasm = idc.generate_disasm_line(addr, 0)
    result["disasm"] = ida_lines.tag_remove(disasm) if disasm else ""
    
    # Get pseudocode
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc:
            sv = cfunc.get_pseudocode()
            lines = []
            for sl in sv:
                lines.append(ida_lines.tag_remove(sl.line))
            result["pseudocode"] = "\n".join(lines)
            
            pseudocode = result["pseudocode"]
            
            # Find format specifiers
            specifiers = re.findall(r'%[-+0 #]*\d*\.?\d*[hlL]?[diouxXeEfFgGaAcspn%]', pseudocode)
            result["format_specifiers_found"] = list(set(specifiers))
            
            # Analyze exploitation potential
            exploitation = {
                "can_read_memory": "%s" in specifiers or any("%x" in s or "%p" in s for s in specifiers),
                "can_write_memory": "%n" in specifiers,
                "can_leak_stack": any(s in specifiers for s in ["%x", "%p", "%lx"]),
                "can_crash": "%s" in specifiers or "%n" in specifiers,
            }
            result["exploitation_potential"] = exploitation
            
    except Exception as e:
        result["error"] = f"反编译失败: {e}"
    
    return result


@tool
@idaread
def get_format_string_functions() -> dict:
    """Get all tracked format string functions"""
    return {
        "printf_like": PRINTF_LIKE_FUNCS,
        "syslog_like": SYSLOG_LIKE_FUNCS,
        "custom": CUSTOM_FORMAT_FUNCS,
        "total": len(ALL_FORMAT_FUNCS),
    }

