"""Path Traversal Vulnerability Analysis API"""

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
# File Operation Functions
# ============================================================================

# File open functions
FILE_OPEN_FUNCS = {
    # func_name: path_arg_index
    "open": 0,
    "open64": 0,
    "fopen": 0,
    "freopen": 0,
    "openat": 1,
    "creat": 0,
    "opendir": 0,
    "fdopendir": 0,
}

# File access/stat functions
FILE_ACCESS_FUNCS = {
    "access": 0,
    "stat": 0,
    "stat64": 0,
    "lstat": 0,
    "lstat64": 0,
    "fstatat": 1,
}

# File manipulation functions
FILE_MANIP_FUNCS = {
    "unlink": 0,
    "unlinkat": 1,
    "remove": 0,
    "rename": (0, 1),  # Both args are paths
    "renameat": (1, 3),
    "link": (0, 1),
    "linkat": (1, 3),
    "symlink": (0, 1),
    "symlinkat": (0, 2),
    "readlink": 0,
    "readlinkat": 1,
}

# Directory functions
DIR_FUNCS = {
    "chdir": 0,
    "fchdir": 0,
    "mkdir": 0,
    "mkdirat": 1,
    "rmdir": 0,
    "getcwd": 0,
}

# Path resolution functions
PATH_RESOLVE_FUNCS = {
    "realpath": 0,
    "canonicalize_file_name": 0,
    "basename": 0,
    "dirname": 0,
}

# Dangerous temp file functions
TEMP_FILE_FUNCS = {
    "tmpnam": 0,
    "tempnam": (0, 1),
    "mktemp": 0,
    "mkstemp": 0,
    "mkostemp": 0,
}

ALL_FILE_FUNCS = {
    **FILE_OPEN_FUNCS, **FILE_ACCESS_FUNCS, **FILE_MANIP_FUNCS,
    **DIR_FUNCS, **PATH_RESOLVE_FUNCS, **TEMP_FILE_FUNCS,
}


class PathTraversalVuln(TypedDict):
    """Path traversal vulnerability information"""
    id: int
    severity: str
    vuln_type: str  # directory_traversal, symlink_attack, race_condition, temp_file_attack
    func_name: str
    func_addr: str
    call_site: str
    file_func: str
    path_arg_idx: int
    disasm: str
    path_source: str  # user_input, config, hardcoded, unknown
    has_sanitization: bool
    sanitization_type: str
    exploitation_notes: str


class PathTraversalChain(TypedDict):
    """Path traversal exploitation chain"""
    file_op: str
    file_op_addr: str
    entry_point: str
    entry_addr: str
    chain: list[dict]
    path_construction: list[dict]
    risk_level: str


# ============================================================================
# Path Traversal Patterns
# ============================================================================

TRAVERSAL_PATTERNS = [
    r'\.\.',           # Basic parent directory
    r'\.\./',          # Unix style
    r'\.\.\\',         # Windows style
    r'%2e%2e',         # URL encoded
    r'%252e%252e',     # Double URL encoded
    r'\.\./\.\.',      # Multiple levels
]

DANGEROUS_PATH_PATTERNS = [
    (r'/etc/passwd', "尝试访问系统密码文件"),
    (r'/etc/shadow', "尝试访问系统影子密码文件"),
    (r'/proc/', "尝试访问 proc 文件系统"),
    (r'/dev/', "尝试访问设备文件"),
    (r'C:\\Windows', "尝试访问 Windows 系统目录"),
    (r'/tmp/', "使用临时目录，可能存在竞争条件"),
]

SANITIZATION_PATTERNS = [
    (r'realpath\s*\(', "realpath 规范化"),
    (r'canonicalize', "路径规范化"),
    (r'strstr\s*\([^,]+,\s*"\.\."', "检查 .. 模式"),
    (r'strchr\s*\([^,]+,\s*[\'"]/', "检查路径分隔符"),
    (r'basename\s*\(', "basename 提取"),
    (r'if\s*\([^)]*\.\.\s*\)', "条件检查 .."),
]


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


def _analyze_path_source(func_addr: int, file_func: str) -> dict:
    """Analyze the source of the path argument"""
    result = {
        "source": "unknown",
        "has_sanitization": False,
        "sanitization_type": "",
        "pseudocode_snippet": "",
        "dangerous_patterns": [],
    }
    
    try:
        cfunc = ida_hexrays.decompile(func_addr)
        if not cfunc:
            return result
        
        sv = cfunc.get_pseudocode()
        lines = []
        for sl in sv:
            lines.append(ida_lines.tag_remove(sl.line))
        pseudocode = "\n".join(lines)
        
        result["pseudocode_snippet"] = pseudocode[:2000]
        
        # Check for user input sources
        user_input_patterns = [
            (r'getenv\s*\(', "environment"),
            (r'argv\b', "command_line"),
            (r'gets\s*\(|fgets\s*\(|scanf\s*\(', "user_input"),
            (r'recv\s*\(|read\s*\(', "network"),
            (r'cgi_|query_string|request', "web_input"),
            (r'nvram_get|config_get|uci_get', "config"),
        ]
        
        for pattern, source_type in user_input_patterns:
            if re.search(pattern, pseudocode, re.IGNORECASE):
                result["source"] = source_type
                break
        
        # Check if there's any path construction with user input
        path_construct_patterns = [
            (rf'sprintf\s*\([^,]+,\s*"[^"]*%s[^"]*",', "sprintf path construction"),
            (rf'snprintf\s*\([^,]+,\s*\d+,\s*"[^"]*%s[^"]*",', "snprintf path construction"),
            (rf'strcat\s*\([^,]+,\s*', "strcat path construction"),
            (rf'strcpy\s*\([^,]+,\s*', "strcpy path construction"),
        ]
        
        for pattern, desc in path_construct_patterns:
            if re.search(pattern, pseudocode, re.IGNORECASE):
                result["dangerous_patterns"].append(desc)
        
        # Check for sanitization
        for pattern, san_type in SANITIZATION_PATTERNS:
            if re.search(pattern, pseudocode, re.IGNORECASE):
                result["has_sanitization"] = True
                result["sanitization_type"] = san_type
                break
        
        # Check for dangerous hardcoded paths
        for pattern, desc in DANGEROUS_PATH_PATTERNS:
            if re.search(pattern, pseudocode, re.IGNORECASE):
                result["dangerous_patterns"].append(desc)
        
        # If no source found but there's string operations, likely some input
        if result["source"] == "unknown" and result["dangerous_patterns"]:
            result["source"] = "constructed"
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def _get_exploitation_notes(vuln_type: str, source: str, has_sanitization: bool) -> str:
    """Generate exploitation notes"""
    notes = []
    
    if vuln_type == "directory_traversal":
        notes.append("【目录穿越】可能通过 ../ 序列访问任意文件")
        if source in ["user_input", "web_input", "network"]:
            notes.append("用户可控输入，高风险")
        if not has_sanitization:
            notes.append("未检测到路径清理，可能可以直接利用")
        else:
            notes.append("检测到某些清理措施，需要进一步分析绕过可能")
    
    elif vuln_type == "symlink_attack":
        notes.append("【符号链接攻击】可能通过符号链接访问敏感文件")
        notes.append("检查是否使用 O_NOFOLLOW 标志")
    
    elif vuln_type == "race_condition":
        notes.append("【竞争条件】文件操作之间可能存在 TOCTOU 漏洞")
        notes.append("检查 access() 后的 open() 调用")
    
    elif vuln_type == "temp_file_attack":
        notes.append("【临时文件攻击】不安全的临时文件创建")
        notes.append("使用 mkstemp() 代替 tmpnam()/mktemp()")
    
    return "\n".join(notes)


def _determine_vuln_type(file_func: str, analysis: dict) -> str:
    """Determine the type of path traversal vulnerability"""
    if file_func in TEMP_FILE_FUNCS:
        return "temp_file_attack"
    
    if file_func in ["symlink", "symlinkat", "readlink", "readlinkat"]:
        return "symlink_attack"
    
    if file_func == "access":
        return "race_condition"
    
    return "directory_traversal"


# ============================================================================
# API Functions
# ============================================================================


@tool
@idaread
def scan_path_traversal_vulns() -> list[PathTraversalVuln]:
    """Scan for path traversal vulnerabilities.
    
    Identifies:
    - Directory traversal (../ attacks)
    - Symlink attacks
    - Race conditions (TOCTOU)
    - Insecure temp file creation
    """
    vulnerabilities = []
    vuln_id = 0
    
    for file_func, path_arg in ALL_FILE_FUNCS.items():
        func_addr = _find_function_address(file_func)
        if func_addr is None:
            continue
        
        # Get path arg index (handle tuple for functions with multiple path args)
        if isinstance(path_arg, tuple):
            path_arg_idx = path_arg[0]  # Use first path arg for analysis
        else:
            path_arg_idx = path_arg
        
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
            
            # Analyze path source
            analysis = _analyze_path_source(caller_func.start_ea, file_func)
            
            source = analysis.get("source", "unknown")
            has_sanitization = analysis.get("has_sanitization", False)
            
            # Skip if hardcoded paths with no user input
            if source == "unknown" and not analysis.get("dangerous_patterns"):
                continue
            
            vuln_type = _determine_vuln_type(file_func, analysis)
            
            # Determine severity
            if source in ["user_input", "web_input", "network"] and not has_sanitization:
                severity = "critical"
            elif source in ["user_input", "web_input", "network"]:
                severity = "high"
            elif source in ["environment", "command_line", "config"]:
                severity = "high" if not has_sanitization else "medium"
            elif vuln_type == "temp_file_attack":
                severity = "medium"
            elif vuln_type == "race_condition":
                severity = "medium"
            else:
                severity = "low"
            
            # Skip low severity unless it's a particularly dangerous function
            if severity == "low" and file_func not in ["open", "fopen", "unlink"]:
                continue
            
            vuln_id += 1
            
            vulnerabilities.append(PathTraversalVuln(
                id=vuln_id,
                severity=severity,
                vuln_type=vuln_type,
                func_name=caller_name,
                func_addr=hex(caller_func.start_ea),
                call_site=hex(caller_addr),
                file_func=file_func,
                path_arg_idx=path_arg_idx,
                disasm=disasm,
                path_source=source,
                has_sanitization=has_sanitization,
                sanitization_type=analysis.get("sanitization_type", ""),
                exploitation_notes=_get_exploitation_notes(vuln_type, source, has_sanitization),
            ))
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"], 4))
    
    return vulnerabilities


@tool
@idaread
def analyze_path_construction(
    func_addr: Annotated[str, "Function address to analyze"],
) -> dict:
    """Analyze how file paths are constructed in a function.
    
    Traces:
    - String concatenations
    - sprintf/snprintf calls
    - User input incorporation
    """
    try:
        addr = int(func_addr, 16) if func_addr.startswith("0x") else int(func_addr)
    except:
        return {"error": f"Invalid address: {func_addr}"}
    
    func = idaapi.get_func(addr)
    if not func:
        return {"error": "No function at address"}
    
    func_name = ida_funcs.get_func_name(func.start_ea)
    
    result = {
        "func_name": func_name,
        "func_addr": hex(func.start_ea),
        "path_constructions": [],
        "file_operations": [],
        "user_inputs": [],
        "sanitizations": [],
        "pseudocode": "",
    }
    
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc:
            sv = cfunc.get_pseudocode()
            lines = []
            for sl in sv:
                lines.append(ida_lines.tag_remove(sl.line))
            pseudocode = "\n".join(lines)
            result["pseudocode"] = pseudocode
            
            # Find path construction patterns
            construction_patterns = [
                (r'sprintf\s*\([^;]+;', "sprintf"),
                (r'snprintf\s*\([^;]+;', "snprintf"),
                (r'strcat\s*\([^;]+;', "strcat"),
                (r'strcpy\s*\([^;]+;', "strcpy"),
                (r'strncat\s*\([^;]+;', "strncat"),
                (r'strncpy\s*\([^;]+;', "strncpy"),
            ]
            
            for pattern, func_type in construction_patterns:
                matches = re.finditer(pattern, pseudocode)
                for match in matches:
                    result["path_constructions"].append({
                        "type": func_type,
                        "code": match.group()[:100],
                    })
            
            # Find file operations
            for file_func in ALL_FILE_FUNCS.keys():
                pattern = rf'{file_func}\s*\([^;]+;'
                matches = re.finditer(pattern, pseudocode)
                for match in matches:
                    result["file_operations"].append({
                        "func": file_func,
                        "code": match.group()[:100],
                    })
            
            # Find user inputs
            input_patterns = [
                (r'getenv\s*\([^)]+\)', "environment"),
                (r'argv\s*\[[^\]]+\]', "command_line"),
                (r'fgets\s*\([^;]+;', "user_input"),
                (r'scanf\s*\([^;]+;', "user_input"),
            ]
            
            for pattern, input_type in input_patterns:
                matches = re.finditer(pattern, pseudocode)
                for match in matches:
                    result["user_inputs"].append({
                        "type": input_type,
                        "code": match.group()[:100],
                    })
            
            # Find sanitizations
            for pattern, san_type in SANITIZATION_PATTERNS:
                if re.search(pattern, pseudocode, re.IGNORECASE):
                    result["sanitizations"].append({
                        "type": san_type,
                    })
    except Exception as e:
        result["error"] = str(e)
    
    return result


@tool
@idaread
def trace_path_traversal_chain(
    call_site: Annotated[str, "Call site address of the file operation"],
    max_depth: Annotated[int, "Maximum depth to trace"] = 10,
) -> PathTraversalChain:
    """Trace the exploitation chain for a path traversal vulnerability.
    
    Traces backwards to find:
    - Entry points
    - Path construction points
    - User input sources
    """
    try:
        addr = int(call_site, 16) if call_site.startswith("0x") else int(call_site)
    except:
        return {"error": f"Invalid address: {call_site}"}
    
    func = idaapi.get_func(addr)
    if not func:
        return {"error": "No function at address"}
    
    func_name = ida_funcs.get_func_name(func.start_ea)
    
    # Get the file operation
    disasm = idc.generate_disasm_line(addr, 0)
    file_op = ida_lines.tag_remove(disasm) if disasm else "unknown"
    
    chain = [{
        "func_name": func_name,
        "func_addr": hex(func.start_ea),
        "call_addr": hex(addr),
        "role": "file_operation",
    }]
    
    path_construction = []
    
    # Analyze current function for path construction
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc:
            pseudocode = str(cfunc)
            
            # Find path constructions
            patterns = [
                r'(sprintf|snprintf)\s*\([^;]+;',
                r'(strcat|strcpy)\s*\([^;]+;',
            ]
            
            for pattern in patterns:
                matches = re.finditer(pattern, pseudocode)
                for match in matches:
                    path_construction.append({
                        "code": match.group()[:100],
                        "func": func_name,
                    })
    except:
        pass
    
    # BFS to find entry points
    from collections import deque
    visited = {func.start_ea}
    queue = deque([(func.start_ea, chain)])
    
    entry_point = func_name
    entry_addr = hex(func.start_ea)
    
    while queue and len(chain) < max_depth:
        current_addr, current_chain = queue.popleft()
        
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
                "role": "caller",
            }
            
            new_chain = [new_entry] + current_chain
            
            # Check if this is an entry point
            entry_keywords = ["main", "cgi_", "http_", "handle_", "process_", "cmd_", "do_"]
            if any(kw in caller_name.lower() for kw in entry_keywords):
                entry_point = caller_name
                entry_addr = hex(caller_func.start_ea)
                new_entry["role"] = "entry_point"
                chain = new_chain
            
            queue.append((caller_func.start_ea, new_chain))
    
    return PathTraversalChain(
        file_op=file_op,
        file_op_addr=hex(addr),
        entry_point=entry_point,
        entry_addr=entry_addr,
        chain=chain,
        path_construction=path_construction,
        risk_level="high" if len(path_construction) > 0 else "medium",
    )


@tool
@idaread
def get_file_operation_functions() -> dict:
    """Get all tracked file operation functions by category"""
    return {
        "file_open": FILE_OPEN_FUNCS,
        "file_access": FILE_ACCESS_FUNCS,
        "file_manip": FILE_MANIP_FUNCS,
        "directory": DIR_FUNCS,
        "path_resolve": PATH_RESOLVE_FUNCS,
        "temp_file": TEMP_FILE_FUNCS,
        "total": len(ALL_FILE_FUNCS),
    }

