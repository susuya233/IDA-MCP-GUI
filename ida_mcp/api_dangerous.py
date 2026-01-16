"""Dangerous Functions API - Find calls to potentially dangerous/vulnerable functions"""

from typing import Annotated, Optional, TypedDict
import idaapi
import idautils
import idc
import ida_funcs
import ida_name
import ida_xref

from .rpc import tool
from .sync import idaread
from .utils import parse_address, get_function

# ============================================================================
# Dangerous Functions List - Common vulnerable/dangerous functions
# ============================================================================

# Memory copy functions - buffer overflow risks
MEMORY_COPY_FUNCTIONS = [
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "strncpy", "strncat", "snprintf", "vsnprintf",
    "memcpy", "memmove", "bcopy",
]

# Format string functions - format string vulnerabilities
FORMAT_STRING_FUNCTIONS = [
    "printf", "fprintf", "dprintf", "syslog", "vsyslog",
    "asprintf", "vasprintf",
]

# Input functions - input validation risks
INPUT_FUNCTIONS = [
    "scanf", "sscanf", "fscanf", "vscanf", "vfscanf", "vsscanf",
]

# Command execution - command injection risks
COMMAND_EXEC_FUNCTIONS = [
    "system", "popen", "pclose",
    "execl", "execlp", "execle", "execv", "execvp", "execvpe",
    "doSystem", "doSystemCmd", "doShell",
    "run_cmd", "cmd_exec", "ExecCmd", "exec_cmd",
    "os_system", "shell_exec",
]

# File operations - path traversal risks
FILE_OPERATION_FUNCTIONS = [
    "open", "open64", "fopen", "freopen", "creat",
    "unlink", "remove", "rename", "link", "symlink",
    "readlink", "realpath", "chdir", "mkdir", "rmdir",
    "tmpnam", "tempnam", "mktemp",
]

# All dangerous functions grouped by category
DANGEROUS_FUNCTIONS = {
    "memory_copy": MEMORY_COPY_FUNCTIONS,
    "format_string": FORMAT_STRING_FUNCTIONS,
    "input": INPUT_FUNCTIONS,
    "command_exec": COMMAND_EXEC_FUNCTIONS,
    "file_operation": FILE_OPERATION_FUNCTIONS,
}

# Flat list of all dangerous function names
ALL_DANGEROUS_FUNCTIONS = (
    MEMORY_COPY_FUNCTIONS +
    FORMAT_STRING_FUNCTIONS +
    INPUT_FUNCTIONS +
    COMMAND_EXEC_FUNCTIONS +
    FILE_OPERATION_FUNCTIONS
)


class DangerousFunctionCall(TypedDict):
    """Represents a call to a dangerous function"""
    dangerous_func_name: str
    dangerous_func_addr: str
    category: str
    caller_addr: str
    caller_name: Optional[str]
    caller_func_addr: Optional[str]


class DangerousFunctionInfo(TypedDict):
    """Information about a dangerous function and its callers"""
    name: str
    addr: str
    category: str
    call_count: int
    callers: list[dict]


# ============================================================================
# API Functions
# ============================================================================


def _get_function_category(func_name: str) -> str:
    """Get the category of a dangerous function"""
    for category, funcs in DANGEROUS_FUNCTIONS.items():
        if func_name in funcs:
            return category
    return "unknown"


def _find_dangerous_function_address(func_name: str) -> Optional[int]:
    """Find the address of a dangerous function by name"""
    # Try exact name match first
    ea = ida_name.get_name_ea(idaapi.BADADDR, func_name)
    if ea != idaapi.BADADDR:
        return ea
    
    # Try with underscore prefix (common in some binaries)
    ea = ida_name.get_name_ea(idaapi.BADADDR, f"_{func_name}")
    if ea != idaapi.BADADDR:
        return ea
    
    # Try with double underscore prefix
    ea = ida_name.get_name_ea(idaapi.BADADDR, f"__{func_name}")
    if ea != idaapi.BADADDR:
        return ea
    
    # Search in imports
    import ida_nalt
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        def check_import(ea, name, ordinal):
            if name and (name == func_name or name == f"_{func_name}" or 
                        name.endswith(f"::{func_name}") or
                        name.lower() == func_name.lower()):
                return ea
            return True
        
        result = []
        def callback(ea, name, ordinal):
            check_result = check_import(ea, name, ordinal)
            if check_result != True:
                result.append(check_result)
                return False  # Stop enumeration
            return True
        
        ida_nalt.enum_import_names(i, callback)
        if result:
            return result[0]
    
    return None


def _get_callers_of_function(func_addr: int) -> list[dict]:
    """Get all callers of a function"""
    callers = []
    
    for xref in idautils.XrefsTo(func_addr, 0):
        # Only consider code references (calls)
        if not xref.iscode:
            continue
        
        caller_addr = xref.frm
        caller_func = idaapi.get_func(caller_addr)
        
        caller_info = {
            "call_addr": hex(caller_addr),
            "caller_func_name": None,
            "caller_func_addr": None,
        }
        
        if caller_func:
            func_name = ida_funcs.get_func_name(caller_func.start_ea)
            caller_info["caller_func_name"] = func_name
            caller_info["caller_func_addr"] = hex(caller_func.start_ea)
        
        # Get the disassembly line at the call site
        disasm = idc.generate_disasm_line(caller_addr, 0)
        if disasm:
            import ida_lines
            caller_info["disasm"] = ida_lines.tag_remove(disasm)
        
        callers.append(caller_info)
    
    return callers


@tool
@idaread
def find_dangerous_calls(
    categories: Annotated[
        Optional[list[str]], 
        "Filter by categories: memory_copy, format_string, input, command_exec, file_operation. None for all."
    ] = None,
) -> list[DangerousFunctionInfo]:
    """Find all calls to dangerous/vulnerable functions in the binary.
    
    Scans for calls to common dangerous functions that may lead to security vulnerabilities:
    - memory_copy: strcpy, strcat, sprintf, memcpy, etc. (buffer overflow risks)
    - format_string: printf, syslog, etc. (format string vulnerabilities)
    - input: scanf, sscanf, etc. (input validation risks)
    - command_exec: system, popen, exec*, etc. (command injection risks)
    - file_operation: fopen, unlink, etc. (path traversal risks)
    """
    results = []
    
    # Determine which functions to search for
    if categories:
        func_names_to_search = []
        for cat in categories:
            if cat in DANGEROUS_FUNCTIONS:
                func_names_to_search.extend(DANGEROUS_FUNCTIONS[cat])
    else:
        func_names_to_search = ALL_DANGEROUS_FUNCTIONS
    
    # Search for each dangerous function
    for func_name in func_names_to_search:
        func_addr = _find_dangerous_function_address(func_name)
        if func_addr is None:
            continue
        
        callers = _get_callers_of_function(func_addr)
        if not callers:
            continue
        
        category = _get_function_category(func_name)
        
        results.append(DangerousFunctionInfo(
            name=func_name,
            addr=hex(func_addr),
            category=category,
            call_count=len(callers),
            callers=callers,
        ))
    
    # Sort by call count (most called first)
    results.sort(key=lambda x: x["call_count"], reverse=True)
    
    return results


@tool
@idaread
def get_dangerous_function_categories() -> dict:
    """Get all dangerous function categories and their functions"""
    return {
        "categories": DANGEROUS_FUNCTIONS,
        "total_functions": len(ALL_DANGEROUS_FUNCTIONS),
    }


@tool
@idaread
def analyze_dangerous_function(
    func_name: Annotated[str, "Name of the dangerous function to analyze"],
) -> Optional[DangerousFunctionInfo]:
    """Analyze a specific dangerous function and find all its callers"""
    func_addr = _find_dangerous_function_address(func_name)
    if func_addr is None:
        return None
    
    callers = _get_callers_of_function(func_addr)
    category = _get_function_category(func_name)
    
    return DangerousFunctionInfo(
        name=func_name,
        addr=hex(func_addr),
        category=category,
        call_count=len(callers),
        callers=callers,
    )

