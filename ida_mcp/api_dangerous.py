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

MEMORY_COPY_FUNCTIONS = [
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "strncpy", "strncat", "snprintf", "vsnprintf",
    "memcpy", "memmove", "bcopy",
    "wstrcpy", "lstrcpy", "lstrcpyA", "lstrcpyW",
    "safe_strcpy",
]

FORMAT_STRING_FUNCTIONS = [
    "printf", "fprintf", "dprintf", "syslog", "vsyslog",
    "asprintf", "vasprintf",
    "log_printf", "debug_printf", "err_printf", "warn_printf",
    "cgi_printf", "web_printf", "httpd_printf",
    "TRACE", "DBG", "LOG", "printk",
]

INPUT_FUNCTIONS = [
    "scanf", "sscanf", "fscanf", "vscanf", "vfscanf", "vsscanf",
    "cgi_input_parse", "parse_query", "decode_uri",
]

COMMAND_EXEC_FUNCTIONS = [
    "system", "popen", "pclose",
    "execl", "execlp", "execle", "execv", "execvp", "execvpe",
    
    "doSystem", "doSystemCmd", "doShell", "do_system",
    "run_cmd", "cmd_exec", "ExecCmd", "exec_cmd", "runcmd",
    "os_system", "shell_exec", "twsystem", "CsteSystem",
    
    "lxmldbc_system", "tpSystem", "acosSystem", "mi_system",
    "tenda_system", "ATP_UTIL_ExecShell", "VOS_System",
    "formSysCmd", "execCommand", "fwSystem",
    "websLaunchCgiProc", "cgiHandler",
    
    "debug_cmd", "test_cmd", "hidden_cmd", "backdoor",
]

FILE_OPERATION_FUNCTIONS = [
    "open", "open64", "fopen", "freopen", "creat",
    "unlink", "remove", "rename", "link", "symlink",
    "readlink", "realpath", "chdir", "mkdir", "rmdir",
    "tmpnam", "tempnam", "mktemp",
    "flash_write", "mtd_write", "firmware_upgrade",
]

CGI_HANDLER_FUNCTIONS = [
    "websGetVar", "websSetVar", "websRedirect", "websWrite",
    "websFormDefine", "websUrlHandlerDefine",
    "ejSetResult", "ejArgs", "ejGetResult",
    
    "cgi_get", "cgi_param", "get_param", "cgiGetValue",
    "cgi_printf", "cgi_write", "cgi_redirect",
    "httpGetEnv", "httpGetParam", "http_get_env",
    
    "nvram_get", "nvram_set", "nvram_safe_get", "nvram_commit",
    "acosNvramConfig_get", "acosNvramConfig_set",
    
    "uci_get", "uci_set", "uci_commit",
]

AUTH_FUNCTIONS = [
    "check_auth", "verify_password", "authenticate",
    "login_check", "session_check", "is_authenticated",
    "check_login", "verify_login", "passwd_check",
    "httpd_auth", "cgi_auth", "web_auth",
    "strcmp", "strncmp", "memcmp",
]

NETWORK_FUNCTIONS = [
    "socket", "connect", "bind", "listen", "accept",
    "send", "recv", "sendto", "recvfrom",
    "raw_socket", "packet_socket",
    "httpd_start", "start_httpd", "mini_httpd",
    "telnetd", "start_telnet", "dropbear",
]

DANGEROUS_FUNCTIONS = {
    "memory_copy": MEMORY_COPY_FUNCTIONS,
    "format_string": FORMAT_STRING_FUNCTIONS,
    "input": INPUT_FUNCTIONS,
    "command_exec": COMMAND_EXEC_FUNCTIONS,
    "file_operation": FILE_OPERATION_FUNCTIONS,
    "cgi_handler": CGI_HANDLER_FUNCTIONS,
    "auth": AUTH_FUNCTIONS,
    "network": NETWORK_FUNCTIONS,
}

ALL_DANGEROUS_FUNCTIONS = (
    MEMORY_COPY_FUNCTIONS +
    FORMAT_STRING_FUNCTIONS +
    INPUT_FUNCTIONS +
    COMMAND_EXEC_FUNCTIONS +
    FILE_OPERATION_FUNCTIONS +
    CGI_HANDLER_FUNCTIONS +
    AUTH_FUNCTIONS +
    NETWORK_FUNCTIONS
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

def _get_function_category(func_name: str) -> str:
    """Get the category of a dangerous function"""
    for category, funcs in DANGEROUS_FUNCTIONS.items():
        if func_name in funcs:
            return category
    return "unknown"

def _find_dangerous_function_address(func_name: str) -> Optional[int]:
    """Find the address of a dangerous function by name"""
    ea = ida_name.get_name_ea(idaapi.BADADDR, func_name)
    if ea != idaapi.BADADDR:
        return ea
    
    ea = ida_name.get_name_ea(idaapi.BADADDR, f"_{func_name}")
    if ea != idaapi.BADADDR:
        return ea
    
    ea = ida_name.get_name_ea(idaapi.BADADDR, f"__{func_name}")
    if ea != idaapi.BADADDR:
        return ea
    
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
                return False
            return True
        
        ida_nalt.enum_import_names(i, callback)
        if result:
            return result[0]
    
    return None

def _get_callers_of_function(func_addr: int) -> list[dict]:
    """Get all callers of a function"""
    callers = []
    
    for xref in idautils.XrefsTo(func_addr, 0):
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
    
    if categories:
        func_names_to_search = []
        for cat in categories:
            if cat in DANGEROUS_FUNCTIONS:
                func_names_to_search.extend(DANGEROUS_FUNCTIONS[cat])
    else:
        func_names_to_search = ALL_DANGEROUS_FUNCTIONS
    
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
