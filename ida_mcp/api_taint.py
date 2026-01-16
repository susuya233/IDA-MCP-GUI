"""Taint Analysis API - Command Injection Detection and Exploit Chain Tracing"""

from typing import Annotated, Optional, TypedDict
from collections import deque
import idaapi
import idautils
import idc
import ida_funcs
import ida_name
import ida_hexrays
import ida_lines

from .rpc import tool
from .sync import idaread

NETWORK_SOURCES = [
    "recv", "recvfrom", "recvmsg", "read", "readv", "pread", "pread64",
    "fread", "fgets", "getline", "getdelim",
    "socket", "accept", "accept4",
    "recv_data", "receive_data", "net_recv",
    "httpd_read", "http_read", "websRead", "websReadData",
    "httpRead", "httpGetData", "tcpRead", "udpRead",
]

USER_INPUT_SOURCES = [
    "gets", "scanf", "sscanf", "fscanf", "vscanf", "vfscanf", "vsscanf",
    "getchar", "fgetc", "getc", "getc_unlocked", "fgetc_unlocked",
    "getenv", "secure_getenv", "getenv_s",
    "argv",
]

FILE_INPUT_SOURCES = [
    "fopen", "freopen", "open", "open64", "openat",
    "mmap", "mmap64",
    "readlink", "realpath",
    "fopen_config", "read_config", "load_config",
]

WEB_INPUT_SOURCES = [
    "getenv",
    "QUERY_STRING", "REQUEST_METHOD", "CONTENT_TYPE", "CONTENT_LENGTH",
    "HTTP_COOKIE", "HTTP_USER_AGENT", "HTTP_REFERER", "REMOTE_ADDR",
    "REQUEST_URI", "SCRIPT_NAME", "PATH_INFO", "SERVER_NAME",
    "cgi_get", "cgi_param", "get_param", "get_query",
    "web_get", "http_get_param", "cgiGetValue", "cgiGetVariable",
    "cgi_input_parse", "cgi_get_val", "cgi_getvar",
    "websGetVar", "websGetVarStr", "websGetVarInt",
    "httpGetEnv", "httpGetParam", "http_get_env",
    "nvram_get", "nvram_safe_get", "nvram_bufget", "nvram_get_int",
    "nvram_match", "nvram_invmatch", "nvram_get_r", "acosNvramConfig_get",
    "bcmGetNvram", "bcm_nvram_get", "Nvram_Get", "NvramGet",
    "uci_get", "uci_get_option", "uci_lookup_option", "uci_get_string",
    "config_get", "GetValue", "getValue", "getValueByName",
    "cfg_get", "cfgGet", "get_config", "read_value",
    "sysconfig_get", "sys_get_value", "get_option",
    "get_cgi", "cgibin_parse", "cgibin_get", "FCGI_Get",
    "httpRpmConfGet", "tpHttpdGetEnv",
    "agApi_fwGetFirst",
    "tcapi_get", "tcapi_staticGet", "nvram_safe_get_r",
    "cgiGetValueByName",
    "ATP_DBGetPara", "ATP_DBGetParaStr", "DB_GetValue",
    "websGetVarSafe", "websGetFormVar",
    "ejGetResult", "ejArgs", "ejSetResult",
    "find_ivalue", "find_value", "unescape", "decodeUrl",
    "json_get", "json_object_get", "cJSON_GetObjectItem",
    "json_get_string", "json_get_value", "jsonGetValue",
]

EMBEDDED_SOURCES = [
    "serial_read", "uart_read", "console_read",
    "shm_read", "shared_mem_get", "ipc_recv",
    "msgrcv", "mq_receive",
    "flash_read", "eeprom_read", "mtd_read",
]

SOURCE_FUNCTIONS = {
    "network": NETWORK_SOURCES,
    "user_input": USER_INPUT_SOURCES,
    "file_input": FILE_INPUT_SOURCES,
    "web_input": WEB_INPUT_SOURCES,
    "embedded": EMBEDDED_SOURCES,
}

ALL_SOURCES = NETWORK_SOURCES + USER_INPUT_SOURCES + FILE_INPUT_SOURCES + WEB_INPUT_SOURCES + EMBEDDED_SOURCES

COMMAND_EXEC_SINKS = [
    "system", "popen", "pclose",
    "execl", "execlp", "execle", "execv", "execvp", "execvpe",
    "execve", "fexecve",
    
    "doSystem", "doSystemCmd", "doShell", "do_system", "dosystem",
    "run_cmd", "cmd_exec", "ExecCmd", "exec_cmd", "runcmd",
    "os_system", "shell_exec", "run_command", "execute_cmd",
    "twsystem", "CsteSystem", "cgi_deal_popen",
    "ExecShell", "RunShell", "shell", "Shell",
    
    "bb_system", "run_shell_cmd", "exec_shell", "xsystem",
    "spawn_shell", "start_shell", "launch_shell",
    
    "lxmldbc_system", "xmldbc_sys", "apmib_set_system",
    "cgibin_exec", "cgi_exec_cmd", "sendcmd", "fwSystem",
    
    "tpSystem", "tp_system", "httpd_system", "httpRpmDoSystem",
    "oal_sys_exec", "oal_doShell", "tpHttpdCgiCmd",
    
    "acosSystem", "acosSysExec", "system_ex", "RunCmd",
    "mini_system", "exec_system", "fw_system",
    
    "eval", "doCmd", "notify_rc", "kill_pidfile_s",
    "start_script", "run_custom_script", "sys_script",
    
    "tenda_system", "tpi_system", "tenda_exec", "tpiShell",
    "formSysCmd", "formDefineTendaCmd", "execCommand",
    
    "ATP_UTIL_ExecShell", "VOS_System", "ATP_UTIL_ForkExecv",
    "ATP_DBSaveParaToFlash", "HW_ExecCmd",
    
    "websFormDefine", "websUrlHandlerDefine", "websLaunchCgiProc",
    "cgiHandler", "ejEval", "ejEvalFile",
    
    "mi_system", "miot_system", "luci_exec",
    
    "luci_sys_exec", "ubus_call", "opkg_exec",
    
    "fork_exec", "vfork_exec", "spawn", "posix_spawn",
    "sh_exec", "bash_exec", "ash_exec", "busybox_exec",
    
    "debug_cmd", "debug_system", "test_cmd", "backdoor",
    "hidden_cmd", "admin_exec", "root_exec", "service_exec",
]

EVAL_SINKS = [
    "eval", "dlopen", "dlsym",
    "luaL_dostring", "luaL_loadstring", "lua_pcall",
    "js_eval", "duktape_eval", "jerryscript_eval",
]

SQL_SINKS = [
    "sqlite3_exec", "mysql_query", "mysql_real_query",
    "PQexec", "PQexecParams",
    "sql_exec", "db_query", "execute_sql",
    "sqlite_exec", "db_execute", "nvram_sql",
]

CONFIG_WRITE_SINKS = [
    "nvram_set", "nvram_commit", "nvram_bufset",
    "uci_set", "uci_commit", "uci_save",
    "config_set", "cfg_set", "write_config",
    "tcapi_set", "tcapi_commit",
    "ATP_DBSetPara", "ATP_DBSaveToFlash",
    "wlink_uci_set_value", "wlink_uci_get_value", "wlink_uci_commit",
    "wlink_set_option", "wlink_save_config",
]

SINK_FUNCTIONS = {
    "command_exec": COMMAND_EXEC_SINKS,
    "eval": EVAL_SINKS,
    "sql": SQL_SINKS,
    "config_write": CONFIG_WRITE_SINKS,
}

ALL_SINKS = COMMAND_EXEC_SINKS + EVAL_SINKS + SQL_SINKS + CONFIG_WRITE_SINKS

STRING_PROPAGATORS = [
    "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "memcpy", "memmove", "bcopy",
    "strdup", "strndup",
]

class SourceInfo(TypedDict):
    """Information about a source function"""
    name: str
    addr: str
    category: str
    callers: list[dict]

class SinkInfo(TypedDict):
    """Information about a sink function"""
    name: str
    addr: str
    category: str
    callers: list[dict]

class TaintPath(TypedDict):
    """A taint propagation path from source to sink"""
    source_func: str
    source_addr: str
    source_category: str
    sink_func: str
    sink_addr: str
    sink_category: str
    path: list[dict]
    path_length: int
    controllability: str
    risk_level: str

class VulnerabilityInfo(TypedDict):
    """Command injection vulnerability information"""
    id: int
    sink_func: str
    sink_addr: str
    caller_func: str
    caller_addr: str
    call_site: str
    disasm: str
    sources: list[dict]
    controllability: str
    risk_level: str
    exploit_paths: list[TaintPath]

def _find_function_address(func_name: str) -> Optional[int]:
    """Find the address of a function by name"""
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
        result = []
        
        def callback(ea, name, ordinal):
            if name and (name == func_name or name == f"_{func_name}" or
                        name.lower() == func_name.lower() or
                        name.endswith(f"::{func_name}")):
                result.append(ea)
                return False
            return True
        
        ida_nalt.enum_import_names(i, callback)
        if result:
            return result[0]
    
    return None

def _get_callers_of_function(func_addr: int) -> list[dict]:
    """Get all callers of a function with detailed info"""
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
            "disasm": None,
        }
        
        if caller_func:
            func_name = ida_funcs.get_func_name(caller_func.start_ea)
            caller_info["caller_func_name"] = func_name
            caller_info["caller_func_addr"] = hex(caller_func.start_ea)
        
        disasm = idc.generate_disasm_line(caller_addr, 0)
        if disasm:
            caller_info["disasm"] = ida_lines.tag_remove(disasm)
        
        callers.append(caller_info)
    
    return callers

def _get_function_callees(func_addr: int) -> list[tuple[int, str]]:
    """Get all functions called by the specified function"""
    func = idaapi.get_func(func_addr)
    if not func:
        return []
    
    callees = []
    for ea in idautils.FuncItems(func.start_ea):
        for xref in idautils.CodeRefsFrom(ea, 0):
            callee_name = ida_funcs.get_func_name(xref)
            if callee_name:
                callees.append((xref, callee_name))
    
    return list(set(callees))

def _get_function_callers(func_addr: int) -> list[tuple[int, str]]:
    """Get all functions that call the specified function"""
    callers = []
    
    for xref in idautils.CodeRefsTo(func_addr, 0):
        caller_func = idaapi.get_func(xref)
        if caller_func:
            caller_name = ida_funcs.get_func_name(caller_func.start_ea)
            if caller_name:
                callers.append((caller_func.start_ea, caller_name))
    
    return list(set(callers))

def _find_paths_between_functions(source_addr: int, sink_addr: int, max_depth: int = 10) -> list[list[dict]]:
    """Find call paths from source to sink using BFS"""
    paths = []
    
    queue = deque()
    queue.append((source_addr, [{"addr": hex(source_addr), "name": ida_funcs.get_func_name(source_addr)}], {source_addr}))
    
    while queue and len(paths) < 20:
        current_addr, path, visited = queue.popleft()
        
        if len(path) > max_depth:
            continue
        
        callees = _get_function_callees(current_addr)
        
        for callee_addr, callee_name in callees:
            if callee_addr == sink_addr:
                final_path = path + [{"addr": hex(callee_addr), "name": callee_name}]
                paths.append(final_path)
            elif callee_addr not in visited:
                new_path = path + [{"addr": hex(callee_addr), "name": callee_name}]
                new_visited = visited | {callee_addr}
                queue.append((callee_addr, new_path, new_visited))
    
    return paths

def _analyze_controllability(caller_func_addr: int, sink_name: str) -> str:
    """Analyze if the sink's arguments are controllable"""
    try:
        cfunc = ida_hexrays.decompile(caller_func_addr)
        if not cfunc:
            return "unknown"
        
        pseudocode = str(cfunc)
        
        dangerous_patterns = [
            f"{sink_name}(getenv",
            f"{sink_name}(argv",
            f"{sink_name}(buf",
            f"{sink_name}(input",
            f"{sink_name}(data",
            f"{sink_name}(cmd",
            f"{sink_name}(command",
            f"{sink_name}(param",
            f"{sink_name}(query",
            f"{sink_name}(request",
            "sprintf", "snprintf",
        ]
        
        has_source = any(src in pseudocode.lower() for src in 
                        ["getenv", "recv", "read", "scanf", "gets", "argv", 
                         "fgets", "nvram", "cgi", "query", "param"])
        has_sprintf = "sprintf" in pseudocode.lower() or "snprintf" in pseudocode.lower()
        
        if any(pattern.lower() in pseudocode.lower() for pattern in dangerous_patterns[:10]):
            return "high"
        elif has_source and has_sprintf:
            return "high"
        elif has_source:
            return "medium"
        elif has_sprintf:
            return "medium"
        else:
            return "low"
    except:
        return "unknown"

def _determine_risk_level(controllability: str, sink_category: str) -> str:
    """Determine overall risk level"""
    if sink_category == "command_exec":
        if controllability == "high":
            return "critical"
        elif controllability == "medium":
            return "high"
        else:
            return "medium"
    elif sink_category == "sql":
        if controllability == "high":
            return "critical"
        elif controllability == "medium":
            return "high"
        else:
            return "medium"
    else:
        if controllability == "high":
            return "high"
        else:
            return "medium"

@tool
@idaread
def scan_command_injection(
    max_depth: Annotated[int, "Maximum call chain depth to trace (default: 8)"] = 8,
) -> list[VulnerabilityInfo]:
    """Scan for command injection vulnerabilities with exploit chain tracing.
    
    This tool identifies potential command injection points by:
    1. Finding all calls to dangerous command execution functions (sinks)
    2. Tracing back to find user-controllable input sources
    3. Analyzing data flow controllability
    4. Rating risk levels based on exploitability
    """
    vulnerabilities = []
    vuln_id = 0
    
    for sink_category, sink_list in SINK_FUNCTIONS.items():
        for sink_name in sink_list:
            sink_addr = _find_function_address(sink_name)
            if sink_addr is None:
                continue
            
            callers = _get_callers_of_function(sink_addr)
            
            for caller in callers:
                caller_func_name = caller.get("caller_func_name")
                caller_func_addr = caller.get("caller_func_addr")
                
                if not caller_func_addr:
                    continue
                
                vuln_id += 1
                
                controllability = _analyze_controllability(
                    int(caller_func_addr, 16), sink_name
                )
                
                sources_found = []
                exploit_paths = []
                
                caller_addr_int = int(caller_func_addr, 16)
                
                caller_callees = _get_function_callees(caller_addr_int)
                for callee_addr, callee_name in caller_callees:
                    clean_name = callee_name.lstrip("_").lower()
                    for source_cat, source_list in SOURCE_FUNCTIONS.items():
                        if any(clean_name == s.lower() or clean_name.endswith(s.lower()) 
                               for s in source_list):
                            sources_found.append({
                                "name": callee_name,
                                "addr": hex(callee_addr),
                                "category": source_cat,
                                "location": "same_function",
                            })
                
                caller_of_callers = _get_function_callers(caller_addr_int)
                for coc_addr, coc_name in caller_of_callers[:10]:
                    coc_callees = _get_function_callees(coc_addr)
                    for callee_addr, callee_name in coc_callees:
                        clean_name = callee_name.lstrip("_").lower()
                        for source_cat, source_list in SOURCE_FUNCTIONS.items():
                            if any(clean_name == s.lower() or clean_name.endswith(s.lower()) 
                                   for s in source_list):
                                sources_found.append({
                                    "name": callee_name,
                                    "addr": hex(callee_addr),
                                    "category": source_cat,
                                    "location": "caller_function",
                                    "via_function": coc_name,
                                    "via_addr": hex(coc_addr),
                                })
                
                for source in sources_found[:5]:
                    source_addr = int(source["addr"], 16)
                    source_func = idaapi.get_func(source_addr)
                    if source_func:
                        paths = _find_paths_between_functions(
                            source_func.start_ea, caller_addr_int, max_depth
                        )
                        for path in paths[:3]:
                            exploit_paths.append(TaintPath(
                                source_func=source["name"],
                                source_addr=source["addr"],
                                source_category=source["category"],
                                sink_func=sink_name,
                                sink_addr=hex(sink_addr),
                                sink_category=sink_category,
                                path=path,
                                path_length=len(path),
                                controllability=controllability,
                                risk_level=_determine_risk_level(controllability, sink_category),
                            ))
                
                if sources_found and controllability == "low":
                    controllability = "medium"
                if any(s.get("location") == "same_function" for s in sources_found):
                    controllability = "high"
                
                risk_level = _determine_risk_level(controllability, sink_category)
                
                vulnerabilities.append(VulnerabilityInfo(
                    id=vuln_id,
                    sink_func=sink_name,
                    sink_addr=hex(sink_addr),
                    caller_func=caller_func_name or "<unknown>",
                    caller_addr=caller_func_addr,
                    call_site=caller.get("call_addr", ""),
                    disasm=caller.get("disasm", ""),
                    sources=sources_found,
                    controllability=controllability,
                    risk_level=risk_level,
                    exploit_paths=exploit_paths,
                ))
    
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vulnerabilities.sort(key=lambda x: (risk_order.get(x["risk_level"], 4), -len(x["sources"])))
    
    return vulnerabilities

@tool
@idaread
def get_source_functions() -> dict:
    """Get all defined source functions (user input points) by category"""
    return {
        "categories": SOURCE_FUNCTIONS,
        "total": len(ALL_SOURCES),
    }

@tool
@idaread
def get_sink_functions() -> dict:
    """Get all defined sink functions (dangerous functions) by category"""
    return {
        "categories": SINK_FUNCTIONS,
        "total": len(ALL_SINKS),
    }

@tool
@idaread
def trace_function_taint(
    func_addr: Annotated[str, "Function address to analyze"],
    max_depth: Annotated[int, "Maximum trace depth"] = 5,
) -> dict:
    """Trace taint flow through a specific function.
    
    Analyzes a function to identify:
    - Source calls (input points)
    - Sink calls (dangerous functions)
    - Data propagation through the function
    """
    try:
        addr = int(func_addr, 16) if func_addr.startswith("0x") else int(func_addr)
    except:
        return {"error": f"Invalid address: {func_addr}"}
    
    func = idaapi.get_func(addr)
    if not func:
        return {"error": "No function at address"}
    
    func_name = ida_funcs.get_func_name(func.start_ea)
    
    callees = _get_function_callees(func.start_ea)
    
    sources_in_func = []
    sinks_in_func = []
    propagators_in_func = []
    
    for callee_addr, callee_name in callees:
        clean_name = callee_name.lstrip("_").lower()
        
        for cat, funcs in SOURCE_FUNCTIONS.items():
            if any(clean_name == f.lower() for f in funcs):
                sources_in_func.append({
                    "name": callee_name,
                    "addr": hex(callee_addr),
                    "category": cat,
                })
        
        for cat, funcs in SINK_FUNCTIONS.items():
            if any(clean_name == f.lower() for f in funcs):
                sinks_in_func.append({
                    "name": callee_name,
                    "addr": hex(callee_addr),
                    "category": cat,
                })
        
        if any(clean_name == p.lower() for p in STRING_PROPAGATORS):
            propagators_in_func.append({
                "name": callee_name,
                "addr": hex(callee_addr),
            })
    
    pseudocode = None
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc:
            sv = cfunc.get_pseudocode()
            lines = []
            for sl in sv:
                lines.append(ida_lines.tag_remove(sl.line))
            pseudocode = "\n".join(lines)
    except:
        pass
    
    is_vulnerable = bool(sources_in_func and sinks_in_func)
    
    return {
        "func_name": func_name,
        "func_addr": hex(func.start_ea),
        "sources": sources_in_func,
        "sinks": sinks_in_func,
        "propagators": propagators_in_func,
        "is_vulnerable": is_vulnerable,
        "pseudocode": pseudocode,
    }

@tool
@idaread
def find_exploit_chains(
    sink_name: Annotated[str, "Name of the sink function to trace"],
    max_depth: Annotated[int, "Maximum call chain depth"] = 10,
) -> list[dict]:
    """Find exploit chains from sources to a specific sink function.
    
    Traces backwards from a sink to find all possible paths from source functions.
    """
    sink_addr = _find_function_address(sink_name)
    if sink_addr is None:
        return [{"error": f"Sink function '{sink_name}' not found"}]
    
    sink_category = "unknown"
    for cat, funcs in SINK_FUNCTIONS.items():
        if sink_name in funcs:
            sink_category = cat
            break
    
    chains = []
    
    callers = _get_callers_of_function(sink_addr)
    
    for caller in callers:
        caller_func_addr = caller.get("caller_func_addr")
        if not caller_func_addr:
            continue
        
        caller_addr_int = int(caller_func_addr, 16)
        
        visited = set()
        queue = deque()
        queue.append((caller_addr_int, [caller]))
        
        while queue:
            current_addr, path = queue.popleft()
            
            if current_addr in visited or len(path) > max_depth:
                continue
            visited.add(current_addr)
            
            callees = _get_function_callees(current_addr)
            for callee_addr, callee_name in callees:
                clean_name = callee_name.lstrip("_").lower()
                for source_cat, source_list in SOURCE_FUNCTIONS.items():
                    if any(clean_name == s.lower() for s in source_list):
                        chains.append({
                            "source_func": callee_name,
                            "source_category": source_cat,
                            "sink_func": sink_name,
                            "sink_category": sink_category,
                            "path": list(reversed(path)),
                            "path_length": len(path),
                            "entry_point": ida_funcs.get_func_name(current_addr),
                            "entry_addr": hex(current_addr),
                        })
            
            current_callers = _get_function_callers(current_addr)
            for c_addr, c_name in current_callers:
                if c_addr not in visited:
                    new_path = path + [{
                        "func_name": c_name,
                        "func_addr": hex(c_addr),
                    }]
                    queue.append((c_addr, new_path))
    
    chains.sort(key=lambda x: x["path_length"])
    
    return chains[:50]
