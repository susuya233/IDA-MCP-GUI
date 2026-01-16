"""Buffer Overflow Analysis API - Stack and Heap Overflow Detection"""

from typing import Annotated, Optional, TypedDict
from collections import defaultdict
import idaapi
import idautils
import idc
import ida_funcs
import ida_name
import ida_hexrays
import ida_lines
import ida_frame
import ida_struct
import ida_bytes
import re

from .rpc import tool
from .sync import idaread

# ============================================================================
# Buffer Operation Functions
# ============================================================================

# Functions that write to buffers with size parameter
SIZED_BUFFER_FUNCS = {
    # (func_name, dest_arg_idx, size_arg_idx)
    "strncpy": (0, 2),
    "strncat": (0, 2),
    "snprintf": (0, 1),
    "vsnprintf": (0, 1),
    "memcpy": (0, 2),
    "memmove": (0, 2),
    "memset": (0, 2),
    "fgets": (0, 1),
    "fread": (0, 1),  # simplified
    "read": (1, 2),
    "recv": (1, 2),
    "recvfrom": (1, 2),
}

# Functions that write to buffers without size limit
UNSIZED_BUFFER_FUNCS = [
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "scanf", "sscanf", "fscanf",
]

# Heap allocation functions
HEAP_ALLOC_FUNCS = {
    "malloc": 0,      # size is arg 0
    "calloc": (0, 1), # count, size
    "realloc": 1,     # size is arg 1
    "aligned_alloc": 1,
    "memalign": 1,
}

HEAP_FREE_FUNCS = ["free", "cfree"]


class BufferOverflowVuln(TypedDict):
    """Buffer overflow vulnerability information"""
    id: int
    vuln_type: str  # stack_overflow, heap_overflow, integer_overflow
    severity: str   # critical, high, medium, low
    function: str
    func_addr: str
    location: str   # call site address
    disasm: str
    description: str
    buffer_info: dict
    recommendation: str


class StackBufferInfo(TypedDict):
    """Stack buffer analysis information"""
    func_name: str
    func_addr: str
    stack_size: int
    local_vars: list[dict]
    dangerous_ops: list[dict]
    risk_score: int


class HeapBufferInfo(TypedDict):
    """Heap buffer analysis information"""
    func_name: str
    func_addr: str
    allocations: list[dict]
    frees: list[dict]
    use_after_free_risks: list[dict]
    double_free_risks: list[dict]


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


def _get_stack_frame_info(func_addr: int) -> dict:
    """Get stack frame information for a function"""
    func = idaapi.get_func(func_addr)
    if not func:
        return {}
    
    frame = ida_frame.get_frame(func)
    if not frame:
        return {"stack_size": func.frsize, "variables": []}
    
    variables = []
    for i in range(ida_struct.get_struc_size(frame)):
        member = ida_struct.get_member(frame, i)
        if member:
            name = ida_struct.get_member_name(member.id)
            size = ida_struct.get_member_size(member)
            offset = member.soff
            
            # Determine if it's a buffer (array)
            tinfo = idaapi.tinfo_t()
            if ida_struct.get_member_tinfo(tinfo, member):
                type_str = str(tinfo)
            else:
                type_str = "unknown"
            
            variables.append({
                "name": name or f"var_{offset:X}",
                "offset": offset,
                "size": size,
                "type": type_str,
                "is_array": "[" in type_str,
            })
    
    return {
        "stack_size": func.frsize,
        "variables": variables,
    }


def _analyze_buffer_operation(func_addr: int, call_addr: int, target_func: str) -> dict:
    """Analyze a buffer operation at a specific call site"""
    result = {
        "call_addr": hex(call_addr),
        "target_func": target_func,
        "risk": "unknown",
        "details": "",
    }
    
    try:
        cfunc = ida_hexrays.decompile(func_addr)
        if not cfunc:
            return result
        
        pseudocode = str(cfunc)
        
        # Look for the function call and analyze arguments
        # Pattern: target_func(dest, src, size) or target_func(dest, src)
        
        if target_func in UNSIZED_BUFFER_FUNCS:
            result["risk"] = "high"
            result["details"] = f"{target_func} 没有大小限制，可能导致缓冲区溢出"
        elif target_func in SIZED_BUFFER_FUNCS:
            # Check if size is properly bounded
            result["risk"] = "medium"
            result["details"] = f"{target_func} 有大小参数，需验证大小是否正确"
        
        # Check for hardcoded sizes vs buffer sizes
        patterns = [
            (r'strcpy\s*\([^,]+,\s*[^)]+\)', "strcpy without size check"),
            (r'sprintf\s*\([^,]+,\s*[^)]+\)', "sprintf without size limit"),
            (r'gets\s*\([^)]+\)', "gets is always dangerous"),
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, pseudocode, re.IGNORECASE):
                if target_func.lower() in pattern.lower():
                    result["risk"] = "critical"
                    result["details"] = desc
        
    except Exception as e:
        result["details"] = f"分析失败: {e}"
    
    return result


def _check_integer_overflow_risk(func_addr: int) -> list[dict]:
    """Check for integer overflow risks that could lead to buffer overflow"""
    risks = []
    
    try:
        cfunc = ida_hexrays.decompile(func_addr)
        if not cfunc:
            return risks
        
        pseudocode = str(cfunc)
        
        # Patterns that may indicate integer overflow leading to buffer issues
        patterns = [
            (r'malloc\s*\([^)]*\*[^)]*\)', "乘法可能导致整数溢出"),
            (r'calloc\s*\([^)]*\+[^)]*\)', "加法可能导致整数溢出"),
            (r'realloc\s*\([^,]+,\s*[^)]*\*[^)]*\)', "realloc大小计算可能溢出"),
            (r'\(.*\)\s*\*\s*sizeof', "大小计算可能整数溢出"),
        ]
        
        for pattern, desc in patterns:
            matches = re.finditer(pattern, pseudocode)
            for match in matches:
                risks.append({
                    "pattern": match.group(),
                    "risk": "high",
                    "description": desc,
                })
        
    except:
        pass
    
    return risks


# ============================================================================
# API Functions
# ============================================================================


@tool
@idaread
def scan_buffer_overflows(
    include_stack: Annotated[bool, "Include stack buffer overflow analysis"] = True,
    include_heap: Annotated[bool, "Include heap buffer overflow analysis"] = True,
    include_integer: Annotated[bool, "Include integer overflow analysis"] = True,
) -> list[BufferOverflowVuln]:
    """Scan for potential buffer overflow vulnerabilities.
    
    Detects:
    - Stack buffer overflows (strcpy, sprintf, etc. to stack buffers)
    - Heap buffer overflows (improper size handling with malloc)
    - Integer overflows that could lead to buffer overflows
    """
    vulnerabilities = []
    vuln_id = 0
    
    # Scan for unsafe buffer operations
    if include_stack:
        # Find calls to dangerous buffer functions
        for func_name in UNSIZED_BUFFER_FUNCS:
            func_addr = _find_function_address(func_name)
            if func_addr is None:
                continue
            
            for xref in idautils.XrefsTo(func_addr, 0):
                if not xref.iscode:
                    continue
                
                caller_addr = xref.frm
                caller_func = idaapi.get_func(caller_addr)
                if not caller_func:
                    continue
                
                vuln_id += 1
                caller_name = ida_funcs.get_func_name(caller_func.start_ea)
                disasm = idc.generate_disasm_line(caller_addr, 0)
                disasm = ida_lines.tag_remove(disasm) if disasm else ""
                
                # Analyze the operation
                analysis = _analyze_buffer_operation(caller_func.start_ea, caller_addr, func_name)
                
                severity = "high" if func_name in ["gets", "strcpy", "sprintf"] else "medium"
                
                vulnerabilities.append(BufferOverflowVuln(
                    id=vuln_id,
                    vuln_type="stack_overflow",
                    severity=severity,
                    function=caller_name,
                    func_addr=hex(caller_func.start_ea),
                    location=hex(caller_addr),
                    disasm=disasm,
                    description=f"调用 {func_name} 可能导致栈缓冲区溢出",
                    buffer_info=analysis,
                    recommendation=f"使用 {func_name}n 或限制大小的版本",
                ))
    
    if include_heap:
        # Find heap allocation and check for size issues
        for alloc_func, size_arg in HEAP_ALLOC_FUNCS.items():
            func_addr = _find_function_address(alloc_func)
            if func_addr is None:
                continue
            
            for xref in idautils.XrefsTo(func_addr, 0):
                if not xref.iscode:
                    continue
                
                caller_addr = xref.frm
                caller_func = idaapi.get_func(caller_addr)
                if not caller_func:
                    continue
                
                # Check for integer overflow risks in this function
                int_risks = _check_integer_overflow_risk(caller_func.start_ea)
                
                if int_risks:
                    vuln_id += 1
                    caller_name = ida_funcs.get_func_name(caller_func.start_ea)
                    disasm = idc.generate_disasm_line(caller_addr, 0)
                    disasm = ida_lines.tag_remove(disasm) if disasm else ""
                    
                    vulnerabilities.append(BufferOverflowVuln(
                        id=vuln_id,
                        vuln_type="heap_overflow",
                        severity="high",
                        function=caller_name,
                        func_addr=hex(caller_func.start_ea),
                        location=hex(caller_addr),
                        disasm=disasm,
                        description=f"{alloc_func} 大小参数可能存在整数溢出风险",
                        buffer_info={"integer_risks": int_risks},
                        recommendation="验证大小参数不会溢出",
                    ))
    
    if include_integer:
        # Scan all functions for integer overflow patterns
        for func_ea in idautils.Functions():
            risks = _check_integer_overflow_risk(func_ea)
            for risk in risks:
                vuln_id += 1
                func_name = ida_funcs.get_func_name(func_ea)
                
                vulnerabilities.append(BufferOverflowVuln(
                    id=vuln_id,
                    vuln_type="integer_overflow",
                    severity="medium",
                    function=func_name,
                    func_addr=hex(func_ea),
                    location=hex(func_ea),
                    disasm=risk.get("pattern", ""),
                    description=risk.get("description", "潜在整数溢出"),
                    buffer_info=risk,
                    recommendation="使用安全的整数运算或检查溢出",
                ))
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"], 4))
    
    return vulnerabilities


@tool
@idaread
def analyze_stack_buffer(
    func_addr: Annotated[str, "Function address to analyze"],
) -> StackBufferInfo:
    """Analyze stack buffer usage in a specific function.
    
    Identifies:
    - Stack buffer sizes
    - Operations on stack buffers
    - Potential overflow points
    """
    try:
        addr = int(func_addr, 16) if func_addr.startswith("0x") else int(func_addr)
    except:
        return {"error": f"Invalid address: {func_addr}"}
    
    func = idaapi.get_func(addr)
    if not func:
        return {"error": "No function at address"}
    
    func_name = ida_funcs.get_func_name(func.start_ea)
    frame_info = _get_stack_frame_info(func.start_ea)
    
    # Find dangerous operations
    dangerous_ops = []
    for ea in idautils.FuncItems(func.start_ea):
        for xref in idautils.CodeRefsFrom(ea, 0):
            callee_name = ida_name.get_name(xref)
            if callee_name:
                clean_name = callee_name.lstrip("_")
                if clean_name in UNSIZED_BUFFER_FUNCS or clean_name in SIZED_BUFFER_FUNCS:
                    disasm = idc.generate_disasm_line(ea, 0)
                    dangerous_ops.append({
                        "addr": hex(ea),
                        "func": clean_name,
                        "disasm": ida_lines.tag_remove(disasm) if disasm else "",
                        "has_size_limit": clean_name in SIZED_BUFFER_FUNCS,
                    })
    
    # Calculate risk score
    risk_score = 0
    for op in dangerous_ops:
        if not op["has_size_limit"]:
            risk_score += 10
        else:
            risk_score += 3
    
    return StackBufferInfo(
        func_name=func_name,
        func_addr=hex(func.start_ea),
        stack_size=frame_info.get("stack_size", 0),
        local_vars=frame_info.get("variables", []),
        dangerous_ops=dangerous_ops,
        risk_score=min(risk_score, 100),
    )


@tool
@idaread
def analyze_heap_usage(
    func_addr: Annotated[str, "Function address to analyze"],
) -> HeapBufferInfo:
    """Analyze heap buffer usage in a specific function.
    
    Identifies:
    - Heap allocations (malloc, calloc, etc.)
    - Heap frees
    - Use-after-free risks
    - Double-free risks
    """
    try:
        addr = int(func_addr, 16) if func_addr.startswith("0x") else int(func_addr)
    except:
        return {"error": f"Invalid address: {func_addr}"}
    
    func = idaapi.get_func(addr)
    if not func:
        return {"error": "No function at address"}
    
    func_name = ida_funcs.get_func_name(func.start_ea)
    
    allocations = []
    frees = []
    
    # Find all heap operations in this function
    for ea in idautils.FuncItems(func.start_ea):
        for xref in idautils.CodeRefsFrom(ea, 0):
            callee_name = ida_name.get_name(xref)
            if callee_name:
                clean_name = callee_name.lstrip("_")
                disasm = idc.generate_disasm_line(ea, 0)
                disasm = ida_lines.tag_remove(disasm) if disasm else ""
                
                if clean_name in HEAP_ALLOC_FUNCS:
                    allocations.append({
                        "addr": hex(ea),
                        "func": clean_name,
                        "disasm": disasm,
                    })
                elif clean_name in HEAP_FREE_FUNCS:
                    frees.append({
                        "addr": hex(ea),
                        "func": clean_name,
                        "disasm": disasm,
                    })
    
    # Analyze for UAF and double-free (simplified heuristics)
    uaf_risks = []
    double_free_risks = []
    
    # Simple heuristic: if we see multiple frees, there might be double-free
    if len(frees) > 1:
        double_free_risks.append({
            "description": f"函数中有 {len(frees)} 次 free 调用，可能存在 double-free 风险",
            "frees": frees,
        })
    
    # If alloc count < free count, suspicious
    if len(allocations) < len(frees):
        uaf_risks.append({
            "description": f"free 调用 ({len(frees)}) 多于 alloc 调用 ({len(allocations)})，可能存在问题",
        })
    
    return HeapBufferInfo(
        func_name=func_name,
        func_addr=hex(func.start_ea),
        allocations=allocations,
        frees=frees,
        use_after_free_risks=uaf_risks,
        double_free_risks=double_free_risks,
    )


@tool
@idaread
def get_buffer_operation_functions() -> dict:
    """Get all tracked buffer operation functions by category"""
    return {
        "unsized_buffer_funcs": UNSIZED_BUFFER_FUNCS,
        "sized_buffer_funcs": list(SIZED_BUFFER_FUNCS.keys()),
        "heap_alloc_funcs": list(HEAP_ALLOC_FUNCS.keys()),
        "heap_free_funcs": HEAP_FREE_FUNCS,
    }

