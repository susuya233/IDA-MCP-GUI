"""LLM-Assisted Semantic Analysis API

This module provides data structures and utilities for AI-assisted code analysis.
It exposes rich context to LLMs for deeper semantic understanding of binary code.
"""

from typing import Annotated, Optional, TypedDict
from collections import defaultdict
import idaapi
import idautils
import idc
import ida_funcs
import ida_name
import ida_hexrays
import ida_lines
import ida_segment
import ida_nalt
import json

from .rpc import tool
from .sync import idaread

# ============================================================================
# Context Extraction for LLM Analysis
# ============================================================================


class FunctionContext(TypedDict):
    """Complete context for a function for LLM analysis"""
    name: str
    addr: str
    size: int
    pseudocode: str
    disassembly: str
    callers: list[dict]
    callees: list[dict]
    strings_used: list[str]
    imports_used: list[str]
    local_variables: list[dict]
    function_signature: str
    xrefs_to: int
    xrefs_from: int
    characteristics: dict


class VulnerabilityContext(TypedDict):
    """Context for vulnerability analysis"""
    function_context: FunctionContext
    dangerous_patterns: list[dict]
    data_flow: list[dict]
    similar_vulnerabilities: list[dict]
    static_analysis_results: dict
    llm_prompt: str


class SemanticAnalysisResult(TypedDict):
    """Result of semantic analysis"""
    function_name: str
    function_purpose: str
    security_assessment: dict
    code_quality: dict
    suggestions: list[str]
    confidence: str


# ============================================================================
# Helper Functions
# ============================================================================


def _get_function_strings(func_addr: int) -> list[str]:
    """Get all strings referenced by a function"""
    strings = []
    func = idaapi.get_func(func_addr)
    if not func:
        return strings
    
    for ea in idautils.FuncItems(func.start_ea):
        for xref in idautils.DataRefsFrom(ea):
            str_type = idc.get_str_type(xref)
            if str_type is not None:
                s = idc.get_strlit_contents(xref)
                if s:
                    try:
                        strings.append(s.decode('utf-8', errors='replace'))
                    except:
                        strings.append(str(s))
    
    return list(set(strings))


def _get_function_imports(func_addr: int) -> list[str]:
    """Get all imported functions called by a function"""
    imports = []
    func = idaapi.get_func(func_addr)
    if not func:
        return imports
    
    for ea in idautils.FuncItems(func.start_ea):
        for xref in idautils.CodeRefsFrom(ea, 0):
            name = ida_name.get_name(xref)
            if name:
                # Check if it's an import
                seg = ida_segment.getseg(xref)
                if seg and "extern" in ida_segment.get_segm_name(seg).lower():
                    imports.append(name)
    
    return list(set(imports))


def _analyze_code_patterns(pseudocode: str) -> list[dict]:
    """Analyze code for common vulnerability patterns"""
    import re
    
    patterns = []
    
    # Dangerous function patterns
    dangerous_funcs = [
        (r'\bstrcpy\s*\(', "buffer_overflow", "使用 strcpy 可能导致缓冲区溢出"),
        (r'\bsprintf\s*\(', "buffer_overflow", "使用 sprintf 可能导致缓冲区溢出"),
        (r'\bgets\s*\(', "buffer_overflow", "gets 函数已废弃，存在缓冲区溢出风险"),
        (r'\bsystem\s*\(', "command_injection", "使用 system 函数可能存在命令注入风险"),
        (r'\bpopen\s*\(', "command_injection", "使用 popen 函数可能存在命令注入风险"),
        (r'\bexec[lvpe]*\s*\(', "command_injection", "使用 exec 系列函数需注意命令注入"),
        (r'\bfopen\s*\([^,]+,\s*"w', "file_operation", "文件写入操作，检查路径是否可控"),
        (r'\bunlink\s*\(', "file_operation", "文件删除操作，检查路径是否可控"),
        (r'\bprintf\s*\([^,\)]+\)', "format_string", "printf 第一个参数不是常量，可能存在格式化字符串漏洞"),
    ]
    
    for pattern, vuln_type, desc in dangerous_funcs:
        matches = re.finditer(pattern, pseudocode, re.IGNORECASE)
        for match in matches:
            patterns.append({
                "type": vuln_type,
                "pattern": match.group(),
                "description": desc,
                "position": match.start(),
            })
    
    # Logic patterns
    logic_patterns = [
        (r'if\s*\([^)]*==\s*0\s*\)[^{]*return', "error_handling", "返回值检查模式"),
        (r'while\s*\(\s*1\s*\)', "infinite_loop", "无限循环"),
        (r'for\s*\([^;]*;\s*;\s*[^)]*\)', "infinite_loop", "可能的无限循环"),
        (r'malloc\s*\([^)]+\)\s*;[^}]*(?!if|while)', "missing_null_check", "malloc 后可能缺少 NULL 检查"),
    ]
    
    for pattern, pattern_type, desc in logic_patterns:
        if re.search(pattern, pseudocode, re.IGNORECASE | re.DOTALL):
            patterns.append({
                "type": pattern_type,
                "description": desc,
            })
    
    return patterns


def _generate_analysis_prompt(context: FunctionContext, analysis_type: str = "security") -> str:
    """Generate a prompt for LLM analysis"""
    
    if analysis_type == "security":
        prompt = f"""请分析以下二进制代码的安全性：

函数名: {context['name']}
地址: {context['addr']}

反编译代码:
```c
{context['pseudocode'][:3000]}
```

调用的函数:
{', '.join([c['name'] for c in context['callees'][:20]])}

使用的字符串:
{json.dumps(context['strings_used'][:10], ensure_ascii=False)}

请分析:
1. 这个函数的主要功能是什么？
2. 是否存在安全漏洞？如果有，是什么类型的漏洞？
3. 漏洞的利用条件是什么？
4. 如何修复这些漏洞？
5. 代码质量如何？有什么改进建议？

请以 JSON 格式回复。
"""
    elif analysis_type == "reverse":
        prompt = f"""请帮助理解以下二进制代码：

函数名: {context['name']}
地址: {context['addr']}

反编译代码:
```c
{context['pseudocode'][:3000]}
```

使用的字符串:
{json.dumps(context['strings_used'][:10], ensure_ascii=False)}

请分析:
1. 这个函数的功能是什么？
2. 参数的含义是什么？
3. 返回值的含义是什么？
4. 建议的函数名和变量名是什么？
5. 这个函数可能属于哪个功能模块？
"""
    elif analysis_type == "vulnerability":
        prompt = f"""请深入分析以下代码中的潜在漏洞：

函数名: {context['name']}
地址: {context['addr']}

反编译代码:
```c
{context['pseudocode'][:3000]}
```

静态分析发现的模式:
{json.dumps(context.get('characteristics', {}).get('patterns', []), ensure_ascii=False, indent=2)}

请提供:
1. 漏洞类型分类
2. 漏洞根本原因
3. 攻击向量和利用方法
4. 影响范围评估
5. 修复建议
"""
    else:
        prompt = f"请分析函数 {context['name']} 的代码。\n\n```c\n{context['pseudocode'][:2000]}\n```"
    
    return prompt


# ============================================================================
# API Functions
# ============================================================================


@tool
@idaread
def get_function_context(
    func_addr: Annotated[str, "Function address to analyze"],
    include_disasm: Annotated[bool, "Include disassembly"] = False,
    max_pseudocode_lines: Annotated[int, "Maximum pseudocode lines"] = 200,
) -> FunctionContext:
    """Get complete context for a function suitable for LLM analysis.
    
    Extracts:
    - Pseudocode
    - Callers and callees
    - Strings and imports
    - Local variables
    - Function characteristics
    """
    try:
        addr = int(func_addr, 16) if func_addr.startswith("0x") else int(func_addr)
    except:
        return {"error": f"Invalid address: {func_addr}"}
    
    func = idaapi.get_func(addr)
    if not func:
        return {"error": "No function at address"}
    
    func_name = ida_funcs.get_func_name(func.start_ea)
    
    # Get pseudocode
    pseudocode = ""
    local_vars = []
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc:
            sv = cfunc.get_pseudocode()
            lines = []
            for i, sl in enumerate(sv):
                if i >= max_pseudocode_lines:
                    lines.append("// ... (truncated)")
                    break
                lines.append(ida_lines.tag_remove(sl.line))
            pseudocode = "\n".join(lines)
            
            # Get local variables
            lvars = cfunc.get_lvars()
            for lvar in lvars:
                local_vars.append({
                    "name": lvar.name,
                    "type": str(lvar.type()),
                    "is_arg": lvar.is_arg_var,
                })
    except:
        pass
    
    # Get disassembly if requested
    disasm = ""
    if include_disasm:
        disasm_lines = []
        for ea in idautils.FuncItems(func.start_ea):
            line = idc.generate_disasm_line(ea, 0)
            if line:
                disasm_lines.append(f"{hex(ea)}: {ida_lines.tag_remove(line)}")
            if len(disasm_lines) > 500:
                disasm_lines.append("... (truncated)")
                break
        disasm = "\n".join(disasm_lines)
    
    # Get callers
    callers = []
    for xref in idautils.XrefsTo(func.start_ea, 0):
        if xref.iscode:
            caller_func = idaapi.get_func(xref.frm)
            if caller_func:
                callers.append({
                    "name": ida_funcs.get_func_name(caller_func.start_ea),
                    "addr": hex(caller_func.start_ea),
                    "call_site": hex(xref.frm),
                })
    
    # Get callees
    callees = []
    seen_callees = set()
    for ea in idautils.FuncItems(func.start_ea):
        for xref in idautils.CodeRefsFrom(ea, 0):
            callee_func = idaapi.get_func(xref)
            if callee_func and callee_func.start_ea not in seen_callees:
                seen_callees.add(callee_func.start_ea)
                callees.append({
                    "name": ida_funcs.get_func_name(callee_func.start_ea),
                    "addr": hex(callee_func.start_ea),
                })
    
    # Get strings and imports
    strings = _get_function_strings(func.start_ea)
    imports = _get_function_imports(func.start_ea)
    
    # Analyze patterns
    patterns = _analyze_code_patterns(pseudocode) if pseudocode else []
    
    # Function signature
    func_type = idc.get_type(func.start_ea) or "unknown"
    
    return FunctionContext(
        name=func_name,
        addr=hex(func.start_ea),
        size=func.size(),
        pseudocode=pseudocode,
        disassembly=disasm,
        callers=callers,
        callees=callees,
        strings_used=strings,
        imports_used=imports,
        local_variables=local_vars,
        function_signature=func_type,
        xrefs_to=len(callers),
        xrefs_from=len(callees),
        characteristics={
            "has_loops": "while" in pseudocode or "for" in pseudocode,
            "has_conditions": "if" in pseudocode,
            "has_memory_ops": any(op in pseudocode for op in ["malloc", "free", "memcpy", "strcpy"]),
            "has_file_ops": any(op in pseudocode for op in ["fopen", "fread", "fwrite", "open"]),
            "has_network_ops": any(op in pseudocode for op in ["socket", "recv", "send", "connect"]),
            "patterns": patterns,
        },
    )


@tool
@idaread
def get_vulnerability_context(
    func_addr: Annotated[str, "Function address to analyze"],
) -> VulnerabilityContext:
    """Get detailed vulnerability analysis context for a function.
    
    Provides:
    - Full function context
    - Dangerous patterns detected
    - Data flow information
    - Analysis prompt for LLM
    """
    context = get_function_context(func_addr, include_disasm=False)
    
    if "error" in context:
        return {"error": context["error"]}
    
    # Analyze dangerous patterns
    patterns = context.get("characteristics", {}).get("patterns", [])
    
    # Generate LLM prompt
    prompt = _generate_analysis_prompt(context, "vulnerability")
    
    return VulnerabilityContext(
        function_context=context,
        dangerous_patterns=patterns,
        data_flow=[],  # Could be enhanced with more sophisticated analysis
        similar_vulnerabilities=[],
        static_analysis_results={
            "pattern_count": len(patterns),
            "risk_indicators": [p["type"] for p in patterns],
        },
        llm_prompt=prompt,
    )


@tool
@idaread
def generate_analysis_prompt(
    func_addr: Annotated[str, "Function address"],
    analysis_type: Annotated[str, "Type: security, reverse, vulnerability, general"] = "security",
) -> dict:
    """Generate an LLM analysis prompt for a function.
    
    Creates a structured prompt suitable for AI analysis.
    """
    context = get_function_context(func_addr)
    
    if "error" in context:
        return {"error": context["error"]}
    
    prompt = _generate_analysis_prompt(context, analysis_type)
    
    return {
        "function": context["name"],
        "addr": context["addr"],
        "analysis_type": analysis_type,
        "prompt": prompt,
        "context_summary": {
            "pseudocode_lines": len(context["pseudocode"].split("\n")),
            "callees": len(context["callees"]),
            "callers": len(context["callers"]),
            "strings": len(context["strings_used"]),
        },
    }


@tool
@idaread
def batch_analyze_functions(
    func_filter: Annotated[Optional[str], "Filter functions by name pattern"] = None,
    max_functions: Annotated[int, "Maximum functions to analyze"] = 20,
    focus_on: Annotated[str, "Focus: dangerous_calls, entry_points, large_functions"] = "dangerous_calls",
) -> list[dict]:
    """Batch analyze multiple functions for LLM review.
    
    Selects interesting functions based on criteria and prepares analysis data.
    """
    import re
    
    results = []
    
    # Get all functions
    all_funcs = list(idautils.Functions())
    
    # Filter based on focus
    interesting_funcs = []
    
    for func_ea in all_funcs:
        func_name = ida_funcs.get_func_name(func_ea)
        
        # Apply name filter if provided
        if func_filter and not re.search(func_filter, func_name, re.IGNORECASE):
            continue
        
        func = idaapi.get_func(func_ea)
        if not func:
            continue
        
        score = 0
        
        if focus_on == "dangerous_calls":
            # Check if function contains dangerous calls
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                if cfunc:
                    pseudocode = str(cfunc).lower()
                    dangerous_funcs = ["strcpy", "sprintf", "system", "popen", "gets", "scanf"]
                    score = sum(1 for d in dangerous_funcs if d in pseudocode)
            except:
                pass
        
        elif focus_on == "entry_points":
            # Functions with many callers from outside
            xref_count = sum(1 for _ in idautils.XrefsTo(func_ea, 0))
            score = xref_count
        
        elif focus_on == "large_functions":
            # Large functions might be complex and error-prone
            score = func.size()
        
        if score > 0:
            interesting_funcs.append((func_ea, func_name, score))
    
    # Sort by score and take top N
    interesting_funcs.sort(key=lambda x: x[2], reverse=True)
    interesting_funcs = interesting_funcs[:max_functions]
    
    # Get context for each
    for func_ea, func_name, score in interesting_funcs:
        context = get_function_context(hex(func_ea))
        if "error" not in context:
            results.append({
                "name": func_name,
                "addr": hex(func_ea),
                "score": score,
                "prompt": _generate_analysis_prompt(context, "security"),
                "summary": {
                    "size": context.get("size", 0),
                    "callees": len(context.get("callees", [])),
                    "patterns": len(context.get("characteristics", {}).get("patterns", [])),
                },
            })
    
    return results


@tool
@idaread
def get_binary_overview() -> dict:
    """Get an overview of the binary suitable for LLM context.
    
    Provides:
    - Binary metadata
    - Function statistics
    - Import/export information
    - Interesting patterns
    """
    # Get basic info
    info = idaapi.get_inf_structure()
    
    # Count functions
    func_count = sum(1 for _ in idautils.Functions())
    
    # Get segments
    segments = []
    seg = ida_segment.get_first_seg()
    while seg:
        segments.append({
            "name": ida_segment.get_segm_name(seg),
            "start": hex(seg.start_ea),
            "end": hex(seg.end_ea),
            "size": seg.size(),
        })
        seg = ida_segment.get_next_seg(seg.end_ea)
    
    # Get imports
    imports = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        import_list = []
        
        def callback(ea, name, ordinal):
            if name:
                import_list.append(name)
            return True
        
        ida_nalt.enum_import_names(i, callback)
        
        imports.append({
            "module": module_name,
            "count": len(import_list),
            "functions": import_list[:20],  # Limit
        })
    
    # Find interesting functions
    dangerous_func_names = ["system", "popen", "strcpy", "sprintf", "gets", "exec"]
    found_dangerous = []
    for func_ea in idautils.Functions():
        func_name = ida_funcs.get_func_name(func_ea)
        if any(d in func_name.lower() for d in dangerous_func_names):
            found_dangerous.append({
                "name": func_name,
                "addr": hex(func_ea),
            })
    
    return {
        "filename": idaapi.get_root_filename(),
        "processor": info.procname,
        "bits": 64 if info.is_64bit() else 32,
        "file_type": "PE" if info.filetype == idaapi.f_PE else "ELF" if info.filetype == idaapi.f_ELF else "other",
        "function_count": func_count,
        "segments": segments,
        "imports": imports,
        "dangerous_functions_found": found_dangerous,
        "analysis_suggestions": [
            f"发现 {len(found_dangerous)} 个可能危险的函数",
            f"共有 {func_count} 个函数需要分析",
            f"建议重点分析导入的危险函数的调用者",
        ],
    }


@tool
@idaread
def get_code_snippet(
    start_addr: Annotated[str, "Start address"],
    end_addr: Annotated[Optional[str], "End address (or None for single function)"] = None,
    output_type: Annotated[str, "Type: pseudocode, disassembly, both"] = "pseudocode",
) -> dict:
    """Get a code snippet for a specific address range.
    
    Useful for getting context around a specific location.
    """
    try:
        start = int(start_addr, 16) if start_addr.startswith("0x") else int(start_addr)
    except:
        return {"error": f"Invalid start address: {start_addr}"}
    
    if end_addr:
        try:
            end = int(end_addr, 16) if end_addr.startswith("0x") else int(end_addr)
        except:
            return {"error": f"Invalid end address: {end_addr}"}
    else:
        # Get function end
        func = idaapi.get_func(start)
        if func:
            end = func.end_ea
        else:
            end = start + 0x100  # Default range
    
    result = {
        "start": hex(start),
        "end": hex(end),
    }
    
    if output_type in ["pseudocode", "both"]:
        func = idaapi.get_func(start)
        if func:
            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                if cfunc:
                    sv = cfunc.get_pseudocode()
                    lines = []
                    for sl in sv:
                        lines.append(ida_lines.tag_remove(sl.line))
                    result["pseudocode"] = "\n".join(lines)
            except:
                result["pseudocode"] = "// Decompilation failed"
    
    if output_type in ["disassembly", "both"]:
        disasm_lines = []
        ea = start
        while ea < end:
            line = idc.generate_disasm_line(ea, 0)
            if line:
                disasm_lines.append(f"{hex(ea)}: {ida_lines.tag_remove(line)}")
            ea = idc.next_head(ea, end)
            if ea == idaapi.BADADDR:
                break
        result["disassembly"] = "\n".join(disasm_lines)
    
    return result

