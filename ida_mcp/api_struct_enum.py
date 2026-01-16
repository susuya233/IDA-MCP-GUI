"""Structure and Enum Auto-Detection and Suggestion API"""

from typing import Annotated, Optional, TypedDict
from collections import defaultdict
import idaapi
import idautils
import idc
import ida_funcs
import ida_name
import ida_hexrays
import ida_lines
import ida_struct
import ida_enum
import ida_bytes
import ida_typeinf
import re

from .rpc import tool
from .sync import idaread, idawrite

# ============================================================================
# Common Patterns
# ============================================================================

# Common struct field patterns
COMMON_STRUCT_PATTERNS = {
    # Network structures
    "sockaddr": {
        "fields": ["sa_family", "sa_data"],
        "signature": r"sin_family|sin_port|sin_addr|s_addr",
    },
    "sockaddr_in": {
        "fields": ["sin_family", "sin_port", "sin_addr"],
        "size": 16,
    },
    # File structures
    "stat": {
        "fields": ["st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size"],
        "signature": r"st_mode|st_size|st_mtime",
    },
    # CGI/HTTP structures
    "http_request": {
        "fields": ["method", "uri", "version", "headers", "body"],
        "signature": r"GET|POST|HEAD|Content-Length|Content-Type",
    },
}

# Common enum patterns
COMMON_ENUM_PATTERNS = {
    # Socket types
    "socket_type": {
        "values": {"SOCK_STREAM": 1, "SOCK_DGRAM": 2, "SOCK_RAW": 3},
        "context": ["socket("],
    },
    # Open flags
    "open_flags": {
        "values": {"O_RDONLY": 0, "O_WRONLY": 1, "O_RDWR": 2, "O_CREAT": 0x40, "O_TRUNC": 0x200},
        "context": ["open(", "fopen("],
    },
    # AF family
    "address_family": {
        "values": {"AF_UNIX": 1, "AF_INET": 2, "AF_INET6": 10},
        "context": ["socket(", "connect(", "bind("],
    },
    # Error codes
    "errno": {
        "values": {"EPERM": 1, "ENOENT": 2, "EIO": 5, "EACCES": 13, "EEXIST": 17},
        "context": ["errno", "perror"],
    },
}


class StructureSuggestion(TypedDict):
    """Suggested structure definition"""
    name: str
    addr: str
    func_name: str
    confidence: str  # high, medium, low
    reason: str
    suggested_fields: list[dict]
    c_definition: str
    apply_command: str


class EnumSuggestion(TypedDict):
    """Suggested enum definition"""
    name: str
    addr: str
    func_name: str
    confidence: str
    reason: str
    suggested_values: dict[str, int]
    c_definition: str
    context: str


class TypeFixSuggestion(TypedDict):
    """Suggested type fix for a variable or function"""
    location: str
    current_type: str
    suggested_type: str
    confidence: str
    reason: str
    fix_command: str


# ============================================================================
# Helper Functions
# ============================================================================


def _analyze_memory_access_pattern(func_addr: int) -> list[dict]:
    """Analyze memory access patterns to detect structure usage"""
    patterns = []
    
    try:
        cfunc = ida_hexrays.decompile(func_addr)
        if not cfunc:
            return patterns
        
        pseudocode = str(cfunc)
        
        # Look for structure-like access patterns: ptr->field, ptr[offset], *(ptr + offset)
        # Pattern: variable + offset or variable->something
        
        # Detect pointer arithmetic patterns
        offset_patterns = re.findall(
            r'(\w+)\s*\+\s*(\d+)',
            pseudocode
        )
        
        for var, offset in offset_patterns:
            offset_int = int(offset)
            patterns.append({
                "type": "offset_access",
                "variable": var,
                "offset": offset_int,
            })
        
        # Detect array-like access
        array_patterns = re.findall(
            r'(\w+)\s*\[\s*(\d+)\s*\]',
            pseudocode
        )
        
        for var, index in array_patterns:
            patterns.append({
                "type": "array_access",
                "variable": var,
                "index": int(index),
            })
        
        # Detect cast patterns (often indicate struct types)
        cast_patterns = re.findall(
            r'\(\s*(\w+)\s*\*?\s*\)\s*(\w+)',
            pseudocode
        )
        
        for type_name, var in cast_patterns:
            if type_name not in ["int", "char", "void", "unsigned", "signed"]:
                patterns.append({
                    "type": "cast",
                    "cast_type": type_name,
                    "variable": var,
                })
        
    except Exception as e:
        pass
    
    return patterns


def _detect_magic_numbers(func_addr: int) -> list[dict]:
    """Detect magic numbers that should be enums"""
    magic_numbers = []
    
    try:
        cfunc = ida_hexrays.decompile(func_addr)
        if not cfunc:
            return magic_numbers
        
        sv = cfunc.get_pseudocode()
        lines = []
        for sl in sv:
            lines.append(ida_lines.tag_remove(sl.line))
        pseudocode = "\n".join(lines)
        
        # Find numeric comparisons and assignments
        # Pattern: var == number, var = number, func(number)
        
        # Comparisons
        comparisons = re.findall(
            r'(\w+)\s*([=!<>]=?)\s*(\d+)',
            pseudocode
        )
        
        for var, op, num in comparisons:
            num_int = int(num)
            if num_int > 1 and num_int < 0x10000:  # Reasonable enum range
                magic_numbers.append({
                    "type": "comparison",
                    "variable": var,
                    "operator": op,
                    "value": num_int,
                    "context": f"{var} {op} {num}",
                })
        
        # Function arguments
        func_args = re.findall(
            r'(\w+)\s*\(\s*([^)]*\d+[^)]*)\)',
            pseudocode
        )
        
        for func_name, args in func_args:
            # Extract numbers from arguments
            arg_nums = re.findall(r'\b(\d+)\b', args)
            for num in arg_nums:
                num_int = int(num)
                if num_int > 1 and num_int != 10 and num_int < 0x10000:
                    magic_numbers.append({
                        "type": "function_arg",
                        "function": func_name,
                        "value": num_int,
                        "context": f"{func_name}(...{num}...)",
                    })
        
    except:
        pass
    
    return magic_numbers


def _match_known_enum(value: int, context: str) -> Optional[tuple[str, str]]:
    """Try to match a value to a known enum"""
    for enum_name, enum_info in COMMON_ENUM_PATTERNS.items():
        # Check if context matches
        if any(ctx in context for ctx in enum_info.get("context", [])):
            # Check if value matches
            for val_name, val in enum_info["values"].items():
                if val == value:
                    return enum_name, val_name
    return None


def _generate_struct_definition(name: str, fields: list[dict]) -> str:
    """Generate C structure definition"""
    lines = [f"struct {name} {{"]
    
    for field in fields:
        field_name = field.get("name", f"field_{field.get('offset', 0):x}")
        field_type = field.get("type", "int")
        field_size = field.get("size", 4)
        
        # Infer type from size
        if field_type == "int":
            if field_size == 1:
                field_type = "char"
            elif field_size == 2:
                field_type = "short"
            elif field_size == 8:
                field_type = "long long"
        
        lines.append(f"    {field_type} {field_name};")
    
    lines.append("};")
    return "\n".join(lines)


def _generate_enum_definition(name: str, values: dict[str, int]) -> str:
    """Generate C enum definition"""
    lines = [f"enum {name} {{"]
    
    for val_name, val in sorted(values.items(), key=lambda x: x[1]):
        lines.append(f"    {val_name} = {val},")
    
    lines.append("};")
    return "\n".join(lines)


# ============================================================================
# API Functions
# ============================================================================


@tool
@idaread
def suggest_structures(
    func_addr: Annotated[Optional[str], "Function address to analyze (None for all functions)"] = None,
    max_suggestions: Annotated[int, "Maximum suggestions to return"] = 20,
) -> list[StructureSuggestion]:
    """Analyze code to suggest structure definitions.
    
    Detects:
    - Pointer arithmetic patterns
    - Consistent field offsets
    - Cast patterns indicating structure types
    """
    suggestions = []
    
    if func_addr:
        try:
            addr = int(func_addr, 16) if func_addr.startswith("0x") else int(func_addr)
        except:
            return [{"error": f"Invalid address: {func_addr}"}]
        
        func_addrs = [addr]
    else:
        # Analyze all functions (limited)
        func_addrs = list(idautils.Functions())[:100]
    
    # Track detected patterns across functions
    struct_patterns = defaultdict(lambda: defaultdict(list))
    
    for faddr in func_addrs:
        func = idaapi.get_func(faddr)
        if not func:
            continue
        
        func_name = ida_funcs.get_func_name(func.start_ea)
        patterns = _analyze_memory_access_pattern(func.start_ea)
        
        for pattern in patterns:
            if pattern["type"] == "offset_access":
                var = pattern["variable"]
                offset = pattern["offset"]
                struct_patterns[var][offset].append({
                    "func": func_name,
                    "func_addr": hex(func.start_ea),
                })
            elif pattern["type"] == "cast":
                cast_type = pattern["cast_type"]
                # Suggest defining this structure
                suggestions.append(StructureSuggestion(
                    name=cast_type,
                    addr=hex(func.start_ea),
                    func_name=func_name,
                    confidence="medium",
                    reason=f"发现类型转换为 {cast_type}*，可能需要定义该结构",
                    suggested_fields=[],
                    c_definition=f"struct {cast_type} {{\n    // TODO: Add fields\n}};",
                    apply_command=f"idc.parse_decl('struct {cast_type} {{}};', idc.PT_TYP)",
                ))
    
    # Analyze collected patterns to suggest structures
    for var, offsets in struct_patterns.items():
        if len(offsets) >= 2:  # At least 2 different offsets
            # Build field list
            fields = []
            sorted_offsets = sorted(offsets.keys())
            
            for i, offset in enumerate(sorted_offsets):
                # Estimate field size
                if i + 1 < len(sorted_offsets):
                    size = sorted_offsets[i + 1] - offset
                else:
                    size = 4  # Default
                
                fields.append({
                    "name": f"field_{offset:x}",
                    "offset": offset,
                    "size": min(size, 8),
                    "type": "int",
                })
            
            # Get example function
            example_func = list(offsets.values())[0][0]
            
            suggestions.append(StructureSuggestion(
                name=f"struct_{var}",
                addr=example_func["func_addr"],
                func_name=example_func["func"],
                confidence="high" if len(offsets) >= 4 else "medium",
                reason=f"变量 {var} 有 {len(offsets)} 个不同的偏移访问，可能是结构体",
                suggested_fields=fields,
                c_definition=_generate_struct_definition(f"struct_{var}", fields),
                apply_command=f"# Use: Edit -> Structs -> Create struct",
            ))
    
    # Sort by confidence
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    suggestions.sort(key=lambda x: confidence_order.get(x.get("confidence", "low"), 3))
    
    return suggestions[:max_suggestions]


@tool
@idaread
def suggest_enums(
    func_addr: Annotated[Optional[str], "Function address to analyze (None for all)"] = None,
    max_suggestions: Annotated[int, "Maximum suggestions to return"] = 20,
) -> list[EnumSuggestion]:
    """Analyze code to suggest enum definitions.
    
    Detects:
    - Magic numbers in comparisons
    - Repeated numeric constants
    - Values matching known patterns (socket types, flags, etc.)
    """
    suggestions = []
    seen_values = defaultdict(list)  # value -> list of contexts
    
    if func_addr:
        try:
            addr = int(func_addr, 16) if func_addr.startswith("0x") else int(func_addr)
        except:
            return [{"error": f"Invalid address: {func_addr}"}]
        
        func_addrs = [addr]
    else:
        func_addrs = list(idautils.Functions())[:100]
    
    for faddr in func_addrs:
        func = idaapi.get_func(faddr)
        if not func:
            continue
        
        func_name = ida_funcs.get_func_name(func.start_ea)
        magic_numbers = _detect_magic_numbers(func.start_ea)
        
        for magic in magic_numbers:
            value = magic["value"]
            context = magic.get("context", "")
            
            # Try to match known enums
            match = _match_known_enum(value, context)
            
            if match:
                enum_name, val_name = match
                enum_values = COMMON_ENUM_PATTERNS[enum_name]["values"]
                
                suggestions.append(EnumSuggestion(
                    name=enum_name,
                    addr=hex(func.start_ea),
                    func_name=func_name,
                    confidence="high",
                    reason=f"值 {value} 匹配已知枚举 {enum_name}::{val_name}",
                    suggested_values=enum_values,
                    c_definition=_generate_enum_definition(enum_name, enum_values),
                    context=context,
                ))
            else:
                # Track for pattern detection
                seen_values[value].append({
                    "func": func_name,
                    "func_addr": hex(func.start_ea),
                    "context": context,
                    "type": magic["type"],
                })
    
    # Suggest enums for frequently used values
    for value, occurrences in seen_values.items():
        if len(occurrences) >= 2:
            # Group by context function (e.g., socket, open)
            funcs_used = set()
            for occ in occurrences:
                if occ["type"] == "function_arg":
                    if "function" in occurrences[0]:
                        funcs_used.add(occ.get("context", "").split("(")[0])
            
            suggestions.append(EnumSuggestion(
                name=f"enum_value_{value}",
                addr=occurrences[0]["func_addr"],
                func_name=occurrences[0]["func"],
                confidence="low",
                reason=f"值 {value} (0x{value:x}) 在 {len(occurrences)} 个地方使用，可能是枚举值",
                suggested_values={f"VALUE_{value}": value},
                c_definition=f"enum enum_value_{value} {{\n    VALUE_{value} = {value},\n}};",
                context=occurrences[0].get("context", ""),
            ))
    
    # Remove duplicates and sort
    seen_enums = set()
    unique_suggestions = []
    for s in suggestions:
        key = (s["name"], s["func_name"])
        if key not in seen_enums:
            seen_enums.add(key)
            unique_suggestions.append(s)
    
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    unique_suggestions.sort(key=lambda x: confidence_order.get(x.get("confidence", "low"), 3))
    
    return unique_suggestions[:max_suggestions]


@tool
@idaread
def suggest_type_fixes(
    func_addr: Annotated[str, "Function address to analyze"],
) -> list[TypeFixSuggestion]:
    """Analyze a function to suggest type fixes.
    
    Detects:
    - Incorrect pointer types
    - Missing structure types
    - Wrong integer sizes
    """
    suggestions = []
    
    try:
        addr = int(func_addr, 16) if func_addr.startswith("0x") else int(func_addr)
    except:
        return [{"error": f"Invalid address: {func_addr}"}]
    
    func = idaapi.get_func(addr)
    if not func:
        return [{"error": "No function at address"}]
    
    func_name = ida_funcs.get_func_name(func.start_ea)
    
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            return suggestions
        
        sv = cfunc.get_pseudocode()
        lines = []
        for sl in sv:
            lines.append(ida_lines.tag_remove(sl.line))
        pseudocode = "\n".join(lines)
        
        # Detect common type issues
        
        # 1. void* that should be typed
        void_ptr_pattern = re.findall(
            r'void\s*\*\s*(\w+)',
            pseudocode
        )
        for var in void_ptr_pattern:
            suggestions.append(TypeFixSuggestion(
                location=hex(func.start_ea),
                current_type="void*",
                suggested_type="<specific type>*",
                confidence="low",
                reason=f"变量 {var} 是 void*，可能需要更具体的类型",
                fix_command=f"# 在反编译视图中右键点击 {var}，选择 'Set lvar type'",
            ))
        
        # 2. Integer that might be pointer
        int_as_ptr_pattern = re.findall(
            r'(\w+)\s*=\s*\([^)]+\*\)',
            pseudocode
        )
        for var in int_as_ptr_pattern:
            suggestions.append(TypeFixSuggestion(
                location=hex(func.start_ea),
                current_type="int",
                suggested_type="void*",
                confidence="medium",
                reason=f"变量 {var} 被转换为指针类型，可能本身就应该是指针",
                fix_command=f"# 在反编译视图中右键点击 {var}，选择 'Set lvar type'",
            ))
        
        # 3. Detect array that might be structure
        array_struct_pattern = re.findall(
            r'(\w+)\s*\[\s*\d+\s*\]\s*\+\s*(\d+)',
            pseudocode
        )
        for var, offset in array_struct_pattern:
            suggestions.append(TypeFixSuggestion(
                location=hex(func.start_ea),
                current_type="array",
                suggested_type="struct*",
                confidence="medium",
                reason=f"数组 {var} 使用偏移 +{offset} 访问，可能是结构体数组",
                fix_command=f"# 定义结构体，然后将 {var} 类型改为 struct_type*",
            ))
        
        # 4. Function calls with wrong argument types
        # Look for casts in function arguments
        cast_in_call = re.findall(
            r'(\w+)\s*\(\s*\([^)]+\)\s*(\w+)',
            pseudocode
        )
        for func_called, casted_var in cast_in_call:
            suggestions.append(TypeFixSuggestion(
                location=hex(func.start_ea),
                current_type="<需检查>",
                suggested_type="<参数所需类型>",
                confidence="low",
                reason=f"调用 {func_called} 时对 {casted_var} 进行了类型转换，可能变量类型不正确",
                fix_command=f"# 检查 {func_called} 的参数类型，修正 {casted_var} 的类型",
            ))
        
    except Exception as e:
        suggestions.append({"error": str(e)})
    
    return suggestions


@tool
@idaread
def get_existing_structures() -> list[dict]:
    """Get all currently defined structures in the IDB"""
    structures = []
    
    idx = ida_struct.get_first_struc_idx()
    while idx != idaapi.BADADDR:
        sid = ida_struct.get_struc_by_idx(idx)
        if sid != idaapi.BADADDR:
            sptr = ida_struct.get_struc(sid)
            if sptr:
                name = ida_struct.get_struc_name(sid)
                size = ida_struct.get_struc_size(sptr)
                
                # Get fields
                fields = []
                for i in range(ida_struct.get_struc_size(sptr)):
                    member = ida_struct.get_member(sptr, i)
                    if member:
                        mname = ida_struct.get_member_name(member.id)
                        msize = ida_struct.get_member_size(member)
                        moff = member.soff
                        fields.append({
                            "name": mname,
                            "offset": moff,
                            "size": msize,
                        })
                
                structures.append({
                    "name": name,
                    "size": size,
                    "field_count": len(fields),
                    "fields": fields,
                })
        
        idx = ida_struct.get_next_struc_idx(idx)
    
    return structures


@tool
@idaread
def get_existing_enums() -> list[dict]:
    """Get all currently defined enums in the IDB"""
    enums = []
    
    qty = ida_enum.get_enum_qty()
    for i in range(qty):
        eid = ida_enum.getn_enum(i)
        if eid != idaapi.BADADDR:
            name = ida_enum.get_enum_name(eid)
            size = ida_enum.get_enum_size(eid)
            
            # Get members
            members = {}
            member_id = ida_enum.get_first_enum_member(eid)
            while member_id != idaapi.BADADDR:
                mname = ida_enum.get_enum_member_name(member_id)
                mval = ida_enum.get_enum_member_value(member_id)
                if mname:
                    members[mname] = mval
                
                member_id = ida_enum.get_next_enum_member(eid, mval)
                if member_id == idaapi.BADADDR:
                    break
            
            enums.append({
                "name": name,
                "member_count": len(members),
                "members": members,
            })
    
    return enums


@tool
@idawrite
def apply_enum_suggestion(
    enum_name: Annotated[str, "Name for the enum"],
    values: Annotated[dict, "Dictionary of name -> value pairs"],
) -> dict:
    """Apply an enum suggestion by creating the enum in IDA"""
    try:
        # Check if enum already exists
        eid = ida_enum.get_enum(enum_name)
        if eid != idaapi.BADADDR:
            return {"error": f"Enum {enum_name} already exists"}
        
        # Create enum
        eid = ida_enum.add_enum(idaapi.BADADDR, enum_name, 0)
        if eid == idaapi.BADADDR:
            return {"error": f"Failed to create enum {enum_name}"}
        
        # Add members
        added = []
        for name, value in values.items():
            result = ida_enum.add_enum_member(eid, name, value)
            if result == 0:
                added.append(name)
        
        return {
            "success": True,
            "enum_name": enum_name,
            "members_added": added,
        }
    except Exception as e:
        return {"error": str(e)}

