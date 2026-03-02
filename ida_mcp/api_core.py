"""Core API Functions - IDB metadata and basic queries"""

from typing import Annotated, Optional

import ida_hexrays
import idaapi
import idautils
import ida_nalt
import ida_typeinf
import ida_segment

from .rpc import tool, test
from .sync import idaread
from .utils import (
    Metadata,
    Function,
    ConvertedNumber,
    Global,
    Import,
    String,
    Segment,
    Page,
    NumberConversion,
    ListQuery,
    get_image_size,
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    looks_like_address,
    get_function,
    create_demangled_to_ea_map,
    paginate,
    pattern_filter,
    DEMANGLED_TO_EA,
)
from .sync import IDAError


# ============================================================================
# String Cache
# ============================================================================

# Cache for idautils.Strings() to avoid rebuilding on every call
_strings_cache: Optional[list[String]] = None
_strings_cache_md5: Optional[str] = None
_STRINGS_CACHE_CAP = 15000


def _get_cached_strings() -> list[String]:
    """Get cached strings, rebuilding if IDB changed (capped to avoid freeze)."""
    global _strings_cache, _strings_cache_md5

    current_md5 = ida_nalt.retrieve_input_file_md5()

    if _strings_cache is None or _strings_cache_md5 != current_md5:
        _strings_cache = []
        import itertools
        for item in itertools.islice(idautils.Strings(), 0, _STRINGS_CACHE_CAP):
            if item is None:
                continue
            try:
                string = str(item)
                if string:
                    _strings_cache.append(
                        String(addr=hex(item.ea), length=item.length, string=string)
                    )
            except Exception:
                continue
        _strings_cache_md5 = current_md5

    return _strings_cache


# ============================================================================
# Core API Functions
# ============================================================================


@tool
@idaread
def idb_meta() -> Metadata:
    """Get IDB metadata"""

    def hash(f):
        try:
            return f().hex()
        except Exception:
            return ""

    return Metadata(
        path=idaapi.get_input_file_path(),
        module=idaapi.get_root_filename(),
        base=hex(idaapi.get_imagebase()),
        size=hex(get_image_size()),
        md5=hash(ida_nalt.retrieve_input_file_md5),
        sha256=hash(ida_nalt.retrieve_input_file_sha256),
        crc32=hex(ida_nalt.retrieve_input_file_crc32()),
        filesize=hex(ida_nalt.retrieve_input_file_size()),
    )


@test()
def test_idb_meta():
    meta = idb_meta()
    assert "path" in meta
    assert "module" in meta
    assert "base" in meta
    assert "size" in meta
    assert "md5" in meta
    assert "sha256" in meta
    assert "crc32" in meta
    assert "filesize" in meta


# 避免全库遍历导致卡死：lookup 用 "*" 时最多返回函数数
LOOKUP_FUNCS_ALL_CAP = 80


@tool
@idaread
def lookup_funcs(
    queries: Annotated[list[str] | str, "Address(es) or name(s). Do not use '*' for large binaries."],
) -> list[dict]:
    """Get functions by address or name (auto-detects). For listing many functions use list_funcs with filter."""
    queries = normalize_list_input(queries)

    # Treat empty/"*" as "first N functions" to avoid freezing on large binaries
    if not queries or (len(queries) == 1 and queries[0] in ("*", "")):
        import itertools
        it = idautils.Functions()
        all_funcs = [get_function(addr) for addr in itertools.islice(it, 0, LOOKUP_FUNCS_ALL_CAP)]
        return [{"query": "*", "fn": fn, "error": None} for fn in all_funcs]

    if len(DEMANGLED_TO_EA) == 0:
        create_demangled_to_ea_map()

    results = []
    for query in queries:
        try:
            ea = idaapi.BADADDR

            # Try as address first if it looks like one
            if looks_like_address(query):
                try:
                    ea = parse_address(query)
                except Exception:
                    ea = idaapi.BADADDR

            # Fall back to name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)
                if ea == idaapi.BADADDR and query in DEMANGLED_TO_EA:
                    ea = DEMANGLED_TO_EA[query]

            if ea != idaapi.BADADDR:
                func = get_function(ea, raise_error=False)
                if func:
                    results.append({"query": query, "fn": func, "error": None})
                else:
                    results.append(
                        {"query": query, "fn": None, "error": "Not a function"}
                    )
            else:
                results.append({"query": query, "fn": None, "error": "Not found"})
        except Exception as e:
            results.append({"query": query, "fn": None, "error": str(e)})

    return results


@tool
@idaread
def cursor_addr() -> str:
    """Get current address"""
    return hex(idaapi.get_screen_ea())


@tool
@idaread
def cursor_func() -> Optional[Function]:
    """Get current function"""
    return get_function(idaapi.get_screen_ea())


@tool
def int_convert(
    inputs: Annotated[
        list[NumberConversion] | NumberConversion,
        "Convert numbers to various formats (hex, decimal, binary, ascii)",
    ],
) -> list[dict]:
    """Convert numbers to different formats"""
    inputs = normalize_dict_list(inputs, lambda s: {"text": s, "size": 64})

    results = []
    for item in inputs:
        text = item.get("text", "")
        size = item.get("size")

        try:
            value = int(text, 0)
        except ValueError:
            results.append(
                {"input": text, "result": None, "error": f"Invalid number: {text}"}
            )
            continue

        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        try:
            bytes_data = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            results.append(
                {
                    "input": text,
                    "result": None,
                    "error": f"Number {text} is too big for {size} bytes",
                }
            )
            continue

        ascii_str = ""
        for byte in bytes_data.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str = None
                break

        results.append(
            {
                "input": text,
                "result": ConvertedNumber(
                    decimal=str(value),
                    hexadecimal=hex(value),
                    bytes=bytes_data.hex(" "),
                    ascii=ascii_str,
                    binary=bin(value),
                ),
                "error": None,
            }
        )

    return results


# 构建函数列表时的上限，避免大二进制下 list_funcs 卡死
LIST_FUNCS_CAP = 1500


@tool
@idaread
def list_funcs(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List functions with optional filtering and pagination (capped for large binaries)",
    ],
) -> list[Page[Function]]:
    """List functions. Builds at most LIST_FUNCS_CAP functions per call to avoid IDA freeze."""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    import itertools
    it = idautils.Functions()
    all_functions = [get_function(addr) for addr in itertools.islice(it, 0, LIST_FUNCS_CAP)]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_functions, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


# 构建全局变量列表时的上限
LIST_GLOBALS_CAP = 4000


@tool
@idaread
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List global variables with optional filtering and pagination",
    ],
) -> list[Page[Global]]:
    """List globals (capped to avoid freeze on large IDBs)."""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    all_globals: list[Global] = []
    for i, (addr, name) in enumerate(idautils.Names()):
        if i >= LIST_GLOBALS_CAP:
            break
        if not idaapi.get_func(addr) and name is not None:
            all_globals.append(Global(addr=hex(addr), name=name))

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_globals, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idaread
def imports(
    offset: Annotated[int, "Offset"],
    count: Annotated[int, "Count (0=all)"],
) -> Page[Import]:
    """List imports"""
    nimps = ida_nalt.get_import_module_qty()

    rv = []
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f"#{ordinal}"
            acc += [Import(addr=hex(ea), imported_name=symbol_name, module=module_name)]
            return True

        def imp_cb_w_context(ea, symbol_name, ordinal):
            return imp_cb(ea, symbol_name, ordinal, rv)

        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return paginate(rv, offset, count)


@tool
@idaread
def strings(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List strings with optional filtering and pagination",
    ],
) -> list[Page[String]]:
    """List strings"""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    # Use cached strings instead of rebuilding every time
    all_strings = _get_cached_strings()

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_strings, filter_pattern, "string")
        results.append(paginate(filtered, offset, count))

    return results


def ida_segment_perm2str(perm: int) -> str:
    perms = []
    if perm & ida_segment.SEGPERM_READ:
        perms.append("r")
    else:
        perms.append("-")
    if perm & ida_segment.SEGPERM_WRITE:
        perms.append("w")
    else:
        perms.append("-")
    if perm & ida_segment.SEGPERM_EXEC:
        perms.append("x")
    else:
        perms.append("-")
    return "".join(perms)


@tool
@idaread
def segments() -> list[Segment]:
    """List all segments"""
    segments = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue
        seg_name = ida_segment.get_segm_name(seg)
        segments.append(
            Segment(
                name=seg_name,
                start=hex(seg.start_ea),
                end=hex(seg.end_ea),
                size=hex(seg.end_ea - seg.start_ea),
                permissions=ida_segment_perm2str(seg.perm),
            )
        )
    return segments


@tool
@idaread
def local_types():
    """List local types"""
    error = ida_hexrays.hexrays_failure_t()
    locals = []
    idati = ida_typeinf.get_idati()
    type_count = ida_typeinf.get_ordinal_limit(idati)
    for ordinal in range(1, type_count):
        try:
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(idati, ordinal):
                type_name = tif.get_type_name()
                if not type_name:
                    type_name = f"<Anonymous Type #{ordinal}>"
                locals.append(f"\nType #{ordinal}: {type_name}")
                if tif.is_udt():
                    c_decl_flags = (
                        ida_typeinf.PRTYPE_MULTI
                        | ida_typeinf.PRTYPE_TYPE
                        | ida_typeinf.PRTYPE_SEMI
                        | ida_typeinf.PRTYPE_DEF
                        | ida_typeinf.PRTYPE_METHODS
                        | ida_typeinf.PRTYPE_OFFSETS
                    )
                    c_decl_output = tif._print(None, c_decl_flags)
                    if c_decl_output:
                        locals.append(f"  C declaration:\n{c_decl_output}")
                else:
                    simple_decl = tif._print(
                        None,
                        ida_typeinf.PRTYPE_1LINE
                        | ida_typeinf.PRTYPE_TYPE
                        | ida_typeinf.PRTYPE_SEMI,
                    )
                    if simple_decl:
                        locals.append(f"  Simple declaration:\n{simple_decl}")
            else:
                message = f"\nType #{ordinal}: Failed to retrieve information."
                if error.str:
                    message += f": {error.str}"
                if error.errea != idaapi.BADADDR:
                    message += f"from (address: {hex(error.errea)})"
                raise IDAError(message)
        except Exception:
            continue
    return locals
