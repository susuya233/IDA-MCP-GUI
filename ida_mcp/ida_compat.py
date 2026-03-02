# -*- coding: utf-8 -*-
"""
IDA Pro 版本兼容层 - 支持 IDA 7.x / 8.x / 9.x
使插件在 IDA 9.2 及更早版本上均可运行。
"""

import ida_kernwin

# -----------------------------------------------------------------------------
# 内核版本 (IDA 9 中 get_kernel_version 可能在 ida_kernwin)
# -----------------------------------------------------------------------------
def get_kernel_version():
    try:
        return ida_kernwin.get_kernel_version()
    except AttributeError:
        import idaapi
        return idaapi.get_kernel_version()


# -----------------------------------------------------------------------------
# execute_sync (IDA 7.4+ 已移至 ida_kernwin)
# -----------------------------------------------------------------------------
def execute_sync(func, reqf):
    try:
        return ida_kernwin.execute_sync(func, reqf)
    except AttributeError:
        import idaapi
        return idaapi.execute_sync(func, reqf)


# -----------------------------------------------------------------------------
# MFF_READ / MFF_WRITE (与 ida_kernwin 一致，IDA 9 中 idaapi 可能不再导出)
# -----------------------------------------------------------------------------
MFF_READ = ida_kernwin.MFF_READ
MFF_WRITE = ida_kernwin.MFF_WRITE
MFF_FAST = getattr(ida_kernwin, "MFF_FAST", 0)


# -----------------------------------------------------------------------------
# BADADDR (IDA 7+ 推荐使用 ida_idaapi.BADADDR，部分版本仍在 idaapi)
# -----------------------------------------------------------------------------
def _get_badaddr():
    try:
        import ida_idaapi
        return ida_idaapi.BADADDR
    except (ImportError, AttributeError):
        import idaapi
        return idaapi.BADADDR


BADADDR = _get_badaddr()


# -----------------------------------------------------------------------------
# get_inf_structure (IDA 9 已移除，改用 ida_ida.inf_get_*)
# -----------------------------------------------------------------------------
class _InfStructureCompat:
    """兼容层：模拟 get_inf_structure() 返回对象的常用属性"""

    def __init__(self):
        try:
            import ida_ida
            self._ida_ida = ida_ida
        except ImportError:
            self._ida_ida = None
        self._cache = None  # 旧版 idaapi.get_inf_structure() 的返回值

    def _get_info(self):
        if self._cache is not None:
            return self._cache if self._cache else None  # False 表示 IDA 9，用 ida_ida
        try:
            import idaapi
            self._cache = idaapi.get_inf_structure()
            return self._cache
        except AttributeError:
            self._cache = False  # IDA 9：无 get_inf_structure，后续用 ida_ida
        return None

    @property
    def procname(self):
        info = self._get_info()
        if info is not None:
            return getattr(info, "procname", "")
        if self._ida_ida and hasattr(self._ida_ida, "inf_get_procname"):
            return self._ida_ida.inf_get_procname() or ""
        return ""

    def is_64bit(self):
        info = self._get_info()
        if info is not None and hasattr(info, "is_64bit"):
            return info.is_64bit()
        if self._ida_ida and hasattr(self._ida_ida, "inf_is_64bit"):
            return self._ida_ida.inf_is_64bit()
        return False

    @property
    def filetype(self):
        info = self._get_info()
        if info is not None:
            return getattr(info, "filetype", 0)
        if self._ida_ida and hasattr(self._ida_ida, "inf_get_filetype"):
            return self._ida_ida.inf_get_filetype()
        return 0


def get_inf_structure():
    """兼容 IDA 7/8/9：返回具有 procname、is_64bit()、filetype 的 inf 对象"""
    return _InfStructureCompat()
