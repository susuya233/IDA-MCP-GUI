---
name: ida-mcp
description: Use IDA Pro MCP tools for binary analysis without freezing IDA. Apply when analyzing binaries in IDA, tracing sinks (e.g. os_exec.Command, system), decompiling handlers, or when the user mentions IDA MCP, reverse engineering, or vulnerability chains.
---

# IDA MCP 使用规范

与 IDA Pro 通过 MCP 联动时**必须遵守本规范**，否则易导致 IDA 卡死或 Connection closed。

---

## Agent 行为准则（优先遵守）

**必须先做**
- 单次只反编译 **1～2 个** 地址；要分析多个函数时**分多轮**请求。
- 查函数列表时**必须带 filter**，例如 `list_funcs(queries=[{"filter": "关键词", "count": 50}])`。
- 追踪 sink 时**先** `get_taint_paths(sink_name="...")` 拿路径，**再**对 1～2 个关键地址 `decompile`。

**禁止**
- 不要一次对 3 个及以上地址调用 `decompile` 或 `analyze_funcs`。
- 不要对 `list_funcs` 使用空 filter 或 `"*"` 拉全库。
- 不要对 `lookup_funcs` 传 `["*"]`（大二进制会重负载且只返回前 80 个）。

---

## 单次调用上限（硬性）

| 工具 | 单次上限 |
|------|----------|
| `decompile`, `analyze_funcs`, `disasm` | **2** 个地址 |
| `xrefs_to`, `callers`, `callees` | **3** 个地址 |
| `callgraph` | **2** 个 root，每 root 最多 **150** 节点 |
| `get_taint_paths` | 最多 **8** 条路径（务必传 `sink_name` 收窄） |
| `list_funcs` | 构建最多 **1500** 个函数，**必须带 filter** |
| `lookup_funcs("*")` | 最多 **80** 个（大二进制避免用） |
| `find_paths` | **3** 个 query |

---

## 调用示例

```text
# 按名称找函数（带 filter，安全）
list_funcs(queries=[{"filter": "Runner.clean", "count": 50}])
list_funcs(queries=[{"filter": "handleCtl", "count": 20}])

# 精确名查一个函数
lookup_funcs(queries=["app_serv_internal_app_apprunner._ptr_Runner.clean"])

# 追踪 sink 再反编译（先路径，后 1～2 个地址）
get_taint_paths(sink_name="os_exec.Command")
decompile(addrs=["0x969060"])
decompile(addrs=["0xfa0f00"])   # 第二个地址下一轮再要

# 看谁调用了某地址
callers(addrs=["0x969060"])

# 看某地址的调用图（最多 2 个 root）
callgraph(roots=["0x1039cc0"])
```

---

## 出错时怎么做

| 现象 | 建议 |
|------|------|
| Connection closed / ECONNREFUSED | 确认 IDA 已启动 MCP（Edit → Plugins → MCP）、端口 13337、只开一个 IDA。 |
| IDA 卡住 / 无响应 | 当前请求过大或过慢；**分批**：每次 1～2 个地址，减少单次 `decompile`/`analyze_funcs`。 |
| 返回「Not found」 | 用 `list_funcs` 的 filter 换关键词，或确认地址/名称是否在当前 IDB 中。 |

---

## 工具速查（带参数与上限）

- `decompile(addrs)`：1～2 个地址。
- `disasm(addrs, max_instructions=2000)`：1～2 个地址，单函数最多 15000 条指令。
- `xrefs_to(addrs)`：最多 3 个地址，每地址最多 200 条 xref。
- `callers(addrs)` / `callees(addrs)`：最多 3 个地址；callers 每地址最多 200 个。
- `analyze_funcs(addrs)`：1～2 个地址（含反编译，较重）。
- `callgraph(roots)`：1～2 个 root，每 root 最多 150 节点。
- `get_taint_paths(sink_name="...", max_paths=8)`：**务必传 sink_name**。
- `list_funcs(queries=[{"filter": "子串", "count": 50}])`：**必须带 filter**。
- `find_paths(queries)`：最多 3 个 `{source, target}`。

遵循上述准则与示例，可稳定配合 IDA MCP 做二进制与漏洞链分析且不触发卡死。
