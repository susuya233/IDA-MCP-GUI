# IDA-MCP-GUI

IDA Pro 漏洞扫描与分析插件 - 集成 MCP (Model Context Protocol) 支持的 IDA Pro 安全分析工具。**支持 IDA 7.x / 8.x / 9.x（含 9.2）。**

## 功能特性

### 🛡️ 危险函数扫描
自动检测二进制文件中对危险函数的调用：
- **内存拷贝函数**: strcpy, strcat, sprintf, memcpy 等
- **格式化字符串函数**: printf, syslog 等
- **输入函数**: scanf, sscanf 等
- **命令执行函数**: system, popen, exec* 等
- **文件操作函数**: fopen, unlink 等
- **CGI处理函数**: websGetVar, nvram_get, cgi_get 等
- **认证函数**: check_auth, verify_password 等

### 💉 命令注入扫描
基于污点分析的命令注入漏洞检测：
- 自动识别 **Source**（用户可控输入点）
- 自动识别 **Sink**（危险命令执行函数）
- 追踪数据流，生成 **利用链路径**
- 可控性分析与风险等级评估

### 🔧 缓冲区溢出分析
- 栈缓冲区溢出检测
- 堆缓冲区溢出检测
- 整数溢出风险分析

### 📝 格式化字符串漏洞
- 格式化函数调用检测
- 可控性分析
- 利用链追踪

### 📂 路径穿越分析
- 目录穿越检测
- 符号链接攻击
- 竞争条件 (TOCTOU)
- 临时文件攻击

### 🔀 函数调用链可视化
- 污点传播路径
- Mermaid/DOT 图表生成
- Source→Sink 路径分析

### 🏗️ 自动结构/枚举建议
- 内存访问模式分析
- 魔数识别与枚举匹配
- 类型修复建议

### 🤖 LLM 语义分析接口
- 函数上下文提取
- 结构化分析提示词生成
- 批量危险函数分析

### 📱 MIPS/CGI 嵌入式设备支持
针对路由器、IoT 设备固件的深度支持：

**支持的厂商特定函数：**
| 厂商 | 命令执行 | 输入获取 |
|------|----------|----------|
| D-Link | lxmldbc_system, fwSystem | cgibin_get |
| TP-Link | tpSystem, httpRpmDoSystem | httpGetEnv, tpHttpdGetEnv |
| Netgear | acosSystem, acosSysExec | acosNvramConfig_get |
| ASUS | doCmd, notify_rc | tcapi_get |
| Tenda | formSysCmd, tenda_system | websGetVar, GetValue |
| 华为 | ATP_UTIL_ExecShell, VOS_System | ATP_DBGetPara |
| 小米 | mi_system, miot_system | - |
| GoAhead | websLaunchCgiProc, cgiHandler | websGetVar, ejArgs |
| OpenWrt | luci_sys_exec, ubus_call | uci_get |

**支持的输入源：**
- NVRAM: nvram_get, nvram_safe_get, bcmGetNvram
- UCI: uci_get, uci_get_option
- CGI: websGetVar, cgiGetValue, httpGetParam
- JSON: cJSON_GetObjectItem, json_get_value
- 环境变量: QUERY_STRING, REQUEST_METHOD, HTTP_COOKIE

### 📊 双重界面
- **Web 界面**: 现代化暗色主题，支持筛选、展开详情、复制内容
- **IDA 内置窗口**: 原生 Chooser 窗口，双击/Enter 快速跳转到代码位置

## 快捷键

| 快捷键 | 功能 |
|--------|------|
| `Ctrl+Alt+M` | 启动 MCP 服务器 |
| `Ctrl+Shift+D` | 危险函数扫描窗口 |
| `Ctrl+Shift+I` | 命令注入扫描窗口 |
| `Ctrl+Shift+S` | 输入源函数窗口 |
| `Ctrl+Shift+B` | 缓冲区溢出扫描 |
| `Ctrl+Shift+F` | 格式化字符串扫描 |
| `Ctrl+Shift+P` | 路径穿越扫描 |
| `Ctrl+Shift+A` | 打开所有扫描窗口 |

## 安装（让 IDA 能用）

**兼容 IDA 7.x / 8.x / 9.x（含 9.2）**。

### ⚠️ 必须先让 IDA 使用 Python

本插件是 **Python 插件**。若 IDA 当前是 **IDC** 模式（底部控制台旁显示 “IDC - Native built-in language”），Python 插件不会加载，菜单里也不会出现 MCP。

**切换到 Python 的方法：**

- **方法一（推荐）**：在终端执行 IDA 自带的 Python 切换工具（先完全退出 IDA）：
  ```bash
  "/Applications/IDA Professional 9.2.app/Contents/MacOS/idapyswitch"
  ```
  按提示选择本机已安装的 **Python 3**，然后重新打开 IDA。
- **方法二**：在 IDA 底部控制台左侧，点击当前显示的 **“IDC”**，在下拉菜单里选择 **“Python 3”** 或 **“Python”**，使当前脚本语言变为 Python。部分版本下，Python 插件只有在用该方法选过 Python 后才会被加载。

切换成功后，重启 IDA，再在 **Edit → Plugins** 里应能看到 **MCP**。

---

1. **找到 IDA 的 plugins 目录**  
   - **macOS**：`~/.idapro/plugins/`（IDA 实际读取这里，不是 Application Support）  
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro 9.2\plugins\`（或你的 IDA 版本）

2. **复制两样到该目录**：本仓库的 **`ida_mcp.py`** 和整个 **`ida_mcp`** 文件夹（缺一不可）。

3. **重启 IDA**，打开任意二进制后，菜单 **Edit → Plugins → MCP** 或按 **Ctrl+Alt+M**（Mac: **Ctrl+Option+M**）启动。

将整个 `ida_mcp` 文件夹和 `ida_mcp.py` 复制到 IDA Pro 的 plugins 目录后，结构如下：

```
%APPDATA%\Hex-Rays\IDA Pro\plugins\
├── ida_mcp.py
└── ida_mcp\
    ├── __init__.py
    ├── ida_compat.py   # IDA 9 兼容层
    ├── api_dangerous.py
    ├── api_taint.py
    ├── api_buffer.py
    ├── api_format_string.py
    ├── api_path_traversal.py
    ├── api_callgraph.py
    ├── api_struct_enum.py
    ├── api_llm_analysis.py
    ├── ida_gui.py
    ├── http.py
    └── ...
```

## 使用方法

1. 在 IDA Pro 中加载目标二进制文件
2. 按 **Ctrl+Alt+M**（Mac: **Ctrl+Option+M**）启动 MCP 服务器
3. 访问 Web 界面：
   - 配置页面: `http://127.0.0.1:13337/config.html`
   - 危险函数扫描: `http://127.0.0.1:13337/dangerous.html`
   - 命令注入扫描: `http://127.0.0.1:13337/cmdi.html`
4. 或使用快捷键打开 IDA 内置窗口

### 一键安装（macOS / Linux）

在项目根目录执行：

```bash
./install_to_ida.sh
```

脚本会自动安装到 `~/.idapro/plugins/`，若检测到 IDA 应用包则同时安装到应用内 `plugins` 目录。

### 在 Cursor 中使用 MCP

在 Cursor 中可使用本插件的 MCP 工具（需先启动 IDA 并运行 MCP 插件）。在 **`~/.cursor/mcp.json`** 中加入：

```json
{
  "mcpServers": {
    "ida-mcp": {
      "url": "http://127.0.0.1:13337/sse"
    }
  }
}
```

保存后重启 Cursor，即可在对话中调用 IDA 的反汇编、漏洞扫描等能力。**注意**：须先在 IDA 中通过 Edit → Plugins → MCP 启动服务，否则 Cursor 会报连接被拒绝。

- **端口**：请确认 `mcp.json` 里写的是 **13337**（只开一个 IDA 并只启动一次 MCP，否则会占 13338 等端口，Cursor 连错会报 ECONNREFUSED）。
- **为何 AI 跑 MCP 时 IDA 会卡住/闪退**：所有 MCP 工具都在 IDA 的**主线程**上执行（反汇编、反编译等都要用 IDA API）。AI 一次请求很多或很大的操作（例如批量反编译很多函数、或全图污点路径）时，主线程会长时间占用，IDA 会表现为无响应甚至“卡死”；若反编译或分析里触发 IDA/Hex-Rays 内部错误，可能直接闪退。建议：
  - 在 Cursor 里**不要一次请求过多**（例如一次只反编译少量函数）；
  - **追踪 sink 调用链并反编译**：先单独调用 `get_taint_paths`（可传 `sink_name` 如 `os_exec.Command`）拿到路径，再**分批**对关键函数反编译，每批 **1～3 个地址**，避免一次反编译 4+ 个大函数导致卡死或 “Connection closed”。
  - 插件已做限制：污点路径单次最多返回 15 条、全图构建节点上限 350、反编译单次最多 4 个地址（大二进制建议 1～3）。
  - 若 IDA 已卡住，可等待当前请求跑完，或关闭 Cursor 里正在跑的 MCP 调用；
  - 若出现 “Connection closed” 或 “Missing ?session for SSE POST”，多为 Cursor 先用了 Streamable HTTP 再回退到 SSE，或连接被关闭，可重开 IDA 的 MCP（Edit → Plugins → MCP 再点一次），并确认只保留一个 MCP 服务（端口 13337）。

## 许可证

MIT License

## 致谢

- 基于 [IDA Pro MCP](https://github.com/mrexodia/ida-pro-mcp) 项目扩展开发
