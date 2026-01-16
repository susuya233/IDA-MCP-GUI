# IDA-MCP-GUI

IDA Pro 漏洞扫描与分析插件 - 集成 MCP (Model Context Protocol) 支持的 IDA Pro 安全分析工具。

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

## 安装

将整个 `ida_mcp` 文件夹和 `ida_mcp.py` 复制到 IDA Pro 的 plugins 目录：

```
%APPDATA%\Hex-Rays\IDA Pro\plugins\
├── ida_mcp.py
└── ida_mcp\
    ├── __init__.py
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
2. 按 `Ctrl+Alt+M` 启动 MCP 服务器
3. 访问 Web 界面：
   - 配置页面: `http://127.0.0.1:13337/config.html`
   - 危险函数扫描: `http://127.0.0.1:13337/dangerous.html`
   - 命令注入扫描: `http://127.0.0.1:13337/cmdi.html`
4. 或使用快捷键打开 IDA 内置窗口

## 许可证

MIT License

## 致谢

- 基于 [IDA Pro MCP](https://github.com/mrexodia/ida-pro-mcp) 项目扩展开发
