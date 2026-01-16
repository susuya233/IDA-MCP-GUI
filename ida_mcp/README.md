# IDA-MCP-GUI

IDA Pro 漏洞扫描与分析插件 - 集成 MCP (Model Context Protocol) 支持的 IDA Pro 安全分析工具。

## 功能特性

### 🛡️ 危险函数扫描
自动检测二进制文件中对危险函数的调用：
- **内存拷贝函数**: strcpy, strcat, sprintf, memcpy 等（缓冲区溢出风险）
- **格式化字符串函数**: printf, syslog 等（格式化字符串漏洞）
- **输入函数**: scanf, sscanf 等（输入验证风险）
- **命令执行函数**: system, popen, exec* 等（命令注入风险）
- **文件操作函数**: fopen, unlink 等（路径穿越风险）

### 💉 命令注入扫描
基于污点分析的命令注入漏洞检测：
- 自动识别 **Source**（用户可控输入点）
- 自动识别 **Sink**（危险命令执行函数）
- 追踪数据流，生成 **利用链路径**
- 可控性分析与风险等级评估

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

## 截图

### 命令注入扫描 Web 界面
```
💉 命令注入扫描
┌────────────────────────────────────────────────────┐
│ 📊 统计: 发现漏洞点 12 | 严重 3 | 高危 5           │
└────────────────────────────────────────────────────┘

#1 🔴严重  system ← vulnerable_func  可控性: HIGH
├─ 📍 调用位置: 0x8048520: call system
├─ 🎯 可控输入源:
│   🌍 nvram_get [Web输入] 同函数内
└─ 🔗 利用链: nvram_get → process_cmd → system
```

### IDA 内置扫描窗口
```
┌─────────────────────────────────────────────────────────────────┐
│ 命令注入扫描结果                                                  │
├────┬──────┬──────────┬─────────────┬──────────┬──────┬────┬─────┤
│ #  │ 风险 │ Sink函数  │ 调用函数     │ 调用地址  │可控性│源数│反汇编│
├────┼──────┼──────────┼─────────────┼──────────┼──────┼────┼─────┤
│ 1  │🔴严重│ system   │ vuln_func   │ 0x8048520│ 高   │ 3  │call │
└────┴──────┴──────────┴─────────────┴──────────┴──────┴────┴─────┘
                      [双击或按 Enter 跳转到代码位置]
```

## 检测的危险函数列表

<details>
<summary>点击展开完整列表</summary>

### 内存拷贝函数
```
strcpy, strcat, sprintf, vsprintf, gets, strncpy, strncat, 
snprintf, vsnprintf, memcpy, memmove, bcopy
```

### 格式化字符串函数
```
printf, fprintf, dprintf, syslog, vsyslog, asprintf, vasprintf
```

### 输入函数
```
scanf, sscanf, fscanf, vscanf, vfscanf, vsscanf
```

### 命令执行函数
```
system, popen, pclose, execl, execlp, execle, execv, execvp, execvpe,
doSystem, doSystemCmd, doShell, run_cmd, cmd_exec, ExecCmd, exec_cmd,
os_system, shell_exec
```

### 文件操作函数
```
open, open64, fopen, freopen, creat, unlink, remove, rename, link,
symlink, readlink, realpath, chdir, mkdir, rmdir, tmpnam, tempnam, mktemp
```

</details>

## 许可证

MIT License

## 致谢

- 基于 [IDA Pro MCP](https://github.com/mrexodia/ida-pro-mcp) 项目扩展开发

