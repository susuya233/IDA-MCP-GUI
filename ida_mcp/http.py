import html
import json
import ida_netnode
from urllib.parse import urlparse, parse_qs
from typing import TypeVar, cast
from http.server import HTTPServer

from .sync import idaread, idawrite
from .rpc import McpRpcRegistry, McpHttpRequestHandler, MCP_SERVER, MCP_UNSAFE
from .api_dangerous import find_dangerous_calls, DANGEROUS_FUNCTIONS
from .api_taint import scan_command_injection, SOURCE_FUNCTIONS, SINK_FUNCTIONS


T = TypeVar("T")


@idaread
def config_json_get(key: str, default: T) -> T:
    node = ida_netnode.netnode(f"$ ida_mcp.{key}")
    json_blob: bytes | None = node.getblob(0, "C")
    if json_blob is None:
        return default
    try:
        return json.loads(json_blob)
    except Exception as e:
        print(
            f"[WARNING] Invalid JSON stored in netnode '{key}': '{json_blob}' from netnode: {e}"
        )
        return default


@idawrite
def config_json_set(key: str, value):
    node = ida_netnode.netnode(f"$ ida_mcp.{key}", 0, True)
    json_blob = json.dumps(value).encode("utf-8")
    node.setblob(json_blob, 0, "C")


def handle_enabled_tools(registry: McpRpcRegistry, config_key: str):
    """Changed to registry to enable configured tools, returns original tools."""
    original_tools = registry.methods.copy()
    enabled_tools = config_json_get(
        config_key, {name: True for name in original_tools.keys()}
    )
    new_tools = [name for name in original_tools if name not in enabled_tools]

    removed_tools = [name for name in enabled_tools if name not in original_tools]
    if removed_tools:
        for name in removed_tools:
            enabled_tools.pop(name)

    if new_tools:
        enabled_tools.update({name: True for name in new_tools})
        config_json_set(config_key, enabled_tools)

    registry.methods = {
        name: func for name, func in original_tools.items() if enabled_tools.get(name)
    }
    return original_tools


DEFAULT_CORS_POLICY = "local"


def get_cors_policy(port: int) -> str:
    """Retrieve the current CORS policy from configuration."""
    match config_json_get("cors_policy", DEFAULT_CORS_POLICY):
        case "unrestricted":
            return "*"
        case "local":
            return "127.0.0.1 localhost"
        case "direct":
            return f"http://127.0.0.1:{port} http://localhost:{port}"
        case _:
            return "*"


ORIGINAL_TOOLS = handle_enabled_tools(MCP_SERVER.tools, "enabled_tools")


class IdaMcpHttpRequestHandler(McpHttpRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.update_cors_policy()

    def update_cors_policy(self):
        match config_json_get("cors_policy", DEFAULT_CORS_POLICY):
            case "unrestricted":
                self.mcp_server.cors_allowed_origins = "*"
            case "local":
                self.mcp_server.cors_allowed_origins = self.mcp_server.cors_localhost
            case "direct":
                self.mcp_server.cors_allowed_origins = None

    def do_POST(self):
        """Handles POST requests."""
        if urlparse(self.path).path == "/config":
            if not self._check_origin():
                return
            self._handle_config_post()
        else:
            super().do_POST()

    def do_GET(self):
        """Handles GET requests."""
        path = urlparse(self.path).path
        if path == "/config.html":
            if not self._check_host():
                return
            self._handle_config_get()
        elif path == "/dangerous.html":
            if not self._check_host():
                return
            self._handle_dangerous_get()
        elif path == "/cmdi.html":
            if not self._check_host():
                return
            self._handle_cmdi_get()
        else:
            super().do_GET()

    @property
    def server_port(self) -> int:
        return cast(HTTPServer, self.server).server_port

    def _check_origin(self) -> bool:
        """
        Prevents CSRF and DNS rebinding attacks by ensuring POST requests
        originate from pages served by this server, not external websites.
        """
        origin = self.headers.get("Origin")
        port = self.server_port
        if origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
            self.send_error(403, "Invalid Origin")
            return False
        return True

    def _check_host(self) -> bool:
        """
        Prevents DNS rebinding attacks where an attacker's domain (e.g., evil.com)
        resolves to 127.0.0.1, allowing their page to read localhost resources.
        """
        host = self.headers.get("Host")
        port = self.server_port
        if host not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            self.send_error(403, "Invalid Host")
            return False
        return True

    def _send_html(self, status: int, text: str):
        """
        Prevents clickjacking by blocking iframes (X-Frame-Options for older
        browsers, frame-ancestors for modern ones). Other CSP directives
        provide defense-in-depth against content injection attacks.
        """
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "; ".join(
                [
                    "frame-ancestors 'none'",
                    "script-src 'self' 'unsafe-inline'",
                    "style-src 'self' 'unsafe-inline'",
                    "default-src 'self'",
                    "form-action 'self'",
                ]
            ),
        )
        self.end_headers()
        self.wfile.write(body)

    def _handle_config_get(self):
        """Sends the configuration page with checkboxes."""
        cors_policy = config_json_get("cors_policy", DEFAULT_CORS_POLICY)

        body = """<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IDA Pro MCP Config</title>
  <style>
.feature-links {
  margin-bottom: 1.5rem;
  padding: 1rem;
  background: var(--hover);
  border-radius: 8px;
  border: 1px solid var(--border);
}

.feature-links h2 {
  font-size: 1rem;
  margin-bottom: 0.75rem;
}

.feature-links a {
  display: inline-block;
  padding: 0.5rem 1rem;
  background: var(--accent);
  color: white;
  text-decoration: none;
  border-radius: 4px;
  margin-right: 0.5rem;
  font-size: 0.9rem;
}

.feature-links a:hover {
  opacity: 0.9;
}
:root {
  --bg: #ffffff;
  --text: #1a1a1a;
  --border: #e0e0e0;
  --accent: #0066cc;
  --hover: #f5f5f5;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1a1a1a;
    --text: #e0e0e0;
    --border: #333333;
    --accent: #4da6ff;
    --hover: #2a2a2a;
  }
}

* {
  box-sizing: border-box;
}

body {
  font-family: system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  max-width: 800px;
  margin: 2rem auto;
  padding: 1rem;
  line-height: 1.4;
}

h1 {
  font-size: 1.5rem;
  margin-bottom: 1rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.5rem;
}

h2 {
  font-size: 1.1rem;
  margin-top: 1.5rem;
  margin-bottom: 0.5rem;
}

label {
  display: block;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  cursor: pointer;
}

label:hover {
  background: var(--hover);
}

input[type="checkbox"],
input[type="radio"] {
  margin-right: 0.5rem;
  accent-color: var(--accent);
}

input[type="submit"] {
  margin-top: 1rem;
  padding: 0.6rem 1.5rem;
  background: var(--accent);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
}

input[type="submit"]:hover {
  opacity: 0.9;
}

.tooltip {
  border-bottom: 1px dotted var(--text);
}
  </style>
  <script defer>
  function setTools(mode) {
    document.querySelectorAll('input[data-tool]').forEach(cb => {
        if (mode === 'all') cb.checked = true;
        else if (mode === 'none') cb.checked = false;
        else if (mode === 'disable-unsafe' && cb.hasAttribute('data-unsafe')) cb.checked = false;
    });
  }
  </script>
</head>
<body>
<h1>IDA Pro MCP Config</h1>

<div class="feature-links">
  <h2>🛠️ 功能</h2>
  <a href="/dangerous.html">🛡️ 危险函数扫描</a>
  <a href="/cmdi.html">💉 命令注入扫描</a>
</div>

<form method="post" action="/config">

<h2>API Access</h2>
"""
        cors_options = [
            (
                "unrestricted",
                "⛔ Unrestricted",
                "Any website can make requests to this server. A malicious site you visit could access or modify your IDA database.",
            ),
            (
                "local",
                "🏠 Local apps only",
                "Only web apps running on localhost can connect. Remote websites are blocked, but local development tools work.",
            ),
            (
                "direct",
                "🔒 Direct connections only",
                "Browser-based requests are blocked. Only direct clients like curl, MCP tools, or Claude Desktop can connect.",
            ),
        ]
        for value, label, tooltip in cors_options:
            checked = "checked" if cors_policy == value else ""
            body += f'<label><input type="radio" name="cors_policy" value="{html.escape(value)}" {checked}><span class="tooltip" title="{html.escape(tooltip)}">{html.escape(label)}</span></label>'
        body += "<br><input type='submit' value='Save'>"

        quick_select = """<p style="font-size: 0.9rem; margin: 0.5rem 0;">
  Select:
  <a href="#" onclick="setTools('all'); return false;">All</a> ·
  <a href="#" onclick="setTools('none'); return false;">None</a> ·
  <a href="#" onclick="setTools('disable-unsafe'); return false;">Disable unsafe</a>
</p>"""

        body += "<h2>Enabled Tools</h2>"
        body += quick_select
        for name, func in ORIGINAL_TOOLS.items():
            description = (
                (func.__doc__ or "No description").strip().splitlines()[0].strip()
            )
            unsafe_prefix = "⚠️ " if name in MCP_UNSAFE else ""
            checked = " checked" if name in self.mcp_server.tools.methods else ""
            unsafe_attr = " data-unsafe" if name in MCP_UNSAFE else ""
            body += f"<label><input type='checkbox' name='{html.escape(name)}' value='{html.escape(name)}'{checked}{unsafe_attr} data-tool>{unsafe_prefix}{html.escape(name)}: {html.escape(description)}</label>"
        body += quick_select
        body += "<br><input type='submit' value='Save'>"
        body += "</form></body></html>"
        self._send_html(200, body)

    def _handle_config_post(self):
        """Handles the configuration form submission."""
        # Validate Content-Type
        content_type = self.headers.get("content-type", "").split(";")[0].strip()
        if content_type != "application/x-www-form-urlencoded":
            self.send_error(400, f"Unsupported Content-Type: {content_type}")
            return

        # Parse the form data
        length = int(self.headers.get("content-length", "0"))
        postvars = parse_qs(self.rfile.read(length).decode("utf-8"))

        # Update CORS policy
        cors_policy = postvars.get("cors_policy", [DEFAULT_CORS_POLICY])[0]
        config_json_set("cors_policy", cors_policy)
        self.update_cors_policy()

        # Update the server's tools
        enabled_tools = {name: name in postvars for name in ORIGINAL_TOOLS.keys()}
        self.mcp_server.tools.methods = {
            name: func
            for name, func in ORIGINAL_TOOLS.items()
            if enabled_tools.get(name)
        }
        config_json_set("enabled_tools", enabled_tools)

        # Redirect back to the config page
        self.send_response(302)
        self.send_header("Location", "/config.html")
        self.end_headers()

    def _handle_dangerous_get(self):
        """Sends the dangerous functions scan page."""
        # Get query parameters for filtering
        query_params = parse_qs(urlparse(self.path).query)
        selected_categories = query_params.get("category", [])
        
        # Get dangerous function calls
        try:
            if selected_categories:
                results = find_dangerous_calls(categories=selected_categories)
            else:
                results = find_dangerous_calls()
        except Exception as e:
            results = []
            error_msg = str(e)
        else:
            error_msg = None

        # Category descriptions
        category_info = {
            "memory_copy": ("🔴", "内存拷贝", "缓冲区溢出风险 - strcpy, memcpy等"),
            "format_string": ("🟠", "格式化字符串", "格式化字符串漏洞 - printf, syslog等"),
            "input": ("🟡", "输入函数", "输入验证风险 - scanf, sscanf等"),
            "command_exec": ("🔴", "命令执行", "命令注入风险 - system, popen, exec*等"),
            "file_operation": ("🟠", "文件操作", "路径穿越风险 - fopen, unlink等"),
        }

        body = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IDA Pro MCP - 危险函数扫描</title>
  <style>
:root {
  --bg: #0d1117;
  --bg-secondary: #161b22;
  --bg-tertiary: #21262d;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --border: #30363d;
  --accent: #58a6ff;
  --accent-hover: #79c0ff;
  --danger: #f85149;
  --warning: #d29922;
  --success: #3fb950;
  --purple: #a371f7;
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  min-height: 100vh;
}

.container {
  max-width: 1400px;
  margin: 0 auto;
  padding: 2rem;
}

header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--border);
}

h1 {
  font-size: 1.75rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

h1 .icon {
  font-size: 2rem;
}

.nav-links {
  display: flex;
  gap: 1rem;
}

.nav-links a {
  color: var(--accent);
  text-decoration: none;
  padding: 0.5rem 1rem;
  border-radius: 6px;
  transition: background 0.2s;
}

.nav-links a:hover {
  background: var(--bg-tertiary);
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}

.stat-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.25rem;
}

.stat-card .label {
  color: var(--text-muted);
  font-size: 0.875rem;
  margin-bottom: 0.25rem;
}

.stat-card .value {
  font-size: 2rem;
  font-weight: 600;
}

.stat-card.danger .value { color: var(--danger); }
.stat-card.warning .value { color: var(--warning); }
.stat-card.success .value { color: var(--success); }

.filter-section {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.25rem;
  margin-bottom: 2rem;
}

.filter-section h2 {
  font-size: 1rem;
  margin-bottom: 1rem;
  color: var(--text-muted);
}

.filter-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
}

.filter-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  border-radius: 20px;
  cursor: pointer;
  transition: all 0.2s;
  font-size: 0.875rem;
}

.filter-chip:hover {
  border-color: var(--accent);
}

.filter-chip.active {
  background: var(--accent);
  border-color: var(--accent);
  color: var(--bg);
}

.filter-chip input {
  display: none;
}

.results-section {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}

.results-header {
  padding: 1rem 1.25rem;
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.results-header h2 {
  font-size: 1.125rem;
  font-weight: 600;
}

.function-group {
  border-bottom: 1px solid var(--border);
}

.function-group:last-child {
  border-bottom: none;
}

.function-header {
  display: flex;
  align-items: center;
  padding: 1rem 1.25rem;
  cursor: pointer;
  transition: background 0.2s;
  gap: 1rem;
}

.function-header:hover {
  background: var(--bg-tertiary);
}

.function-name {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-weight: 600;
  color: var(--danger);
  min-width: 180px;
}

.function-addr {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  color: var(--text-muted);
  font-size: 0.875rem;
  min-width: 120px;
}

.function-category {
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 500;
}

.category-memory_copy { background: rgba(248, 81, 73, 0.2); color: var(--danger); }
.category-format_string { background: rgba(210, 153, 34, 0.2); color: var(--warning); }
.category-input { background: rgba(210, 153, 34, 0.15); color: #e3b341; }
.category-command_exec { background: rgba(248, 81, 73, 0.2); color: var(--danger); }
.category-file_operation { background: rgba(210, 153, 34, 0.2); color: var(--warning); }

.call-count {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: var(--text-muted);
  font-size: 0.875rem;
}

.call-count .badge {
  background: var(--accent);
  color: var(--bg);
  padding: 0.125rem 0.5rem;
  border-radius: 10px;
  font-weight: 600;
  font-size: 0.75rem;
}

.expand-icon {
  color: var(--text-muted);
  transition: transform 0.2s;
}

.function-group.expanded .expand-icon {
  transform: rotate(90deg);
}

.callers-list {
  display: none;
  background: var(--bg);
  border-top: 1px solid var(--border);
}

.function-group.expanded .callers-list {
  display: block;
}

.caller-item {
  display: grid;
  grid-template-columns: 1fr 120px auto;
  gap: 1rem;
  padding: 0.75rem 1.25rem 0.75rem 3rem;
  border-bottom: 1px solid var(--border);
  font-size: 0.875rem;
  align-items: center;
}

.caller-item:last-child {
  border-bottom: none;
}

.caller-func {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  color: var(--accent);
}

.caller-addr {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  color: var(--text-muted);
}

.caller-disasm {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  color: var(--purple);
  font-size: 0.8125rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 400px;
}

.empty-state {
  text-align: center;
  padding: 4rem 2rem;
  color: var(--text-muted);
}

.empty-state .icon {
  font-size: 3rem;
  margin-bottom: 1rem;
}

.refresh-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: var(--accent);
  color: var(--bg);
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  text-decoration: none;
  font-size: 0.875rem;
  transition: background 0.2s;
}

.refresh-btn:hover {
  background: var(--accent-hover);
}

.error-banner {
  background: rgba(248, 81, 73, 0.1);
  border: 1px solid var(--danger);
  color: var(--danger);
  padding: 1rem;
  border-radius: 8px;
  margin-bottom: 2rem;
}
  </style>
</head>
<body>
<div class="container">
  <header>
    <h1><span class="icon">🛡️</span> 危险函数扫描</h1>
    <nav class="nav-links">
      <a href="/config.html">⚙️ 配置</a>
    </nav>
  </header>
"""

        if error_msg:
            body += f'<div class="error-banner">⚠️ 错误: {html.escape(error_msg)}</div>'

        # Calculate statistics
        total_functions = len(results)
        total_calls = sum(r["call_count"] for r in results)
        high_risk_count = sum(1 for r in results if r["category"] in ("memory_copy", "command_exec"))

        body += f"""
  <div class="stats-grid">
    <div class="stat-card danger">
      <div class="label">发现的危险函数</div>
      <div class="value">{total_functions}</div>
    </div>
    <div class="stat-card warning">
      <div class="label">总调用次数</div>
      <div class="value">{total_calls}</div>
    </div>
    <div class="stat-card danger">
      <div class="label">高风险函数</div>
      <div class="value">{high_risk_count}</div>
    </div>
    <div class="stat-card success">
      <div class="label">检测类别</div>
      <div class="value">{len(DANGEROUS_FUNCTIONS)}</div>
    </div>
  </div>

  <form method="get" action="/dangerous.html">
  <div class="filter-section">
    <h2>🔍 按类别筛选</h2>
    <div class="filter-grid">
"""
        for cat_key, (icon, cat_name, cat_desc) in category_info.items():
            checked = "checked" if cat_key in selected_categories or not selected_categories else ""
            active_class = "active" if cat_key in selected_categories else ""
            body += f"""
      <label class="filter-chip {active_class}" title="{html.escape(cat_desc)}">
        <input type="checkbox" name="category" value="{html.escape(cat_key)}" {checked} onchange="this.form.submit()">
        {icon} {html.escape(cat_name)}
      </label>
"""

        body += """
    </div>
  </div>
  </form>

  <div class="results-section">
    <div class="results-header">
      <h2>📋 扫描结果</h2>
      <a href="/dangerous.html" class="refresh-btn">🔄 刷新</a>
    </div>
"""

        if not results:
            body += """
    <div class="empty-state">
      <div class="icon">✅</div>
      <p>未发现危险函数调用，或当前二进制文件中没有匹配的函数。</p>
    </div>
"""
        else:
            for result in results:
                func_name = result["name"]
                func_addr = result["addr"]
                category = result["category"]
                call_count = result["call_count"]
                callers = result["callers"]
                
                cat_icon, cat_name, _ = category_info.get(category, ("❓", category, ""))
                
                body += f"""
    <div class="function-group">
      <div class="function-header" onclick="this.parentElement.classList.toggle('expanded')">
        <span class="expand-icon">▶</span>
        <span class="function-name">{html.escape(func_name)}</span>
        <span class="function-addr">{html.escape(func_addr)}</span>
        <span class="function-category category-{html.escape(category)}">{cat_icon} {html.escape(cat_name)}</span>
        <span class="call-count">
          调用次数 <span class="badge">{call_count}</span>
        </span>
      </div>
      <div class="callers-list" onclick="event.stopPropagation()">
"""
                for caller in callers:
                    caller_func = caller.get("caller_func_name") or "<未知函数>"
                    caller_addr = caller.get("call_addr", "")
                    disasm = caller.get("disasm", "")
                    
                    body += f"""
        <div class="caller-item">
          <span class="caller-func">{html.escape(caller_func)}</span>
          <span class="caller-addr">{html.escape(caller_addr)}</span>
          <span class="caller-disasm" title="{html.escape(disasm)}">{html.escape(disasm)}</span>
        </div>
"""
                body += """
      </div>
    </div>
"""

        body += """
  </div>
</div>

<script>
// Auto-expand first few results
document.querySelectorAll('.function-group').forEach((el, i) => {
  if (i < 3) el.classList.add('expanded');
});
</script>
</body>
</html>
"""
        self._send_html(200, body)

    def _handle_cmdi_get(self):
        """Sends the command injection scan page with exploit chain tracing."""
        # Get scan results
        try:
            results = scan_command_injection(max_depth=8)
        except Exception as e:
            results = []
            error_msg = str(e)
        else:
            error_msg = None

        # Risk level info
        risk_info = {
            "critical": ("🔴", "#f85149", "严重"),
            "high": ("🟠", "#d29922", "高危"),
            "medium": ("🟡", "#e3b341", "中危"),
            "low": ("🟢", "#3fb950", "低危"),
        }

        # Source category info
        source_cat_info = {
            "network": ("🌐", "网络输入"),
            "user_input": ("⌨️", "用户输入"),
            "file_input": ("📁", "文件输入"),
            "web_input": ("🌍", "Web输入"),
        }

        body = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IDA Pro MCP - 命令注入扫描</title>
  <style>
:root {
  --bg: #0d1117;
  --bg-secondary: #161b22;
  --bg-tertiary: #21262d;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --border: #30363d;
  --accent: #58a6ff;
  --accent-hover: #79c0ff;
  --danger: #f85149;
  --warning: #d29922;
  --success: #3fb950;
  --purple: #a371f7;
  --cyan: #39c5cf;
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  min-height: 100vh;
}

.container {
  max-width: 1600px;
  margin: 0 auto;
  padding: 2rem;
}

header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--border);
}

h1 {
  font-size: 1.75rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.nav-links {
  display: flex;
  gap: 1rem;
}

.nav-links a {
  color: var(--accent);
  text-decoration: none;
  padding: 0.5rem 1rem;
  border-radius: 6px;
  transition: background 0.2s;
}

.nav-links a:hover {
  background: var(--bg-tertiary);
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}

.stat-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.25rem;
}

.stat-card .label {
  color: var(--text-muted);
  font-size: 0.875rem;
  margin-bottom: 0.25rem;
}

.stat-card .value {
  font-size: 2rem;
  font-weight: 600;
}

.stat-card.critical .value { color: var(--danger); }
.stat-card.high .value { color: var(--warning); }
.stat-card.medium .value { color: #e3b341; }
.stat-card.success .value { color: var(--success); }

.vuln-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 1rem;
  overflow: hidden;
}

.vuln-header {
  display: flex;
  align-items: center;
  padding: 1rem 1.25rem;
  cursor: pointer;
  transition: background 0.2s;
  gap: 1rem;
  flex-wrap: wrap;
}

.vuln-header:hover {
  background: var(--bg-tertiary);
}

.vuln-id {
  font-weight: 700;
  color: var(--text-muted);
  min-width: 50px;
}

.risk-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
}

.risk-critical { background: rgba(248, 81, 73, 0.2); color: var(--danger); }
.risk-high { background: rgba(210, 153, 34, 0.2); color: var(--warning); }
.risk-medium { background: rgba(227, 179, 65, 0.15); color: #e3b341; }
.risk-low { background: rgba(63, 185, 80, 0.2); color: var(--success); }

.sink-info {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.sink-name {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-weight: 600;
  color: var(--danger);
}

.caller-info {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  color: var(--accent);
  font-size: 0.875rem;
}

.controllability {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.25rem 0.5rem;
  border-radius: 8px;
  font-size: 0.75rem;
  background: var(--bg-tertiary);
}

.ctrl-high { color: var(--danger); }
.ctrl-medium { color: var(--warning); }
.ctrl-low { color: var(--success); }

.expand-icon {
  color: var(--text-muted);
  transition: transform 0.2s;
  margin-left: auto;
}

.vuln-card.expanded .expand-icon {
  transform: rotate(90deg);
}

.vuln-details {
  display: none;
  background: var(--bg);
  border-top: 1px solid var(--border);
  padding: 1.25rem;
}

.vuln-card.expanded .vuln-details {
  display: block;
}

.detail-section {
  margin-bottom: 1.5rem;
}

.detail-section:last-child {
  margin-bottom: 0;
}

.detail-title {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--text-muted);
  margin-bottom: 0.75rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.disasm-line {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  background: var(--bg-secondary);
  padding: 0.75rem 1rem;
  border-radius: 6px;
  font-size: 0.8125rem;
  color: var(--purple);
  overflow-x: auto;
}

.source-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.source-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem 0.75rem;
  background: var(--bg-secondary);
  border-radius: 6px;
  font-size: 0.875rem;
}

.source-icon {
  font-size: 1rem;
}

.source-name {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  color: var(--cyan);
}

.source-cat {
  color: var(--text-muted);
  font-size: 0.75rem;
}

.source-location {
  margin-left: auto;
  font-size: 0.75rem;
  color: var(--text-muted);
}

.path-chain {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem;
  background: var(--bg-secondary);
  border-radius: 6px;
  margin-bottom: 0.5rem;
}

.path-node {
  display: inline-flex;
  align-items: center;
  padding: 0.25rem 0.5rem;
  background: var(--bg-tertiary);
  border-radius: 4px;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 0.75rem;
}

.path-node.source { background: rgba(57, 197, 207, 0.2); color: var(--cyan); }
.path-node.sink { background: rgba(248, 81, 73, 0.2); color: var(--danger); }

.path-arrow {
  color: var(--text-muted);
  font-size: 0.875rem;
}

.empty-state {
  text-align: center;
  padding: 4rem 2rem;
  color: var(--text-muted);
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
}

.empty-state .icon {
  font-size: 3rem;
  margin-bottom: 1rem;
}

.refresh-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: var(--accent);
  color: var(--bg);
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  text-decoration: none;
  font-size: 0.875rem;
  transition: background 0.2s;
}

.refresh-btn:hover {
  background: var(--accent-hover);
}

.error-banner {
  background: rgba(248, 81, 73, 0.1);
  border: 1px solid var(--danger);
  color: var(--danger);
  padding: 1rem;
  border-radius: 8px;
  margin-bottom: 2rem;
}

.info-box {
  background: rgba(88, 166, 255, 0.1);
  border: 1px solid var(--accent);
  padding: 1rem;
  border-radius: 8px;
  margin-bottom: 2rem;
  font-size: 0.875rem;
}

.info-box h3 {
  font-size: 0.9rem;
  margin-bottom: 0.5rem;
  color: var(--accent);
}

.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  margin-top: 0.75rem;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  font-size: 0.8125rem;
}
  </style>
</head>
<body>
<div class="container">
  <header>
    <h1>💉 命令注入扫描</h1>
    <nav class="nav-links">
      <a href="/dangerous.html">🛡️ 危险函数</a>
      <a href="/config.html">⚙️ 配置</a>
    </nav>
  </header>
"""

        if error_msg:
            body += f'<div class="error-banner">⚠️ 错误: {html.escape(error_msg)}</div>'

        # Calculate statistics
        total_vulns = len(results)
        critical_count = sum(1 for r in results if r["risk_level"] == "critical")
        high_count = sum(1 for r in results if r["risk_level"] == "high")
        with_sources = sum(1 for r in results if r["sources"])

        body += f"""
  <div class="info-box">
    <h3>📖 扫描说明</h3>
    <p>本工具通过污点分析追踪从用户可控输入(Source)到危险命令执行函数(Sink)的数据流路径，识别潜在的命令注入漏洞。</p>
    <div class="legend">
      <span class="legend-item"><span class="risk-badge risk-critical">🔴 严重</span> 直接可控</span>
      <span class="legend-item"><span class="risk-badge risk-high">🟠 高危</span> 间接可控</span>
      <span class="legend-item"><span class="risk-badge risk-medium">🟡 中危</span> 需验证</span>
      <span class="legend-item"><span class="risk-badge risk-low">🟢 低危</span> 可能不可利用</span>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card critical">
      <div class="label">发现漏洞点</div>
      <div class="value">{total_vulns}</div>
    </div>
    <div class="stat-card critical">
      <div class="label">严重风险</div>
      <div class="value">{critical_count}</div>
    </div>
    <div class="stat-card high">
      <div class="label">高危风险</div>
      <div class="value">{high_count}</div>
    </div>
    <div class="stat-card success">
      <div class="label">有可控输入源</div>
      <div class="value">{with_sources}</div>
    </div>
  </div>

  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
    <h2 style="font-size: 1.25rem;">🔍 扫描结果</h2>
    <a href="/cmdi.html" class="refresh-btn">🔄 重新扫描</a>
  </div>
"""

        if not results:
            body += """
  <div class="empty-state">
    <div class="icon">✅</div>
    <p>未发现命令注入漏洞点，或当前二进制文件中没有匹配的危险函数调用。</p>
  </div>
"""
        else:
            for vuln in results:
                vuln_id = vuln["id"]
                sink_func = vuln["sink_func"]
                sink_addr = vuln["sink_addr"]
                caller_func = vuln["caller_func"]
                caller_addr = vuln["caller_addr"]
                call_site = vuln["call_site"]
                disasm = vuln["disasm"]
                sources = vuln["sources"]
                controllability = vuln["controllability"]
                risk_level = vuln["risk_level"]
                exploit_paths = vuln["exploit_paths"]

                risk_icon, risk_color, risk_name = risk_info.get(risk_level, ("❓", "#8b949e", "未知"))
                
                body += f"""
  <div class="vuln-card">
    <div class="vuln-header" onclick="this.parentElement.classList.toggle('expanded')">
      <span class="vuln-id">#{vuln_id}</span>
      <span class="risk-badge risk-{html.escape(risk_level)}">{risk_icon} {html.escape(risk_name)}</span>
      <div class="sink-info">
        <span class="sink-name">{html.escape(sink_func)}</span>
        <span style="color: var(--text-muted); font-size: 0.75rem;">{html.escape(sink_addr)}</span>
      </div>
      <span style="color: var(--text-muted);">←</span>
      <span class="caller-info">{html.escape(caller_func)}</span>
      <span class="controllability ctrl-{html.escape(controllability)}">
        可控性: {html.escape(controllability.upper())}
      </span>
      <span class="expand-icon">▶</span>
    </div>
    <div class="vuln-details" onclick="event.stopPropagation()">
      <div class="detail-section">
        <div class="detail-title">📍 调用位置</div>
        <div class="disasm-line">{html.escape(call_site)}: {html.escape(disasm or "N/A")}</div>
      </div>
"""
                
                if sources:
                    body += """
      <div class="detail-section">
        <div class="detail-title">🎯 可控输入源</div>
        <div class="source-list">
"""
                    for src in sources[:10]:  # Limit displayed sources
                        src_name = src.get("name", "")
                        src_cat = src.get("category", "")
                        src_location = src.get("location", "")
                        src_via = src.get("via_function", "")
                        
                        src_icon, src_cat_name = source_cat_info.get(src_cat, ("📥", src_cat))
                        
                        location_text = "同函数内" if src_location == "same_function" else f"经由 {src_via}" if src_via else ""
                        
                        body += f"""
          <div class="source-item">
            <span class="source-icon">{src_icon}</span>
            <span class="source-name">{html.escape(src_name)}</span>
            <span class="source-cat">{html.escape(src_cat_name)}</span>
            <span class="source-location">{html.escape(location_text)}</span>
          </div>
"""
                    body += """
        </div>
      </div>
"""
                
                if exploit_paths:
                    body += """
      <div class="detail-section">
        <div class="detail-title">🔗 利用链路径</div>
"""
                    for path in exploit_paths[:5]:  # Limit displayed paths
                        path_nodes = path.get("path", [])
                        source_func = path.get("source_func", "")
                        
                        body += """
        <div class="path-chain">
"""
                        body += f'<span class="path-node source">{html.escape(source_func)}</span>'
                        body += '<span class="path-arrow">→</span>'
                        
                        for i, node in enumerate(path_nodes):
                            node_name = node.get("name", "")
                            if i > 0:
                                body += '<span class="path-arrow">→</span>'
                            if node_name == sink_func:
                                body += f'<span class="path-node sink">{html.escape(node_name)}</span>'
                            else:
                                body += f'<span class="path-node">{html.escape(node_name)}</span>'
                        
                        body += """
        </div>
"""
                    body += """
      </div>
"""
                
                body += """
    </div>
  </div>
"""

        body += """
</div>

<script>
// Auto-expand critical/high vulnerabilities
document.querySelectorAll('.vuln-card').forEach((el, i) => {
  const header = el.querySelector('.vuln-header');
  const riskBadge = header.querySelector('.risk-badge');
  if (riskBadge && (riskBadge.classList.contains('risk-critical') || riskBadge.classList.contains('risk-high'))) {
    if (i < 5) el.classList.add('expanded');
  }
});
</script>
</body>
</html>
"""
        self._send_html(200, body)
