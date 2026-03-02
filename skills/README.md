# Cursor Skill：IDA MCP

本目录是配合 [IDA-MCP-GUI](https://github.com/susuya233/IDA-MCP-GUI) 的 **Cursor Agent Skill**，让 AI 在对话里按规范调用 IDA MCP（单次少地址、带 filter 等），减少 IDA 卡死。

## 这个 Skill 怎么用？

**一步：把 skill 复制到 Cursor 会读的位置**

在**本仓库根目录**打开终端，执行：

```bash
mkdir -p .cursor/skills && cp -r skills/ida-mcp .cursor/skills/
```

**然后：** 用 Cursor 打开本仓库，并确保已配置好 IDA MCP（`~/.cursor/mcp.json` 里 `url: "http://127.0.0.1:13337/sse"`）、IDA 里已启动 MCP 插件。之后在对话里让 AI「追踪某 sink」「反编译某地址」「按名称查函数」等，Agent 会自动按 `ida-mcp/SKILL.md` 的规则调用工具（例如一次只反编译 1～2 个地址）。

- 只需复制**一次**，只要用 Cursor 打开这个项目，就会加载该 skill。
- 不需要改 Cursor 设置，skill 放在项目内 `.cursor/skills/` 即可生效。

## 目录结构

```
skills/
├── README.md           # 本说明
└── ida-mcp/
    └── SKILL.md        # IDA MCP 使用规范（Agent 会按此执行）
```

## 说明

- Skill 内容在 `ida-mcp/SKILL.md`，包含单次调用上限、场景步骤与示例。
- 本仓库**不**把 `.cursor/` 纳入版本控制，因此 skill 放在 `skills/` 下便于随仓库上传 GitHub；使用前需按上面步骤复制到 `.cursor/skills/`。
