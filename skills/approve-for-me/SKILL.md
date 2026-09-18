---
name: approve-for-me
description: >-
  Manages the 'Approve for Me' (Auto-Review Guardian) mode for Google AntiGravity.
  Use to inspect status, switch approval modes (approve-for-me, manual, strict, turbo),
  simulate tool safety evaluations, and review audit logs.
argument-hint: "[status | mode <name> | test <cmd> | audit [-n <count>]]"
license: Apache-2.0
---

# 🛡️ Approve for Me (Auto-Review Guardian) Skill

The **Approve for Me** skill brings OpenAI Codex and ChatGPT Desktop's `auto_review` / `guardian_subagent` experience to Google AntiGravity.

It operates on one core principle:
> **"Don't bother me unless it's important."**

Routine workspace tasks (running tests, local builds, staging git changes, reading source files, editing workspace code) are automatically approved with zero clicks. Real threats (destructive deletions, secret credential exfiltration, out-of-bounds file writes, and system-level tampering) are intercepted and escalated for manual human confirmation.

---

## 🎯 When to Activate This Skill

Activate this skill when the user:
- Says *"approve for me"*, *"auto approve safe commands"*, or *"stop bugging me for routine commands"*
- Asks *"what mode is guardian in?"*, *"check guardian status"*, or *"show approval mode"*
- Requests to switch modes: *"switch to manual mode"*, *"switch to turbo mode"*, *"switch to strict mode"*
- Asks to simulate or test an action: *"can I run this safely?"*, *"test command <command>"*, or *"simulate approval"*
- Asks to inspect recent decisions: *"show audit log"*, *"why was my command blocked?"*, or *"guardian audit"*

---

## ⚙️ Operational Modes

| Mode | Behavior | Best Used For |
| :--- | :--- | :--- |
| **`approve-for-me`** | **Default**: Auto-approves safe inner-loop developer actions; escalates high-risk threats to human confirmation modal. | Daily development with maximum flow and zero confirmation fatigue. |
| **`manual`** | Traditional prompt mode: requires manual developer confirmation for every proposed tool action. | High-security audits, unknown codebases, or delicate production operations. |
| **`strict`** | Hard-blocks critical threats outright (`deny`), while prompting the developer for all other tool calls. | Untrusted workflows or strictly constrained sandboxes. |
| **`turbo`** | High-velocity mode: auto-approves all workspace reads, writes, and non-destructive shell commands. | Rapid prototyping in isolated temporary workspaces. |

---

## 🕹️ CLI Usage & Quick Reference

You can interact with Guardian through the bundled CLI tool:

```bash
# Check current mode, config paths, and approval telemetry
guardian status

# Switch operational mode immediately
guardian mode approve-for-me
guardian mode manual
guardian mode strict
guardian mode turbo

# Test and simulate a command before running it
guardian test "npm test"
guardian test "git push origin main --force"
guardian test "cat .env"

# Display the last N audit decisions
guardian audit -n 20
```

*Direct Node.js fallback:*
```bash
node plugins/antigravity-approve-for-me/scripts/guardian.js status
```

---

## 🔍 How the Safety Evaluation Engine Works

When a tool call is proposed (`run_command`, `write_to_file`, `replace_file_content`), the engine evaluates the payload in under 0.2ms across 5 security layers:

1. **Quote-Aware Shell Lexing**: Splits compound commands (`&&`, `||`, `;`, `|`), unmasks base64-encoded PowerShell payloads (`-EncodedCommand`, `-enc`), and identifies subexpression invocations (`$(...)`).
2. **Cmdlet & Parameter Normalization**: Expands dangerous PowerShell aliases (`del`, `rm`, `rd`, `iex`, `sc`) and flags abbreviated flags (`Remove-Item -r -fo`).
3. **Multi-Root Path Canonicalization**: Resolves relative paths, case-folds paths on Windows, and prevents directory traversal attacks (`../../`) escaping the workspace.
4. **Active Credential Protection**: Hard-blocks reads of active secrets (`.env`, `.env.production`, `.git/config`, `id_rsa`) while allowing benign template files (`.env.example`).
5. **System Denylist**: Permanently blocks disk formatting (`Format-Volume`), user account tampering (`net user`), and registry edits (`reg add`).

---

## 📁 File Locations & Configuration

- **Configuration File**: `~/.gemini/antigravity/guardian.json`
- **Audit Log Ledger**: `~/.gemini/antigravity/guardian_audit.jsonl`
- **Global Lifecycle Hook**: `~/.gemini/config/hooks.json`
- **Interactive UI Dashboard**: `ui/approve_for_me_dashboard.html`
