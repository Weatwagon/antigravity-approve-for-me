# 🛡️ Google AntiGravity Guardian: "Approve for Me"

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#-installation)
[![Tests](https://img.shields.io/badge/tests-41%2F41%20passing-success.svg)](tests/)

Bring OpenAI Codex / ChatGPT Desktop's beloved **"Approve for Me"** (`auto_review` / `guardian_subagent`) permission mode to **Google AntiGravity** (Desktop App, VS Code Extension, and IDE).

---

## 🎯 The Philosophy
> **"Don't bother me unless it's important."**

- **Auto-Approves**: Routine workspace developer tasks (`git status`, `npm test`, `pytest`, reading project files, compiling, and editing workspace code) with zero confirmation modals.
- **Escalates / Blocks**: Destructive deletions (`rm -rf /`, `del /s /q`), secret credential exfiltration (`cat .env`, `id_rsa`), out-of-bounds file writes, privilege escalation, and obfuscated payloads.

---

## 🚀 Quick Install (Windows 1-Click)

Run PowerShell in the cloned repository directory:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

**What the installer does:**
1. Backs up existing configs (`config.json.bak`, `hooks.json.bak`).
2. Deploys the plugin to `~/.gemini/config/plugins/antigravity-approve-for-me`.
3. Registers the global `PreToolUse` lifecycle hook in `~/.gemini/config/hooks.json`.
4. Sets eager auto-execution policy in `~/.gemini/config/config.json` using pure BOM-free UTF-8.
5. Installs the `guardian` CLI wrapper in `~/.gemini/antigravity/bin` and adds it to User `PATH`.

---

## 🎮 CLI Management Reference

The bundled `guardian` CLI lets you inspect telemetry, switch modes, and simulate command evaluation:

```bash
# Check current approval mode and telemetry
guardian status

# Switch operational mode
guardian mode approve-for-me   # Default: Codex auto-review mode
guardian mode manual          # Prompt for every tool action
guardian mode strict          # Deny threats, prompt for all others
guardian mode turbo           # Auto-approve all non-destructive workspace actions

# Test/simulate any command before running
guardian test "npm test"
guardian test "git push origin main --force"
guardian test "cat .env"

# View recent decision audit trail
guardian audit -n 20
```

---

## 🛡️ Threat Rules & Security Matrix

| Category | Filter Pattern / Check | Verdict | Rationale |
| :--- | :--- | :---: | :--- |
| **Safe Inner-Loop** | `npm test`, `pytest`, `git status`, `node`, `cargo check` | **ALLOW** | Routine local developer tasks auto-approved with zero clicks. |
| **Template Reads** | `cat .env.example`, `cat .env.sample` | **ALLOW** | Safe environment templates permitted. |
| **Active Secrets** | `cat .env`, `gc .env.production`, reading `id_rsa` | **FORCE_ASK** | Active credentials cannot be accessed without human confirmation. |
| **Git Destructive** | `git push --force`, `git reset --hard` | **FORCE_ASK** | Prevents unrecoverable loss of remote or local history. |
| **Recursive Deletes** | `rm -rf /`, `del /s /q`, `Remove-Item -r -fo` | **FORCE_ASK** | Prevents recursive directory wiping. |
| **System Tampering** | Disk formatting, registry edits, user creation | **DENY** | Hard-blocks operating system and user-account manipulation. |
| **Pipelined Execution** | `curl ... \| bash`, `iwr ... \| iex` | **FORCE_ASK** | Untrusted remote execution payloads halted. |
| **Obfuscated Payloads** | `-EncodedCommand`, base64 decode, dynamic invoke | **FORCE_ASK** | Obfuscated code patterns halted for human inspection. |
| **Out-of-Workspace** | Target path escapes workspace root | **DENY / ASK** | Agent cannot tamper with files outside active repository. |

---

## 🧪 Testing

Run the full automated adversarial and end-to-end test suite (41 tests):

```bash
npm test
```

Average evaluation latency: **&le; 0.2ms**.

---

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).
