# Guardian Guidelines: Approve for Me Mode

When operating in **Approve for Me** mode:

1. **Inner-Loop Safety**:
   - Feel free to run routine tests (`npm test`, `pytest`, `cargo test`), builds (`npm run build`), linters, and diagnostics. The Guardian auto-approves these without prompting the user.
   - Maintain file edits strictly within the designated workspace boundaries.

2. **Respect Protected Boundaries**:
   - Never attempt to modify system directories (`C:\Windows`, `C:\Program Files`, `/etc`, etc.) or read sensitive credential files (`.env`, `id_rsa`, `.git/config`).
   - If an operation genuinely requires modifying an out-of-workspace file or running an elevated command, inform the user upfront that it will require manual confirmation.

3. **Avoid Destructive Shorthand**:
   - Prefer targeted, reversible commands over broad wildcards or recursive deletions (`rm -rf *`, `del /s /q`).
