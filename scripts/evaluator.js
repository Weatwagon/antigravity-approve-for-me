/**
 * Core Guardian Evaluator
 * Multi-tiered risk analysis combining lexing, normalization, boundary checks,
 * secret scanning, and policy modes.
 */

'use strict';

const path = require('path');
const { splitCompoundCommands, detectObfuscation, checkSubexpressions, tokenize } = require('./shell_lexer');
const { normalizeCommandToken } = require('./alias_normalizer');
const { isWithinWorkspace, isProtectedSystemPath, canonicalizePath } = require('./path_normalizer');
const { isSecretTarget, scanCommandForSecrets } = require('./secret_scanner');
const { scanThreatRules, checkDeletionThreats, isSafeInnerLoopCommand } = require('./threat_rules');
const { loadConfig } = require('./config_manager');

/**
 * Evaluates a proposed tool execution against Guardian security policies.
 * @param {object} payload - Hook input payload
 * @returns {{ decision: 'allow'|'ask'|'force_ask'|'deny', reason: string, riskScore: number, category: string }}
 */
function evaluateToolCall(payload) {
  const config = loadConfig();
  const mode = config.mode || 'approve-for-me';

  const toolName = payload?.toolCall?.name;
  const toolArgs = payload?.toolCall?.args || {};
  const workspacePaths = payload?.workspacePaths || [];
  const cwd = toolArgs.Cwd || process.cwd();

  // 1. Policy Mode Override: Manual requires approval for everything
  if (mode === 'manual') {
    return {
      decision: 'ask',
      reason: 'Guardian is in Manual Mode: User confirmation required for all operations.',
      riskScore: 50,
      category: 'POLICY_MANUAL'
    };
  }

  // 2. Handle File-Writing Tools: write_to_file, replace_file_content
  if (toolName === 'write_to_file' || toolName === 'replace_file_content') {
    const targetFile = toolArgs.TargetFile;
    if (!targetFile) {
      return {
        decision: 'ask',
        reason: 'Missing target file in file modification tool',
        riskScore: 40,
        category: 'VALIDATION_ERROR'
      };
    }

    // Check protected system directories
    const sysCheck = isProtectedSystemPath(targetFile, cwd);
    if (sysCheck.isProtected) {
      return {
        decision: 'deny',
        reason: `Blocked: ${sysCheck.reason}`,
        riskScore: 100,
        category: 'SYSTEM_PROTECTION'
      };
    }

    // Check workspace containment
    const inWorkspace = isWithinWorkspace(targetFile, workspacePaths, cwd);
    if (!inWorkspace) {
      return {
        decision: 'ask',
        reason: `File modification target is outside workspace: ${targetFile}`,
        riskScore: 75,
        category: 'BOUNDARY_VIOLATION'
      };
    }

    // Check secret file targeting
    const secretCheck = isSecretTarget(targetFile);
    if (secretCheck.isSecret) {
      return {
        decision: 'force_ask',
        reason: `Sensitive file modification: ${secretCheck.reason}`,
        riskScore: 85,
        category: 'SECRET_PROTECTION'
      };
    }

    // Safe workspace file write
    if (mode === 'strict') {
      return {
        decision: 'ask',
        reason: 'Strict Mode: File writes require user confirmation.',
        riskScore: 30,
        category: 'POLICY_STRICT'
      };
    }

    return {
      decision: 'allow',
      reason: `Safe workspace file mutation auto-approved (${path.basename(targetFile)})`,
      riskScore: 10,
      category: 'SAFE_WORKSPACE_WRITE'
    };
  }

  // 3. Handle Terminal Execution: run_command
  if (toolName === 'run_command') {
    const cmdLine = toolArgs.CommandLine;
    if (!cmdLine || typeof cmdLine !== 'string' || !cmdLine.trim()) {
      return {
        decision: 'ask',
        reason: 'Empty or invalid CommandLine',
        riskScore: 30,
        category: 'VALIDATION_ERROR'
      };
    }

    // Layer 1: Obfuscation & Encoded Invocation Check
    const obfCheck = detectObfuscation(cmdLine);
    if (obfCheck.isObfuscated) {
      return {
        decision: 'force_ask',
        reason: `Obfuscation detected: ${obfCheck.reason}`,
        riskScore: 95,
        category: 'OBFUSCATION_ATTEMPT'
      };
    }

    // Layer 2: Subexpression / Subshell Check
    const subCheck = checkSubexpressions(cmdLine);
    if (subCheck.hasSubexpression) {
      return {
        decision: 'ask',
        reason: `Dynamic subexpression evaluation detected: ${subCheck.details}`,
        riskScore: 70,
        category: 'DYNAMIC_SUBEXPRESSION'
      };
    }

    // Layer 3: Secret Credential Access Check in Command Line
    const secretCmdCheck = scanCommandForSecrets(cmdLine);
    if (secretCmdCheck.touchesSecret) {
      return {
        decision: 'force_ask',
        reason: `Credential access detected: ${secretCmdCheck.reason}`,
        riskScore: 85,
        category: 'SECRET_ACCESS'
      };
    }

    // Layer 4: Global Threat Scan on Full Command Line (e.g. pipelined downloads, format, force-push)
    const globalThreat = scanThreatRules(cmdLine);
    if (globalThreat.isThreat) {
      return {
        decision: globalThreat.action || 'deny',
        reason: `Security Threat: ${globalThreat.threat}`,
        riskScore: 95,
        category: 'CRITICAL_THREAT'
      };
    }

    // Layer 5: Split Compound Commands (&&, ||, ;, |, &)
    const segments = splitCompoundCommands(cmdLine);
    if (segments.length === 0) {
      return {
        decision: 'ask',
        reason: 'Unable to parse command line segments',
        riskScore: 50,
        category: 'PARSE_AMBIGUITY'
      };
    }

    // Evaluate each atomic segment
    for (const seg of segments) {
      const rawCmd = seg.command;
      const tokens = tokenize(rawCmd);
      if (tokens.length === 0) continue;

      const rawHead = tokens[0];
      const canonicalHead = normalizeCommandToken(rawHead);

      // Threat Rule Scan (Registry, Net user, Format, Elevate, Force-push)
      const threatScan = scanThreatRules(rawCmd);
      if (threatScan.isThreat) {
        return {
          decision: threatScan.action || 'deny',
          reason: `Security Threat: ${threatScan.threat}`,
          riskScore: 95,
          category: 'CRITICAL_THREAT'
        };
      }

      // Deletion Threats (Remove-Item -Recurse, rm -rf, del /s)
      const delCheck = checkDeletionThreats(rawCmd, canonicalHead);
      if (delCheck.isDestructive) {
        return {
          decision: 'force_ask',
          reason: `Destructive Deletion: ${delCheck.threat}`,
          riskScore: 90,
          category: 'DESTRUCTIVE_COMMAND'
        };
      }

      // Path arguments check for protected system dirs or directory escape
      for (let i = 1; i < tokens.length; i++) {
        const token = tokens[i];
        // If token looks like a path or parameter containing path
        if (/[\\\/]/.test(token) || /^[a-zA-Z]:/i.test(token)) {
          const cleanPath = token.replace(/^["']|["']$/g, '').replace(/^-[a-zA-Z0-9]+:/i, '');
          const protCheck = isProtectedSystemPath(cleanPath, cwd);
          if (protCheck.isProtected) {
            return {
              decision: 'deny',
              reason: `Command targets protected system path: ${cleanPath}`,
              riskScore: 100,
              category: 'SYSTEM_PROTECTION'
            };
          }
        }
      }

      // Check if command is safe inner loop
      const isSafe = isSafeInnerLoopCommand(rawCmd, canonicalHead);

      // Safe git workspace actions (add, commit, status, branch, checkout, switch)
      const isSafeGit = /^git\s+(?:add|commit|checkout|switch|branch|stash|merge)\b/i.test(rawCmd) &&
                        !/--force|-f\b|--hard/i.test(rawCmd);

      if (!isSafe && !isSafeGit) {
        // Unknown or potentially state-modifying command
        if (mode === 'turbo') {
          // In turbo mode, allow non-destructive workspace operations
          continue;
        }

        return {
          decision: 'ask',
          reason: `Command '${rawHead}' requires confirmation: ${rawCmd}`,
          riskScore: 60,
          category: 'UNVERIFIED_COMMAND'
        };
      }
    }

    // All segments passed!
    if (mode === 'strict') {
      return {
        decision: 'ask',
        reason: 'Strict Mode: User confirmation required for all commands.',
        riskScore: 30,
        category: 'POLICY_STRICT'
      };
    }

    return {
      decision: 'allow',
      reason: 'Safe workspace developer command auto-approved',
      riskScore: 5,
      category: 'SAFE_INNER_LOOP'
    };
  }

  // 4. Default for other tools (read-only introspection)
  return {
    decision: 'allow',
    reason: `Standard tool '${toolName}' auto-approved`,
    riskScore: 5,
    category: 'DEFAULT_SAFE_TOOL'
  };
}

module.exports = {
  evaluateToolCall
};
