#!/usr/bin/env node
/**
 * Antigravity Guardian Engine
 * PreToolUse Lifecycle Hook Interceptor for 'Approve for Me' (Auto-Review)
 * Zero external dependencies, fail-closed posture, sub-30ms performance.
 */

'use strict';

const { evaluateToolCall } = require('./evaluator');
const { recordAudit } = require('./audit_logger');

// Fail-closed fallback response
function failClosed(reason) {
  return {
    decision: 'ask',
    reason: `Guardian fail-closed: ${reason || 'Unhandled evaluation fault'}`
  };
}

let inputBuffer = '';

process.stdin.setEncoding('utf8');

process.stdin.on('data', chunk => {
  inputBuffer += chunk;
});

process.stdin.on('end', () => {
  let response;
  let auditPayload;

  try {
    if (!inputBuffer || !inputBuffer.trim()) {
      response = failClosed('Empty hook payload on stdin');
    } else {
      const payload = JSON.parse(inputBuffer);
      const evalResult = evaluateToolCall(payload);

      response = {
        decision: evalResult.decision,
        reason: evalResult.reason
      };

      if (evalResult.decision === 'allow') {
        const overrides = [];
        const cmd = payload?.toolCall?.args?.CommandLine;
        if (cmd) {
          overrides.push(`command(${cmd})`);
          const head = cmd.trim().split(/[\s"']+/)[0];
          if (head && head !== cmd) overrides.push(`command(${head})`);
        }
        const targetFile = payload?.toolCall?.args?.TargetFile;
        if (targetFile) {
          overrides.push(`write_file(${targetFile})`);
        }
        response.permissionOverrides = overrides;
      }

      auditPayload = {
        toolName: payload?.toolCall?.name,
        commandLine: payload?.toolCall?.args?.CommandLine,
        targetFile: payload?.toolCall?.args?.TargetFile,
        decision: evalResult.decision,
        reason: evalResult.reason,
        riskScore: evalResult.riskScore,
        category: evalResult.category,
        stepIdx: payload?.stepIdx,
        conversationId: payload?.conversationId
      };
    }
  } catch (err) {
    // Fail-closed on ANY error or JSON parse exception
    response = failClosed(err?.message || 'Syntax parse error');
    auditPayload = {
      decision: 'ask',
      reason: response.reason,
      riskScore: 100,
      category: 'ENGINE_EXCEPTION'
    };
  }

  // Record audit trail
  try {
    if (auditPayload) {
      recordAudit(auditPayload);
    }
  } catch (auditErr) {
    // Non-fatal
  }

  // Write exact Antigravity hook response contract to stdout
  process.stdout.write(JSON.stringify(response));
  process.exit(0);
});

process.stdin.on('error', err => {
  process.stdout.write(JSON.stringify(failClosed(err.message)));
  process.exit(0);
});
