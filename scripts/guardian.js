#!/usr/bin/env node
/**
 * Antigravity Guardian CLI Tool
 * Command-line manager for approval modes, audit logs, and test evaluations.
 */

'use strict';

const path = require('path');
const fs = require('fs');

// Dynamic resolution so guardian.js works from either bin/ or plugin scripts/
function resolveModule(name) {
  const local = path.join(__dirname, name);
  if (fs.existsSync(local + '.js')) return local;
  const scripts = path.join(__dirname, '..', 'scripts', name);
  if (fs.existsSync(scripts + '.js')) return scripts;
  const src = path.join(__dirname, '..', 'src', name);
  if (fs.existsSync(src + '.js')) return src;
  return local;
}

const { loadConfig, setMode, getConfigPath } = require(resolveModule('config_manager'));
const { getRecentEntries, getLogPath } = require(resolveModule('audit_logger'));
const { evaluateToolCall } = require(resolveModule('evaluator'));

const args = process.argv.slice(2);
const command = args[0] || 'status';

function printHeader() {
  console.log('\n🛡️  ANTIGRAVITY GUARDIAN: APPROVE FOR ME MANAGER');
  console.log('─────────────────────────────────────────────────');
}

function showStatus() {
  printHeader();
  const cfg = loadConfig();
  const recent = getRecentEntries(100);

  let approved = 0;
  let asked = 0;
  let denied = 0;

  for (const entry of recent) {
    if (entry.decision === 'allow') approved++;
    else if (entry.decision === 'deny') denied++;
    else asked++;
  }

  console.log(`Current Mode:           \x1b[1;32m${cfg.mode.toUpperCase()}\x1b[0m`);
  console.log(`Config File:            ${getConfigPath()}`);
  console.log(`Audit Log:              ${getLogPath()}`);
  console.log(`\nTelemetry Summary (Last ${recent.length} actions):`);
  console.log(`  ✓ Auto-Approved:      \x1b[32m${approved}\x1b[0m`);
  console.log(`  ❓ Escalated to User:  \x1b[33m${asked}\x1b[0m`);
  console.log(`  ⛔ Blocked Threats:    \x1b[31m${denied}\x1b[0m`);
  console.log('\nAvailable Modes:');
  console.log('  • approve-for-me  (Codex Auto-Review parity: "Don\'t bother me unless it\'s important")');
  console.log('  • manual          (Prompt user for every tool call)');
  console.log('  • strict          (Deny threats, prompt for everything else)');
  console.log('  • turbo           (Auto-approve all workspace actions with light checks)');
  console.log('\nUsage:');
  console.log('  guardian mode <mode-name>   Switch active approval mode');
  console.log('  guardian audit [-n 20]      View recent audit decisions');
  console.log('  guardian test "<command>"   Simulate Guardian evaluation\n');
}

function switchMode(newMode) {
  printHeader();
  if (!newMode) {
    console.error('Error: Please specify a mode: approve-for-me | manual | strict | turbo\n');
    process.exit(1);
  }

  try {
    const updated = setMode(newMode.toLowerCase());
    console.log(`✓ Approval Mode successfully switched to: \x1b[1;32m${updated.mode.toUpperCase()}\x1b[0m`);
    console.log(`Updated configuration in ${getConfigPath()}\n`);
  } catch (err) {
    console.error(`Error: ${err.message}\n`);
    process.exit(1);
  }
}

function showAudit(countArg) {
  printHeader();
  const count = parseInt(countArg || '20', 10) || 20;
  const entries = getRecentEntries(count);

  console.log(`Displaying last ${entries.length} audit entries:\n`);
  if (entries.length === 0) {
    console.log('No audit records found yet.');
    return;
  }

  for (const entry of entries) {
    const time = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : 'N/A';
    let badge = '\x1b[32m[ALLOW]\x1b[0m';
    if (entry.decision === 'deny') badge = '\x1b[31m[DENY ]\x1b[0m';
    else if (entry.decision === 'force_ask') badge = '\x1b[35m[F-ASK]\x1b[0m';
    else if (entry.decision === 'ask') badge = '\x1b[33m[ASK  ]\x1b[0m';

    const target = entry.commandLine || entry.targetFile || entry.toolName || 'Unknown';
    console.log(`${time} ${badge} (${entry.category || 'GENERAL'})`);
    console.log(`  Target: ${target}`);
    console.log(`  Reason: ${entry.reason}\n`);
  }
}

function testCommand(cmdLine) {
  printHeader();
  if (!cmdLine) {
    console.error('Error: Please specify a command to test, e.g.: guardian test "git status"\n');
    process.exit(1);
  }

  console.log(`Evaluating command: "${cmdLine}"\n`);
  const payload = {
    toolCall: {
      name: 'run_command',
      args: { CommandLine: cmdLine, Cwd: process.cwd() }
    },
    workspacePaths: [process.cwd()]
  };

  const res = evaluateToolCall(payload);

  let badge = '\x1b[1;32mALLOW (AUTO-APPROVE)\x1b[0m';
  if (res.decision === 'deny') badge = '\x1b[1;31mDENY (BLOCKED)\x1b[0m';
  else if (res.decision === 'force_ask') badge = '\x1b[1;35mFORCE_ASK (ESCALATE ALWAYS)\x1b[0m';
  else if (res.decision === 'ask') badge = '\x1b[1;33mASK (PROMPT USER)\x1b[0m';

  console.log(`Verdict:     ${badge}`);
  console.log(`Risk Score:  ${res.riskScore} / 100`);
  console.log(`Category:    ${res.category}`);
  console.log(`Rationale:   ${res.reason}\n`);
}

switch (command.toLowerCase()) {
  case 'status':
    showStatus();
    break;
  case 'mode':
  case 'set-mode':
    switchMode(args[1]);
    break;
  case 'audit':
  case 'log':
  case 'logs':
    showAudit(args[1] === '-n' ? args[2] : args[1]);
    break;
  case 'test':
  case 'eval':
    testCommand(args.slice(1).join(' '));
    break;
  case 'help':
  case '--help':
  case '-h':
    showStatus();
    break;
  default:
    console.error(`Unknown command: ${command}`);
    showStatus();
    break;
}
