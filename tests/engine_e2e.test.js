/**
 * End-to-End Stdin/Stdout Process Tests for Guardian Engine
 * Verifies IPC protocol, fail-closed behavior, and audit logging.
 */

'use strict';

const assert = require('assert');
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const { getRecentEntries } = require('../scripts/audit_logger');

const ENGINE_PATH = path.join(__dirname, '..', 'scripts', 'guardian_engine.js');
const TEST_WORKSPACE = path.resolve(__dirname, '..');

let passed = 0;
let failed = 0;

function runEngineWithInput(inputStr) {
  const res = spawnSync(process.execPath, [ENGINE_PATH], {
    input: inputStr,
    encoding: 'utf8',
    timeout: 3000
  });
  return {
    stdout: res.stdout,
    stderr: res.stderr,
    status: res.status
  };
}

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ PASS: ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ FAIL: ${name}`);
    console.error(`    Error: ${err.message}`);
    failed++;
  }
}

console.log('=== Running Guardian Engine Stdin/Stdout E2E Tests ===\n');

test('1. Valid inner-loop payload returns JSON allow', () => {
  const payload = {
    toolCall: {
      name: 'run_command',
      args: { CommandLine: 'git status' }
    },
    workspacePaths: [TEST_WORKSPACE],
    stepIdx: 5,
    conversationId: 'e2e-test-1'
  };

  const { stdout, status } = runEngineWithInput(JSON.stringify(payload));
  assert.strictEqual(status, 0);
  const parsed = JSON.parse(stdout);
  assert.strictEqual(parsed.decision, 'allow');
  assert(parsed.reason.includes('auto-approved'));
});

test('2. Destructive command returns JSON deny / force_ask', () => {
  const payload = {
    toolCall: {
      name: 'run_command',
      args: { CommandLine: 'Format-Volume -DriveLetter C' }
    },
    workspacePaths: [TEST_WORKSPACE],
    stepIdx: 6,
    conversationId: 'e2e-test-2'
  };

  const { stdout, status } = runEngineWithInput(JSON.stringify(payload));
  assert.strictEqual(status, 0);
  const parsed = JSON.parse(stdout);
  assert.strictEqual(parsed.decision, 'deny');
});

test('3. Corrupt non-JSON input fails-closed to ask', () => {
  const corruptInput = 'THIS IS NOT VALID JSON {{{{}}';
  const { stdout, status } = runEngineWithInput(corruptInput);
  assert.strictEqual(status, 0);
  const parsed = JSON.parse(stdout);
  assert.strictEqual(parsed.decision, 'ask');
  assert(parsed.reason.includes('fail-closed'));
});

test('4. Empty stdin input fails-closed to ask', () => {
  const { stdout, status } = runEngineWithInput('');
  assert.strictEqual(status, 0);
  const parsed = JSON.parse(stdout);
  assert.strictEqual(parsed.decision, 'ask');
  assert(parsed.reason.includes('fail-closed'));
});

test('5. Audit log correctly recorded recent decisions', () => {
  const entries = getRecentEntries(5);
  assert(entries.length > 0, 'Audit entries should exist');
  const latest = entries[0];
  assert(latest.timestamp, 'Entry should have timestamp');
  assert(latest.decision, 'Entry should have decision');
});

console.log(`\n=== E2E Test Results: ${passed} Passed, ${failed} Failed ===`);
if (failed > 0) process.exit(1);
