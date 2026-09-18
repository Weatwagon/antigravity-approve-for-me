/**
 * Atomic JSONL Audit Logger & Rotation Manager
 * Records all Guardian evaluation decisions with rolling file rotation.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const MAX_LOG_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB

function getLogDir() {
  return path.join(os.homedir(), '.gemini', 'antigravity');
}

function getLogPath() {
  return path.join(getLogDir(), 'guardian_audit.jsonl');
}

function getBackupLogPath() {
  return path.join(getLogDir(), 'guardian_audit.jsonl.1');
}

/**
 * Checks log size and performs rolling rotation if necessary.
 */
function checkRotation() {
  const logFile = getLogPath();
  try {
    if (fs.existsSync(logFile)) {
      const stats = fs.statSync(logFile);
      if (stats.size >= MAX_LOG_SIZE_BYTES) {
        const backup = getBackupLogPath();
        if (fs.existsSync(backup)) {
          fs.unlinkSync(backup);
        }
        fs.renameSync(logFile, backup);
      }
    }
  } catch (err) {
    // Suppress rotation failure to avoid interrupting execution
  }
}

/**
 * Records an audit event atomically to guardian_audit.jsonl.
 * @param {object} event
 */
function recordAudit(event) {
  const dir = getLogDir();
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  checkRotation();

  const entry = {
    timestamp: new Date().toISOString(),
    ...event
  };

  const line = JSON.stringify(entry) + '\n';
  try {
    fs.appendFileSync(getLogPath(), line, 'utf8');
  } catch (err) {
    // Non-fatal, audit append error should not block decision
  }
}

/**
 * Reads the last N audit entries.
 * @param {number} [limit=20]
 * @returns {Array<object>}
 */
function getRecentEntries(limit = 20) {
  const logFile = getLogPath();
  if (!fs.existsSync(logFile)) {
    return [];
  }

  try {
    const raw = fs.readFileSync(logFile, 'utf8');
    const lines = raw.trim().split('\n').filter(Boolean);
    const slice = lines.slice(-limit);
    return slice.map(line => {
      try {
        return JSON.parse(line);
      } catch (e) {
        return null;
      }
    }).filter(Boolean).reverse();
  } catch (err) {
    return [];
  }
}

module.exports = {
  getLogPath,
  recordAudit,
  getRecentEntries
};
