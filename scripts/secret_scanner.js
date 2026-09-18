/**
 * Secret & Sensitive Credential Scanner
 * Identifies active secret files while allowing benign templates.
 */

'use strict';

const path = require('path');

// Active secret filenames (case-insensitive)
const ACTIVE_SECRET_PATTERNS = [
  /^\.env(?:\.(?:local|prod|production|staging|dev|development|test))?$/i,
  /^\.npmrc$/i,
  /^\.git\/config$/i,
  /^(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)(?:\.pub)?$/i,
  /^(?:known_hosts|authorized_keys)$/i,
  /^(?:service[-_]account|credentials|client[-_]secrets|client_secret)[a-zA-Z0-9_\-]*\.json$/i,
  /^(?:secrets?|passwords?|keys?)\.(?:json|yml|yaml|txt|conf)$/i
];

// Benign template exemptions
const BENIGN_TEMPLATE_PATTERNS = [
  /^\.env\.(?:example|sample|template|defaults|dist)$/i,
  /^\.env\.schema$/i,
  /^package\.json$/i,
  /^package-lock\.json$/i,
  /^tsconfig.*\.json$/i,
  /^jsconfig.*\.json$/i
];

/**
 * Checks whether a given filename or relative path is an active secret.
 * @param {string} filePath
 * @returns {{ isSecret: boolean, reason?: string }}
 */
function isSecretTarget(filePath) {
  if (!filePath || typeof filePath !== 'string') {
    return { isSecret: false };
  }

  const base = path.basename(filePath).trim();

  // 1. First check if it matches a benign template
  for (const pattern of BENIGN_TEMPLATE_PATTERNS) {
    if (pattern.test(base)) {
      return { isSecret: false };
    }
  }

  // 2. Check normalized relative path for .git/config
  const normalized = filePath.replace(/\\/g, '/');
  if (/\.git\/config(?:\s|$)/i.test(normalized)) {
    return {
      isSecret: true,
      reason: 'Access to Git repository configuration (.git/config) containing authentication tokens'
    };
  }

  // 3. Check against active secret patterns
  for (const pattern of ACTIVE_SECRET_PATTERNS) {
    if (pattern.test(base)) {
      return {
        isSecret: true,
        reason: `Target is an active credential or secret file: ${base}`
      };
    }
  }

  return { isSecret: false };
}

/**
 * Scans a command line string for references to secret files.
 * @param {string} cmdLine
 * @returns {{ touchesSecret: boolean, reason?: string }}
 */
function scanCommandForSecrets(cmdLine) {
  if (!cmdLine || typeof cmdLine !== 'string') {
    return { touchesSecret: false };
  }

  // Look for .env references
  const envMatch = cmdLine.match(/(?:^|[\s"'\\])\.env(?:\.(?:local|prod|production|staging|dev|development))?(?:[\s"']|$)/i);
  if (envMatch) {
    // Check if it's actually .env.example
    if (/\.env\.(?:example|sample|template|defaults|dist)/i.test(cmdLine)) {
      return { touchesSecret: false };
    }
    return {
      touchesSecret: true,
      reason: 'Command references active environment secrets file (.env)'
    };
  }

  // Check for .git/config
  if (/\.git[\/\\]config/i.test(cmdLine)) {
    return {
      touchesSecret: true,
      reason: 'Command references Git configuration (.git/config)'
    };
  }

  // Check for private keys
  if (/(?:id_rsa|id_ed25519|id_ecdsa)/i.test(cmdLine)) {
    return {
      touchesSecret: true,
      reason: 'Command references SSH private key files'
    };
  }

  // Check for npm credentials (.npmrc)
  if (/\.npmrc/i.test(cmdLine)) {
    return {
      touchesSecret: true,
      reason: 'Command references NPM authentication configuration (.npmrc)'
    };
  }

  return { touchesSecret: false };
}

module.exports = {
  isSecretTarget,
  scanCommandForSecrets,
  BENIGN_TEMPLATE_PATTERNS,
  ACTIVE_SECRET_PATTERNS
};
