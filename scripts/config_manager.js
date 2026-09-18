/**
 * Guardian Configuration Manager
 * Manages operational modes and policy thresholds.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const DEFAULT_CONFIG = {
  mode: 'approve-for-me', // 'approve-for-me' | 'manual' | 'strict' | 'turbo'
  version: '1.0.0',
  allowTests: true,
  allowBuilds: true,
  allowWorkspaceWrites: true,
  blockNetworkPipes: true,
  blockSecretAccess: true,
  customAllowedPrefixes: [],
  customBlockedPatterns: []
};

function getConfigDir() {
  return path.join(os.homedir(), '.gemini', 'antigravity');
}

function getConfigPath() {
  return path.join(getConfigDir(), 'guardian.json');
}

function loadConfig() {
  const cfgPath = getConfigPath();
  try {
    if (fs.existsSync(cfgPath)) {
      const raw = fs.readFileSync(cfgPath, 'utf8');
      const parsed = JSON.parse(raw);
      return { ...DEFAULT_CONFIG, ...parsed };
    }
  } catch (err) {
    // If corrupt, fallback to defaults
  }
  return { ...DEFAULT_CONFIG };
}

function saveConfig(config) {
  const dir = getConfigDir();
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const cfgPath = getConfigPath();
  const merged = { ...DEFAULT_CONFIG, ...config };
  fs.writeFileSync(cfgPath, JSON.stringify(merged, null, 2), 'utf8');
  return merged;
}

function setMode(newMode) {
  const validModes = ['approve-for-me', 'manual', 'strict', 'turbo'];
  if (!validModes.includes(newMode)) {
    throw new Error(`Invalid mode '${newMode}'. Must be one of: ${validModes.join(', ')}`);
  }
  const cfg = loadConfig();
  cfg.mode = newMode;
  return saveConfig(cfg);
}

module.exports = {
  DEFAULT_CONFIG,
  getConfigPath,
  loadConfig,
  saveConfig,
  setMode
};
