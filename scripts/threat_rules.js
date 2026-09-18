/**
 * Threat Rules & Policy Evaluator
 * Comprehensive pattern matching for destructive commands, privilege escalation,
 * parameter abbreviations (e.g. -r, -fo), and safe inner-loop whitelists.
 */

'use strict';

// 1. Critical destructive patterns (Hard Deny or Force Ask)
const DESTRUCTIVE_PATTERNS = [
  // Disk / Volume Formatting
  {
    regex: /\b(format-volume|diskpart|format\s+[a-z]:)\b/i,
    threat: 'Disk or filesystem volume formatting attempt',
    action: 'deny'
  },
  // Windows Registry Mutation
  {
    regex: /\breg(?:\.exe)?\s+(?:add|delete|copy|restore|import)\b/i,
    threat: 'Windows registry modification attempt',
    action: 'deny'
  },
  // User Account & Group Escalation
  {
    regex: /\bnet(?:\.exe)?\s+(?:user|localgroup|group)\s+.*(?:\/add|\/delete|\/active)/i,
    threat: 'User account or security group manipulation',
    action: 'deny'
  },
  // Windows Elevation & UAC Bypass
  {
    regex: /\b(elevate(?:\.exe)?|runas(?:\.exe)?|takeown(?:\.exe)?)\b/i,
    threat: 'Process privilege elevation / ownership takeover attempt',
    action: 'force_ask'
  },
  // Windows Service Tampering
  {
    regex: /\bsc(?:\.exe)?\s+(?:create|delete|config)\b/i,
    threat: 'Windows system service creation or modification',
    action: 'deny'
  },
  // Git Destructive Operations
  {
    regex: /\bgit\s+push\b.*(?:--force\b|-f\b)/i,
    threat: 'Force-pushing Git repository branch (can overwrite remote history)',
    action: 'force_ask'
  },
  {
    regex: /\bgit\s+reset\s+--hard\b/i,
    threat: 'Hard Git reset (destroys uncommitted and unstaged changes)',
    action: 'force_ask'
  },
  {
    regex: /\bgit\s+clean\s+-[a-zA-Z]*f[a-zA-Z]*x/i,
    threat: 'Destructive Git clean (removes untracked and gitignored files)',
    action: 'force_ask'
  },
  // Database Destructive Queries
  {
    regex: /\b(?:DROP\s+DATABASE|DROP\s+TABLE|TRUNCATE\s+TABLE)\b/i,
    threat: 'Destructive SQL database/table operation',
    action: 'force_ask'
  },
  // Suspicious Remote Pipeline Execution (curl | sh, iwr | iex)
  {
    regex: /(?:curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b.*\|\s*(?:bash|sh|cmd|powershell|pwsh|iex|invoke-expression)\b/i,
    threat: 'Remote script download piped directly to execution shell',
    action: 'force_ask'
  },
  // Living off the land downloaders
  {
    regex: /\b(certutil(?:\.exe)?\s+-urlcache|bitsadmin(?:\.exe)?\s+\/transfer)\b/i,
    threat: 'Suspicious system utility remote file download',
    action: 'force_ask'
  }
];

/**
 * Checks for recursive or force file deletion.
 * Accurately parses PowerShell abbreviations: -r, -rec, -recurse, -fo, -force, and CMD /s /q.
 * @param {string} cmdSegment
 * @param {string} canonicalCmd
 * @returns {{ isDestructive: boolean, threat?: string }}
 */
function checkDeletionThreats(cmdSegment, canonicalCmd) {
  const lower = cmdSegment.toLowerCase();

  // If canonical command is Remove-Item
  if (canonicalCmd === 'Remove-Item') {
    // Check for recursive deletion flag
    const hasRecurse = /\s-(?:r\b|rec\b|recurse\b)/i.test(cmdSegment);
    // Check for force flag
    const hasForce = /\s-(?:fo\b|force\b)/i.test(cmdSegment);

    // If deleting root drive or wildcards recursively
    if (hasRecurse && (/\s[a-z]:\\?(\s|$)/i.test(cmdSegment) || /\s[\/\\](\s|$)/.test(cmdSegment) || /\s\*(?:\.\*)?(\s|$)/.test(cmdSegment))) {
      return {
        isDestructive: true,
        threat: 'Recursive deletion of root directory or broad wildcard'
      };
    }

    if (hasRecurse || hasForce) {
      return {
        isDestructive: true,
        threat: `Remove-Item with recursive or force flags (${hasRecurse ? '-Recurse ' : ''}${hasForce ? '-Force' : ''})`
      };
    }
  }

  // Unix rm -rf / or rm -rf *
  if (/^rm\s+.*-[a-zA-Z]*r[a-zA-Z]*f/i.test(lower) || /^rmdir\s+.*\/s/i.test(lower) || /^del\s+.*\/s/i.test(lower)) {
    return {
      isDestructive: true,
      threat: 'Recursive file or directory deletion command'
    };
  }

  return { isDestructive: false };
}

// 2. Safe inner-loop command prefixes
const SAFE_INNER_LOOP_PREFIXES = new Set([
  // Version checks & environment queries
  'node -v', 'node --version',
  'npm -v', 'npm --version', 'npm list', 'npm ls',
  'npx --version',
  'python --version', 'python -v', 'python3 --version', 'python3 -v', 'pip list', 'pip --version',
  'cargo --version', 'cargo -v', 'rustc --version',
  'go version',
  'dotnet --version', 'dotnet --info',
  'git --version',
  'whoami', 'hostname', 'ver',

  // Git safe inspections
  'git status', 'git diff', 'git log', 'git show', 'git branch',
  'git tag', 'git remote', 'git rev-parse', 'git describe',
  'git config --get', 'git config --list', 'git stash list',

  // Build & test runners
  'npm test', 'npm run test', 'npm run build', 'npm run lint',
  'npm run check', 'npm run typecheck', 'npm run compile',
  'npx tsc', 'npx eslint', 'npx prettier',
  'pytest', 'python -m unittest', 'python -m pytest',
  'cargo test', 'cargo build', 'cargo check', 'cargo clippy',
  'go test', 'go build', 'go vet',
  'mvn test', 'mvn compile',
  'gradle test', 'gradle build',
  'dotnet test', 'dotnet build'
]);

// 3. Safe read-only PowerShell cmdlets
const SAFE_READ_CMDLETS = new Set([
  'Get-ChildItem', 'Get-Content', 'Get-Command', 'Get-Help',
  'Get-Process', 'Get-Service', 'Get-Location', 'Get-Item',
  'Get-ItemProperty', 'Get-ItemPropertyValue', 'Get-Member',
  'Get-Variable', 'Get-Alias', 'Get-History', 'Get-Module',
  'Get-Date', 'Get-Host', 'Get-PSDrive', 'Get-CimInstance',
  'Get-NetIPAddress', 'Get-NetTCPConnection', 'Get-NetAdapter',
  'Test-Path', 'Resolve-Path', 'Split-Path', 'Join-Path',
  'Select-String', 'Select-Object', 'Where-Object', 'Sort-Object',
  'Measure-Object', 'Format-Table', 'Format-List', 'Format-Wide',
  'Out-String', 'Out-Host', 'ConvertFrom-Json', 'ConvertTo-Json',
  'ConvertFrom-Csv', 'ConvertTo-Csv', 'Compare-Object'
]);

/**
 * Checks if an atomic command is a known safe inner-loop developer task.
 * @param {string} cmdSegment
 * @param {string} canonicalCmd
 * @returns {boolean}
 */
function isSafeInnerLoopCommand(cmdSegment, canonicalCmd) {
  const trimmed = cmdSegment.trim();
  const lower = trimmed.toLowerCase();

  // 1. Check if executable is a standard developer runtime or virtualenv executable
  // Matches python, python3, py, .venv\Scripts\python.exe, venv/bin/python, pip, node, etc.
  const rawFirstToken = lower.split(/[\s"']+/)[0].replace(/\\/g, '/');
  const exeBase = rawFirstToken.split('/').pop().replace(/\.exe$/, '');

  const DEV_RUNTIMES = new Set([
    'python', 'python3', 'py',
    'pip', 'pip3',
    'pytest',
    'node',
    'npm', 'npx', 'yarn', 'pnpm', 'bun',
    'sqlite3',
    'cargo', 'rustc', 'go', 'dotnet'
  ]);

  if (DEV_RUNTIMES.has(exeBase)) {
    return true;
  }

  // 2. Check prefix matches
  for (const prefix of SAFE_INNER_LOOP_PREFIXES) {
    if (lower === prefix || lower.startsWith(prefix + ' ') || lower.startsWith(prefix + '\t')) {
      return true;
    }
  }

  // 3. Check PowerShell safe read cmdlets
  if (SAFE_READ_CMDLETS.has(canonicalCmd)) {
    return true;
  }

  // 4. CMD read commands
  const firstWord = lower.split(/[\s"']+/)[0];
  if (['echo', 'dir', 'type', 'where', 'findstr', 'find', 'attrib', 'fc'].includes(firstWord)) {
    return true;
  }

  return false;
}

/**
 * Scans a command segment against destructive threat rules.
 * @param {string} cmdSegment
 * @returns {{ isThreat: boolean, threat?: string, action?: string }}
 */
function scanThreatRules(cmdSegment) {
  for (const rule of DESTRUCTIVE_PATTERNS) {
    if (rule.regex.test(cmdSegment)) {
      return {
        isThreat: true,
        threat: rule.threat,
        action: rule.action
      };
    }
  }
  return { isThreat: false };
}

module.exports = {
  DESTRUCTIVE_PATTERNS,
  checkDeletionThreats,
  isSafeInnerLoopCommand,
  scanThreatRules
};
