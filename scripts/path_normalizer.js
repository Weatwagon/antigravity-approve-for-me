/**
 * Windows Path Canonicalizer & Multi-Root Boundary Check
 * Enforces strict workspace containment and detects directory traversal/junction bypasses.
 */

'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');

const IS_WINDOWS = process.platform === 'win32';

// Protected system directories (normalized lowercase on Windows)
const PROTECTED_PREFIXES = [
  'c:\\windows',
  'c:\\program files',
  'c:\\program files (x86)',
  'c:\\programdata',
  'c:\\recovery',
  'c:\\boot',
  '/etc',
  '/usr',
  '/bin',
  '/sbin',
  '/var',
  '/System',
  '/Library'
];

const USER_HOME = os.homedir();
const SENSITIVE_USER_DIRS = [
  path.join(USER_HOME, '.ssh'),
  path.join(USER_HOME, '.aws'),
  path.join(USER_HOME, '.docker'),
  path.join(USER_HOME, '.kube'),
  path.join(USER_HOME, '.gnupg'),
  path.join(USER_HOME, 'AppData', 'Local', 'Microsoft', 'Windows')
];

/**
 * Fully canonicalizes a path, resolving relative segments and symlinks/junctions where possible.
 * @param {string} inputPath
 * @param {string} [cwd]
 * @returns {string} Canonical normalized path
 */
function canonicalizePath(inputPath, cwd) {
  if (!inputPath || typeof inputPath !== 'string') return '';

  let resolved = inputPath;
  if (!path.isAbsolute(resolved)) {
    resolved = path.resolve(cwd || process.cwd(), resolved);
  } else {
    resolved = path.normalize(resolved);
  }

  // Attempt realpath resolution to defeat symlink/junction point redirection
  try {
    if (fs.existsSync(resolved)) {
      resolved = fs.realpathSync.native(resolved);
    } else {
      // If leaf does not exist, resolve existing parent
      let parent = path.dirname(resolved);
      let rest = path.basename(resolved);
      while (parent && parent !== path.dirname(parent) && !fs.existsSync(parent)) {
        rest = path.join(path.basename(parent), rest);
        parent = path.dirname(parent);
      }
      if (fs.existsSync(parent)) {
        const realParent = fs.realpathSync.native(parent);
        resolved = path.join(realParent, rest);
      }
    }
  } catch (e) {
    // Fallback to normalized path if realpath throws
  }

  return IS_WINDOWS ? resolved.toLowerCase() : resolved;
}

/**
 * Checks whether a target path is strictly contained within any declared workspace root.
 * @param {string} targetPath
 * @param {string[]} workspacePaths
 * @param {string} [cwd]
 * @returns {boolean}
 */
function isWithinWorkspace(targetPath, workspacePaths, cwd) {
  if (!targetPath || !workspacePaths || !Array.isArray(workspacePaths) || workspacePaths.length === 0) {
    return false;
  }

  const canonicalTarget = canonicalizePath(targetPath, cwd);

  for (const ws of workspacePaths) {
    if (!ws) continue;
    // Strip file:// prefix if present
    let cleanWs = ws;
    if (cleanWs.startsWith('file:///')) {
      cleanWs = decodeURIComponent(cleanWs.replace('file:///', ''));
    } else if (cleanWs.startsWith('file://')) {
      cleanWs = decodeURIComponent(cleanWs.replace('file://', ''));
    }

    const canonicalWs = canonicalizePath(cleanWs);
    if (!canonicalWs) continue;

    // Check exact match or subpath
    if (canonicalTarget === canonicalWs) {
      return true;
    }
    const relative = path.relative(canonicalWs, canonicalTarget);
    if (!relative.startsWith('..') && !path.isAbsolute(relative)) {
      return true;
    }
  }

  return false;
}

/**
 * Checks if a path targets sensitive system directories or user credential directories.
 * @param {string} targetPath
 * @param {string} [cwd]
 * @returns {{ isProtected: boolean, reason?: string }}
 */
function isProtectedSystemPath(targetPath, cwd) {
  if (!targetPath) return { isProtected: false };
  const canonical = canonicalizePath(targetPath, cwd);

  // Check system root drives
  if (/^[a-z]:\\?$/i.test(canonical) || canonical === '/') {
    return {
      isProtected: true,
      reason: `Target is a root drive / filesystem root: ${targetPath}`
    };
  }

  // Check OS protected prefixes
  for (const prefix of PROTECTED_PREFIXES) {
    const normPrefix = IS_WINDOWS ? prefix.toLowerCase() : prefix;
    if (canonical === normPrefix || canonical.startsWith(normPrefix + path.sep)) {
      return {
        isProtected: true,
        reason: `Target touches protected operating system directory: ${targetPath}`
      };
    }
  }

  // Check sensitive user directories (SSH, AWS, etc.)
  for (const sDir of SENSITIVE_USER_DIRS) {
    const normSDir = IS_WINDOWS ? sDir.toLowerCase() : sDir;
    if (canonical === normSDir || canonical.startsWith(normSDir + path.sep)) {
      return {
        isProtected: true,
        reason: `Target touches sensitive credential/system directory: ${targetPath}`
      };
    }
  }

  return { isProtected: false };
}

module.exports = {
  canonicalizePath,
  isWithinWorkspace,
  isProtectedSystemPath,
  IS_WINDOWS
};
