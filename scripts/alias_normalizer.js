/**
 * PowerShell & Windows Cmdlet / Command Alias Normalizer
 * Maps shorthand aliases to canonical names to prevent evasive execution.
 */

'use strict';

const ALIAS_MAP = {
  // Destructive / File Deletion
  'rm': 'Remove-Item',
  'del': 'Remove-Item',
  'erase': 'Remove-Item',
  'rd': 'Remove-Item',
  'ri': 'Remove-Item',
  'rmdir': 'Remove-Item',

  // Mutation / Writing
  'sc': 'Set-Content',
  'ac': 'Add-Content',
  'clc': 'Clear-Content',
  'ni': 'New-Item',
  'md': 'mkdir',
  'cp': 'Copy-Item',
  'cpi': 'Copy-Item',
  'copy': 'Copy-Item',
  'mv': 'Move-Item',
  'mi': 'Move-Item',
  'move': 'Move-Item',
  'ren': 'Rename-Item',
  'rni': 'Rename-Item',

  // Reading / Output
  'gc': 'Get-Content',
  'cat': 'Get-Content',
  'type': 'Get-Content',
  'gci': 'Get-ChildItem',
  'ls': 'Get-ChildItem',
  'dir': 'Get-ChildItem',
  'gi': 'Get-Item',
  'gp': 'Get-ItemProperty',
  'gl': 'Get-Location',
  'pwd': 'Get-Location',
  'gcm': 'Get-Command',
  'gal': 'Get-Alias',
  'ghy': 'Get-History',
  'history': 'Get-History',
  'gps': 'Get-Process',
  'ps': 'Get-Process',
  'gsv': 'Get-Service',

  // Dynamic Execution
  'iex': 'Invoke-Expression',
  'icm': 'Invoke-Command',
  'saps': 'Start-Process',
  'start': 'Start-Process',

  // Networking / Web
  'iwr': 'Invoke-WebRequest',
  'curl': 'Invoke-WebRequest',
  'wget': 'Invoke-WebRequest',
  'irm': 'Invoke-RestMethod',

  // Process Kill
  'kill': 'Stop-Process',
  'spsv': 'Stop-Service',

  // Formatting & Selection
  'select': 'Select-Object',
  'where': 'Where-Object',
  'sort': 'Sort-Object',
  'measure': 'Measure-Object',
  'ft': 'Format-Table',
  'fl': 'Format-List',
  'sls': 'Select-String'
};

/**
 * Normalizes a command token to its canonical name if it is a known alias.
 * @param {string} token
 * @returns {string}
 */
function normalizeCommandToken(token) {
  if (!token || typeof token !== 'string') return '';
  // Strip trailing .exe if present (e.g. rm.exe)
  const clean = token.trim().toLowerCase().replace(/\.exe$/, '');
  return ALIAS_MAP[clean] || token;
}

module.exports = {
  ALIAS_MAP,
  normalizeCommandToken
};
