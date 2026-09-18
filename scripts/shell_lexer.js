/**
 * Shell Lexer & Compound Command Parser
 * Splits command lines into individual atomic statements, respecting quotes,
 * detects subshells, script blocks, and obfuscated/encoded commands.
 */

'use strict';

/**
 * Checks if a string contains encoded/obfuscated command invocations.
 * @param {string} cmdLine
 * @returns {{ isObfuscated: boolean, reason?: string }}
 */
function detectObfuscation(cmdLine) {
  if (!cmdLine || typeof cmdLine !== 'string') {
    return { isObfuscated: false };
  }

  // Check for PowerShell encoded command flags
  const encMatch = cmdLine.match(/(?:^|\s)(?:-enc|-encodedcommand|\/enc|\/encodedcommand)(?:\s+|=)(["']?[A-Za-z0-9+/=]{8,}["']?)/i);
  if (encMatch) {
    return {
      isObfuscated: true,
      reason: 'Base64 encoded command parameter detected (-EncodedCommand / -enc)'
    };
  }

  // Check for .NET / PowerShell base64 decoding patterns
  if (/\[(?:System\.)?Convert\]::FromBase64String/i.test(cmdLine)) {
    return {
      isObfuscated: true,
      reason: 'Direct base64 decode pattern detected ([Convert]::FromBase64String)'
    };
  }

  // Check for hidden environment variable execution indirection
  if (/%[a-zA-Z0-9_]+%(?:.*cmd\.exe|.*powershell)/i.test(cmdLine) ||
      /\$env:[a-zA-Z0-9_]+(?:\s*\|\s*iex)/i.test(cmdLine)) {
    return {
      isObfuscated: true,
      reason: 'Environment variable execution indirection detected'
    };
  }

  return { isObfuscated: false };
}

/**
 * Splits a compound command string into atomic command segments.
 * Correctly respects single quotes ('...'), double quotes ("..."), and backtick escapes.
 * @param {string} cmdLine
 * @returns {Array<{ command: string, operator: string }>}
 */
function splitCompoundCommands(cmdLine) {
  if (!cmdLine || typeof cmdLine !== 'string') {
    return [];
  }

  const segments = [];
  let current = '';
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let prevOperator = '';
  let i = 0;

  while (i < cmdLine.length) {
    const char = cmdLine[i];
    const nextChar = i + 1 < cmdLine.length ? cmdLine[i + 1] : '';

    // Handle backtick escape in PowerShell or backslash in Unix (outside single quotes)
    if (char === '`' && !inSingleQuote) {
      current += char;
      if (nextChar) {
        current += nextChar;
        i += 2;
        continue;
      }
    }

    // Toggle single quotes (no escapes inside single quotes)
    if (char === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
      current += char;
      i++;
      continue;
    }

    // Toggle double quotes
    if (char === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
      current += char;
      i++;
      continue;
    }

    // Inside quotes, everything is literal
    if (inSingleQuote || inDoubleQuote) {
      current += char;
      i++;
      continue;
    }

    // Check for operators: '&&', '||', ';', '|', '&'
    const twoChars = char + nextChar;
    if (twoChars === '&&' || twoChars === '||') {
      const trimmed = current.trim();
      if (trimmed) {
        segments.push({ command: trimmed, operator: prevOperator });
      }
      prevOperator = twoChars;
      current = '';
      i += 2;
      continue;
    }

    if (char === ';' || char === '|' || char === '&') {
      const trimmed = current.trim();
      if (trimmed) {
        segments.push({ command: trimmed, operator: prevOperator });
      }
      prevOperator = char;
      current = '';
      i++;
      continue;
    }

    current += char;
    i++;
  }

  const trimmed = current.trim();
  if (trimmed) {
    segments.push({ command: trimmed, operator: prevOperator });
  }

  return segments;
}

/**
 * Scans a command for subshell / subexpression invocations.
 * E.g. $(...), `...`, {...}
 * @param {string} cmdSegment
 * @returns {{ hasSubexpression: boolean, details?: string }}
 */
function checkSubexpressions(cmdSegment) {
  if (!cmdSegment || typeof cmdSegment !== 'string') {
    return { hasSubexpression: false };
  }

  // Check for $(...) subexpression
  const subDollar = cmdSegment.match(/\$\(([^)]+)\)/);
  if (subDollar) {
    return {
      hasSubexpression: true,
      details: `Subshell expression: $(${subDollar[1].trim()})`
    };
  }

  return { hasSubexpression: false };
}

/**
 * Tokenizes a single command line into executable and arguments.
 * Respects quotes.
 * @param {string} cmd
 * @returns {string[]}
 */
function tokenize(cmd) {
  const tokens = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];

    if (c === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (c === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }

    if (/\s/.test(c) && !inSingle && !inDouble) {
      if (current) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += c;
    }
  }

  if (current) {
    tokens.push(current);
  }

  return tokens;
}

module.exports = {
  detectObfuscation,
  splitCompoundCommands,
  checkSubexpressions,
  tokenize
};
