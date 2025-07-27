/**
 * @fileoverview Surge to QuantumultX rule converter with proper error handling
 * @version 1.0.0
 * @supported QuantumultX v1.0.8-build253+
 */

// Constants - because magic strings are for amateurs
const RULE_TYPES = Object.freeze({
  DOMAIN: 'host',
  'DOMAIN-SUFFIX': 'host-suffix',
  'DOMAIN-KEYWORD': 'host-keyword',
  'IP-CIDR': 'ip-cidr',
  'IP-CIDR6': 'ip6-cidr',
  'IP-ASN': 'ip-asn'
});

const DEFAULT_POLICY = 'proxy';
const LINE_ENDINGS = /\r?\n|\r/g;
const COMMENT_PREFIXES = ['#', '//', ';'];

/**
 * Parse URL parameters from fragment identifier
 * @param {string} url - URL with potential fragment parameters
 * @returns {Object} Parsed parameters object
 * @throws {Error} If URL parsing fails
 */
function parseUrlParameters(url) {
  if (!url || typeof url !== 'string') {
    return {};
  }

  const fragmentIndex = url.indexOf('#');
  if (fragmentIndex === -1) {
    return {};
  }

  const fragment = url.slice(fragmentIndex + 1);
  if (!fragment) {
    return {};
  }

  const params = {};
  const pairs = fragment.split('&');

  for (const pair of pairs) {
    if (!pair) continue;

    const equalsIndex = pair.indexOf('=');
    if (equalsIndex === -1) {
      // Handle key-only parameters
      params[decodeURIComponent(pair.trim())] = '';
      continue;
    }

    const key = decodeURIComponent(pair.slice(0, equalsIndex).trim());
    const value = decodeURIComponent(pair.slice(equalsIndex + 1).trim());
    
    if (key) {
      params[key] = value;
    }
  }

  return params;
}

/**
 * Check if a line should be ignored (empty or comment)
 * @param {string} line - Line to check
 * @returns {boolean} True if line should be ignored
 */
function shouldIgnoreLine(line) {
  if (!line) return true;
  
  return COMMENT_PREFIXES.some(prefix => line.startsWith(prefix));
}

/**
 * Process domain-set format line
 * @param {string} line - Input line
 * @param {string} policy - Policy to apply
 * @returns {string|null} Converted rule or null if invalid
 */
function processDomainSetLine(line, policy) {
  if (!line) return null;

  // Handle .example.com format (suffix match)
  if (line.startsWith('.')) {
    const domain = line.slice(1);
    if (!domain) {
      console.warn(`Invalid domain-set suffix rule: "${line}"`);
      return null;
    }
    return `host-suffix,${domain},${policy}`;
  }

  // Handle example.com format (exact match)
  return `host,${line},${policy}`;
}

/**
 * Process standard Surge rule format
 * @param {string} line - Input line
 * @param {string} policy - Policy to apply
 * @returns {string|null} Converted rule or null if invalid
 */
function processStandardRule(line, policy) {
  const parts = line.split(',');
  
  if (parts.length < 2) {
    console.warn(`Invalid rule format: "${line}" - expected at least 2 comma-separated parts`);
    return null;
  }

  const ruleType = parts[0].trim().toUpperCase();
  const target = parts[1].trim();

  if (!ruleType || !target) {
    console.warn(`Invalid rule format: "${line}" - empty rule type or target`);
    return null;
  }

  const quantumultType = RULE_TYPES[ruleType];
  if (!quantumultType) {
    console.warn(`Unsupported rule type: "${ruleType}" in line: "${line}"`);
    return null;
  }

  return `${quantumultType},${target},${policy}`;
}

/**
 * Convert Surge rules to QuantumultX format
 * @param {string} content - Raw rule content
 * @param {Object} options - Conversion options
 * @returns {Object} Conversion result with content and stats
 */
function convertRules(content, options = {}) {
  const { policy = DEFAULT_POLICY, useDomainSet = false } = options;
  
  if (!content || typeof content !== 'string') {
    throw new Error('Content must be a non-empty string');
  }

  const lines = content.split(LINE_ENDINGS);
  const convertedRules = [];
  const stats = {
    totalLines: lines.length,
    processedLines: 0,
    skippedLines: 0,
    errorLines: 0
  };

  for (const rawLine of lines) {
    const line = rawLine.trim();
    
    if (shouldIgnoreLine(line)) {
      stats.skippedLines++;
      continue;
    }

    let convertedRule;
    try {
      if (useDomainSet) {
        convertedRule = processDomainSetLine(line, policy);
      } else {
        convertedRule = processStandardRule(line, policy);
      }

      if (convertedRule) {
        convertedRules.push(convertedRule);
        stats.processedLines++;
      } else {
        stats.errorLines++;
      }
    } catch (error) {
      console.error(`Error processing line "${line}": ${error.message}`);
      stats.errorLines++;
    }
  }

  return {
    content: convertedRules.join('\n'),
    stats
  };
}

// Main execution - wrapped in try-catch because we're not savages
try {
  // Validate global objects exist
  if (typeof $resource === 'undefined') {
    throw new Error('$resource object not available');
  }

  if (typeof $done === 'undefined') {
    throw new Error('$done function not available');
  }

  // Parse parameters with proper error handling
  const params = parseUrlParameters($resource.link);
  const policy = params.policy || DEFAULT_POLICY;
  const useDomainSet = params['domain-set'] === 'true';

  // Convert rules
  const result = convertRules($resource.content, { policy, useDomainSet });

  // Log conversion statistics
  console.log(`Conversion complete: ${result.stats.processedLines} rules converted, ` +
              `${result.stats.skippedLines} lines skipped, ` +
              `${result.stats.errorLines} errors`);

  // Return result
  $done({ content: result.content });

} catch (error) {
  console.error(`Fatal error during rule conversion: ${error.message}`);
  $done({ 
    content: `# Error: ${error.message}\n# Original content preserved below\n${$resource.content || ''}` 
  });
}