export const ENDPOINTS = {
  REST_API_USERS: '/wp-json/wp/v2/users',
  AUTHOR_PREFIX: '/?author=',
  AUTHOR_1: '/?author=1',
  AUTHOR_2: '/?author=2',
  AUTHOR_3: '/?author=3',
  DEBUG_LOG: '/wp-content/debug.log',
  README: '/readme.html',
  XMLRPC: '/xmlrpc.php',
  WP_LOGIN: '/wp-login.php',
  WP_ADMIN: '/wp-admin/',
} as const;

export const CONSTANTS = {
  DEFAULT_PASSWORD_FILE: 'passwords.txt',
  DEFAULT_TARGET_URL: 'http://localhost:8080',
  DEFAULT_USER_AGENT: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  AUDITOR_USER_AGENT: 'Mastra-Security-Auditor/1.0',
} as const;

export const AGENT_MESSAGES = {
  SYSTEM_PROMPT: (targetUrl: string) =>
    `You are a WordPress security auditor on an authorized pentest of ${targetUrl}.\n\n` +
    `Call tools in this order:\n` +
    `1. inspectEndpoint: ${ENDPOINTS.REST_API_USERS}\n` +
    `2. If no users found: inspectEndpoint ${ENDPOINTS.AUTHOR_1}, ${ENDPOINTS.AUTHOR_2}, ${ENDPOINTS.AUTHOR_3}\n` +
    `3. inspectEndpoint: ${ENDPOINTS.DEBUG_LOG}\n` +
    `4. inspectEndpoint: ${ENDPOINTS.README}\n` +
    `5. probeXmlRpc with the best username found (or "admin")\n` +
    `6. bruteForceLogin ONCE with the admin or first discovered username\n\n` +
    `Do not repeat endpoints. Do not call bruteForceLogin more than once.\n` +
    `After all tools finish, write a 3-sentence executive risk summary.`,
  RATE_LIMIT_WARNING:
    '\n[!] Groq API quota or rate limit exceeded.\n' +
    '[!] The AI agent has hit free-tier rate limits. Proceeding with collected security telemetry.\n',
  RATE_LIMIT_SUMMARY:
    '[Security Executive Summary]\nAPI rate limit reached during automated synthesis. Inspection results collected above remain valid.',
  PARSE_ERROR_RECOVERY:
    '\n[AI Agent] Groq function-call parse error — recovering with collected results...',
  PARSE_ERROR_FALLBACK:
    '[Security Executive Summary]\nEnumeration loop finished. Please review detailed endpoint inspection findings above.',
} as const;

export const RECOMMENDATIONS = {
  REST_API: 'Restrict /wp-json/wp/v2/users access via custom theme filters (require authentication).',
  AUTHOR_WAF: 'Configure WAF rules to return HTTP 403 on ?author= query parameters.',
  DISABLE_XMLRPC: 'Disable or block xmlrpc.php at the web server level.',
  RESTRICT_DEBUG_LOG: 'Move or restrict access to /wp-content/debug.log.',
  COMPROMISED_PASSWORD: 'CRITICAL: Change the compromised password immediately.',
  ENFORCE_2FA: 'Enforce 2FA for all administrator accounts.',
  BRUTE_FORCE_PROTECTION: 'Deploy brute force protection (e.g. Wordfence, Fail2ban).',
  RATE_LIMIT_LOGIN: 'Implement rate limiting on wp-login.php.',
  STRONG_PASSWORDS: 'Use strong, unique passwords (minimum 16 characters).',
} as const;

export interface SecurityCheckDefinition {
  name: string;
  endpoint: string;
  description: string;
  remediationAdvice: string;
}

export const WORDPRESS_SECURITY_CHECKS: SecurityCheckDefinition[] = [
  {
    name: 'REST API User Directory Exposure',
    endpoint: ENDPOINTS.REST_API_USERS,
    description: 'Checks if unauthenticated users can view user directory objects via the REST API.',
    remediationAdvice: 'Apply rest_endpoints filter in functions.php to require authentication for /wp-json/wp/v2/users.',
  },
  {
    name: 'Author Query String Redirect',
    endpoint: ENDPOINTS.AUTHOR_1,
    description: 'Checks if direct author query parameter redirects reveal author user handles.',
    remediationAdvice: RECOMMENDATIONS.AUTHOR_WAF,
  },
  {
    name: 'XML-RPC Interface Exposure',
    endpoint: ENDPOINTS.XMLRPC,
    description: 'Checks if the legacy XML-RPC interface is publicly accessible.',
    remediationAdvice: RECOMMENDATIONS.DISABLE_XMLRPC,
  },
  {
    name: 'Exposed Debug Log File',
    endpoint: ENDPOINTS.DEBUG_LOG,
    description: 'Checks if PHP debug logs containing error details are publicly readable.',
    remediationAdvice: 'Set WP_DEBUG_LOG to a location outside the web root or restrict web server access.',
  },
  {
    name: 'Default Readme Documentation Exposure',
    endpoint: ENDPOINTS.README,
    description: 'Checks if the default installation readme file is accessible, exposing exact version info.',
    remediationAdvice: 'Remove readme.html from the web root directory after installation.',
  },
];
