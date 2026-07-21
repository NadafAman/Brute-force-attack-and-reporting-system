

export interface SecurityCheckDefinition {
  name: string;
  endpoint: string;
  description: string;
  remediationAdvice: string;
}

export const WORDPRESS_SECURITY_CHECKS: SecurityCheckDefinition[] = [
  {
    name: 'REST API User Directory Exposure',
    endpoint: '/wp-json/wp/v2/users',
    description: 'Checks if unauthenticated users can view user directory objects via the REST API.',
    remediationAdvice: 'Apply rest_endpoints filter in functions.php to require authentication for /wp-json/wp/v2/users.'
  },
  {
    name: 'Author Query String Redirect',
    endpoint: '/?author=1',
    description: 'Checks if direct author query parameter redirects reveal author user handles.',
    remediationAdvice: 'Add WAF rules or Nginx directives to block ?author= query parameters.'
  },
  {
    name: 'XML-RPC Interface Exposure',
    endpoint: '/xmlrpc.php',
    description: 'Checks if the legacy XML-RPC interface is publicly accessible.',
    remediationAdvice: 'Disable xmlrpc.php or block access via web server rules to avoid multi-call authentication vectors.'
  },
  {
    name: 'Exposed Debug Log File',
    endpoint: '/wp-content/debug.log',
    description: 'Checks if PHP debug logs containing error details are publicly readable.',
    remediationAdvice: 'Set WP_DEBUG_LOG to a location outside the web root or restrict web server access.'
  },
  {
    name: 'Default Readme Documentation Exposure',
    endpoint: '/readme.html',
    description: 'Checks if the default installation readme file is accessible, exposing exact version info.',
    remediationAdvice: 'Remove readme.html from the web root directory after installation.'
  }
];


