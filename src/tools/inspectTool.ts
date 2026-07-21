import { tool } from 'ai';
import { z } from 'zod';
import { HTTPInspector } from '../inspector.js';
import { bruteForceWordPressUser } from '../bruteforce.js';
import { ENDPOINTS, CONSTANTS } from '../constants.js';

/**
 * Probes any WordPress HTTP endpoint for status, headers, and extracted usernames.
 */
export const inspectEndpointTool = tool({
  description:
    'Inspect a WordPress HTTP endpoint. Returns status code and any extracted usernames. ' +
    `Use endpointPath values like: ${ENDPOINTS.REST_API_USERS}, ${ENDPOINTS.AUTHOR_1}, ${ENDPOINTS.AUTHOR_2}, ${ENDPOINTS.AUTHOR_3}, ` +
    `${ENDPOINTS.DEBUG_LOG}, ${ENDPOINTS.README}`,
  inputSchema: z.object({
    targetUrl: z.string().describe(`Base URL of the WordPress target, e.g. ${CONSTANTS.DEFAULT_TARGET_URL}`),
    endpointPath: z.string().describe(`Relative path to probe, e.g. ${ENDPOINTS.REST_API_USERS}`),
  }),
  execute: async ({ targetUrl, endpointPath }: { targetUrl: string; endpointPath: string }) => {
    const inspector = new HTTPInspector({ targetUrl, timeoutMs: 8000 });
    return inspector.inspectEndpoint(endpointPath);
  },
});

/**
 * Probes the XML-RPC interface. Uses error-code discrimination:
 * HTTP 403 faultCode = username exists. HTTP 404 faultCode = username not found.
 */
export const probeXmlRpcTool = tool({
  description:
    `Probe the WordPress XML-RPC interface at ${ENDPOINTS.XMLRPC}. ` +
    'Validates whether a username exists using error-code discrimination (403=exists, 404=not found). ' +
    'Always call this once. Pass the best known username or "admin" if none found yet.',
  inputSchema: z.object({
    targetUrl: z.string().describe('Base URL of the WordPress target'),
    usernameToValidate: z.string().describe('Username to validate, e.g. "admin"'),
  }),
  execute: async ({ targetUrl, usernameToValidate }: { targetUrl: string; usernameToValidate: string }) => {
    const inspector = new HTTPInspector({ targetUrl, timeoutMs: 8000 });
    return inspector.probeXmlRpc(usernameToValidate);
  },
});

/**
 * Brute-forces wp-login.php using passwords.txt wordlist.
 */
export const bruteForceLoginTool = tool({
  description:
    `Brute-force ${ENDPOINTS.WP_LOGIN} for a confirmed WordPress username. ` +
    'Call this ONCE using the admin or first discovered username.',
  inputSchema: z.object({
    targetUrl: z.string().describe('Base URL of the WordPress target'),
    username: z.string().describe('The confirmed username to brute-force'),
  }),
  execute: async ({ targetUrl, username }: { targetUrl: string; username: string }) => {
    return bruteForceWordPressUser(targetUrl, username, CONSTANTS.DEFAULT_PASSWORD_FILE, {
      workers: 10,
      delay: 0.05,
      timeout: 10000,
    });
  },
});
