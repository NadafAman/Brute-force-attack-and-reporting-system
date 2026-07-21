import { InspectionResult, TelemetryConfig } from './types.js';
import { ENDPOINTS, CONSTANTS } from './constants.js';

export class HTTPInspector {
  private config: TelemetryConfig;

  constructor(config: TelemetryConfig) {
    this.config = config;
  }

  get targetUrl(): string {
    return this.config.targetUrl;
  }

  /**
   * Safe fetch method with strict timeouts and error bounds.
   * Handles GET endpoints, JSON payload extraction, and redirect header parsing.
   */
  async inspectEndpoint(path: string): Promise<InspectionResult> {
    const fullUrl = new URL(path, this.config.targetUrl).toString();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const response = await fetch(fullUrl, {
        method: 'GET',
        signal: controller.signal,
        redirect: 'manual',
        headers: {
          'User-Agent': CONSTANTS.AUDITOR_USER_AGENT
        }
      });
      clearTimeout(timeoutId);

      const headersObj: Record<string, string> = {};
      response.headers.forEach((val, key) => {
        headersObj[key] = val;
      });

      const extractedUsers: string[] = [];

      // REST API user directory extraction
      if (response.status === 200) {
        try {
          const bodyText = await response.text();
          if (path.includes(ENDPOINTS.REST_API_USERS)) {
            const data = JSON.parse(bodyText);
            if (Array.isArray(data)) {
              for (const item of data) {
                if (item && typeof item === 'object' && item.slug) {
                  extractedUsers.push(String(item.slug));
                } else if (item && typeof item === 'object' && item.name) {
                  extractedUsers.push(String(item.name));
                }
              }
            }
          }

          // Debug log username extraction via PHP error messages
          if (path.includes('debug.log')) {
            const userMatches = [
              ...bodyText.matchAll(/login failed for ['"]?([a-zA-Z0-9_\-\.]+)['"]?/gi),
              ...bodyText.matchAll(/user[: ]+['"]?([a-zA-Z0-9_\-\.]+)['"]?.*not found/gi),
              ...bodyText.matchAll(/Invalid username[. ]*['"]([a-zA-Z0-9_\-\.]+)['"]/gi),
              ...bodyText.matchAll(/Username:?\s+['"]?([a-zA-Z0-9_\-\.]+)['"]/gi)
            ];
            for (const match of userMatches) {
              if (match[1]) extractedUsers.push(match[1]);
            }
          }
        } catch (err: any) {
          // Parse error or text read failure - telemetry continues cleanly
        }
      }

      // Author redirect header extraction
      if (path.includes('author=') && (response.status === 301 || response.status === 302)) {
        const location = headersObj['location'] || headersObj['Location'];
        if (location) {
          const match = location.match(/\/author\/([^\/]+)/);
          if (match && match[1]) {
            extractedUsers.push(match[1]);
          }
        }
      }

      const isExposed = response.status === 200 || extractedUsers.length > 0;
      const userSummary = extractedUsers.length > 0 ? ` [Discovered accounts: ${extractedUsers.join(', ')}]` : '';

      return {
        endpoint: path,
        statusCode: response.status,
        isPubliclyExposed: isExposed,
        rawHeaders: headersObj,
        findingsSummary: `Endpoint returned HTTP status ${response.status}${userSummary}`,
        extractedUsers: extractedUsers.length > 0 ? extractedUsers : undefined
      };
    } catch (error: any) {
      clearTimeout(timeoutId);
      return {
        endpoint: path,
        statusCode: 0,
        isPubliclyExposed: false,
        rawHeaders: {},
        findingsSummary: `Network check failed: ${error.message || 'Timeout'}`
      };
    }
  }

  /**
   * Probes the XML-RPC interface using a wp.getUsersBlogs multicall payload.
   * Detects whether the interface is accessible and if error messages leak usernames.
   */
  async probeXmlRpc(usernameToValidate: string = 'admin'): Promise<InspectionResult> {
    const fullUrl = new URL(ENDPOINTS.XMLRPC, this.config.targetUrl).toString();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);

    const xmlPayload = `<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>${usernameToValidate}</string></value>
        <value><string>invalidpassword</string></value>
      </data></array></value></member>
    </struct></value>
  </data></array></value></param></params>
</methodCall>`;

    try {
      const response = await fetch(fullUrl, {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'Content-Type': 'text/xml',
          'User-Agent': CONSTANTS.AUDITOR_USER_AGENT
        },
        body: xmlPayload
      });
      clearTimeout(timeoutId);

      const headersObj: Record<string, string> = {};
      response.headers.forEach((val, key) => { headersObj[key] = val; });

      const extractedUsers: string[] = [];
      let findingDetail = `XML-RPC probe returned HTTP ${response.status}`;

      if (response.status === 200) {
        try {
          const body = await response.text();

          if (body.includes('faultCode') && body.includes('403')) {
            extractedUsers.push(usernameToValidate);
            findingDetail = `XML-RPC multicall: user '${usernameToValidate}' confirmed via error code 403 (incorrect password, valid user)`;
          } else if (body.includes('faultCode') && body.includes('404')) {
            findingDetail = `XML-RPC multicall: user '${usernameToValidate}' not found (error 404)`;
          } else if (body.includes('<methodResponse>') && !body.includes('faultCode')) {
            findingDetail = `XML-RPC multicall: unexpected success response - interface is fully unauthenticated`;
          }
        } catch {
          findingDetail = `XML-RPC probe: could not read response body`;
        }
      }

      return {
        endpoint: `${ENDPOINTS.XMLRPC} [multicall probe]`,
        statusCode: response.status,
        isPubliclyExposed: response.status === 200,
        rawHeaders: headersObj,
        findingsSummary: findingDetail,
        extractedUsers: extractedUsers.length > 0 ? extractedUsers : undefined
      };
    } catch (error: any) {
      clearTimeout(timeoutId);
      return {
        endpoint: `${ENDPOINTS.XMLRPC} [multicall probe]`,
        statusCode: 0,
        isPubliclyExposed: false,
        rawHeaders: {},
        findingsSummary: `XML-RPC multicall probe failed: ${error.message || 'Timeout'}`
      };
    }
  }
}
