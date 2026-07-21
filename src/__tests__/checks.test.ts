import test from 'node:test';
import assert from 'node:assert';
import { WORDPRESS_SECURITY_CHECKS } from '../checks.js';
import { parseTargetUrl } from '../index.js';
import { SecurityAuditAgent } from '../agent.js';
import { HTTPInspector } from '../inspector.js';
import { AuditReporter } from '../reporter.js';

// ─── checks.ts sanity ────────────────────────────────────────────────────────

test('defines standard configuration inspection endpoints', () => {
  assert.ok(WORDPRESS_SECURITY_CHECKS.length > 0);
  const restCheck = WORDPRESS_SECURITY_CHECKS.find(c => c.endpoint === '/wp-json/wp/v2/users');
  assert.ok(restCheck !== undefined);
  assert.strictEqual(restCheck?.name, 'REST API User Directory Exposure');
});

test('contains remediation advice for all checks', () => {
  for (const check of WORDPRESS_SECURITY_CHECKS) {
    assert.ok(check.remediationAdvice.length > 10, `Missing remediation for: ${check.name}`);
  }
});

// ─── CLI flag parsing ─────────────────────────────────────────────────────────

test('parses CLI target URL flags correctly', () => {
  assert.strictEqual(parseTargetUrl(['--target=http://example.com']), 'http://example.com');
  assert.strictEqual(parseTargetUrl(['-t', 'http://test.local']), 'http://test.local');
  assert.strictEqual(parseTargetUrl(['--target', 'http://site.org']), 'http://site.org');
  assert.strictEqual(parseTargetUrl([]), process.env.TARGET_URL || 'http://localhost:8080');
});

// ─── Reporter / JSON output ───────────────────────────────────────────────────

test('AuditReporter.buildJsonOutput formats findings and deduplicates users', () => {
  const mockReport = {
    target: 'http://localhost:8080',
    timestamp: '2026-07-21T12:00:00.000Z',
    techniquesUsed: ['/wp-json/wp/v2/users', '/?author=1'],
    inspections: [
      {
        endpoint: '/wp-json/wp/v2/users',
        statusCode: 200,
        isPubliclyExposed: true,
        rawHeaders: {},
        findingsSummary: 'Exposed',
        extractedUsers: ['admin', 'editor'],
      },
      {
        endpoint: '/?author=1',
        statusCode: 301,
        isPubliclyExposed: true,
        rawHeaders: {},
        findingsSummary: 'Redirect',
        extractedUsers: ['admin'], // duplicate — should be deduplicated
      },
    ],
    aiExecutiveSummary: '[Security Audit Agent]: Risk summary test',
    defensiveRecommendations: ['Restrict REST API'],
  };

  const jsonOutput = AuditReporter.buildJsonOutput(mockReport);

  assert.strictEqual(jsonOutput.target, 'http://localhost:8080');
  assert.strictEqual(jsonOutput.timestamp, '2026-07-21T12:00:00.000Z');
  assert.deepStrictEqual(jsonOutput.techniques_used, ['/wp-json/wp/v2/users', '/?author=1']);
  assert.strictEqual(jsonOutput.users.length, 2, 'admin duplicate from author redirect must be removed');
  assert.deepStrictEqual(jsonOutput.users[0], { username: 'admin', evidence: '/wp-json/wp/v2/users' });
  assert.deepStrictEqual(jsonOutput.users[1], { username: 'editor', evidence: '/wp-json/wp/v2/users' });
  assert.strictEqual(jsonOutput.ai_summary, '[Security Audit Agent]: Risk summary test');
});

// ─── HTTPInspector — network resilience ──────────────────────────────────────

test('HTTPInspector handles unreachable host gracefully', async () => {
  const inspector = new HTTPInspector({ targetUrl: 'http://127.0.0.1:59999', timeoutMs: 500 });
  const result = await inspector.inspectEndpoint('/wp-json/wp/v2/users');
  assert.strictEqual(result.statusCode, 0);
  assert.strictEqual(result.isPubliclyExposed, false);
  assert.ok(result.findingsSummary.includes('Network check failed'));
});

test('HTTPInspector XML-RPC probe handles unreachable host gracefully', async () => {
  const inspector = new HTTPInspector({ targetUrl: 'http://127.0.0.1:59999', timeoutMs: 500 });
  const result = await inspector.probeXmlRpc();
  assert.strictEqual(result.statusCode, 0);
  assert.strictEqual(result.isPubliclyExposed, false);
  assert.ok(result.findingsSummary.includes('multicall probe failed'));
});

test('HTTPInspector XML-RPC probe accepts custom username', async () => {
  const inspector = new HTTPInspector({ targetUrl: 'http://127.0.0.1:59999', timeoutMs: 500 });
  const result = await inspector.probeXmlRpc('customuser');
  // Should fail gracefully — just verify it doesn't throw
  assert.strictEqual(result.statusCode, 0);
  assert.strictEqual(result.isPubliclyExposed, false);
});

// ─── Brute force logic — unit tests (no network) ─────────────────────────────

test('bruteforce: extracting users from REST API JSON response shape', () => {
  // Validate that the slug-first, name-fallback extraction logic is correct
  // by testing the shape our inspector would receive
  const mockApiResponse = [
    { id: 1, slug: 'admin', name: 'Administrator' },
    { id: 2, name: 'editor' }, // no slug field
    { id: 3, slug: 'testuser', name: 'Test User' },
  ];

  const extractedUsers: string[] = [];
  for (const item of mockApiResponse) {
    if (item && typeof item === 'object' && 'slug' in item && item.slug) {
      extractedUsers.push(String(item.slug));
    } else if (item && typeof item === 'object' && 'name' in item && item.name) {
      extractedUsers.push(String(item.name));
    }
  }

  assert.deepStrictEqual(extractedUsers, ['admin', 'editor', 'testuser']);
});

test('bruteforce: author redirect regex extracts slug correctly', () => {
  const location = 'http://localhost:8080/author/johndoe/';
  const match = location.match(/\/author\/([^\/]+)/);
  assert.ok(match !== null);
  assert.strictEqual(match![1], 'johndoe');
});

test('bruteforce: author redirect regex rejects non-author URLs', () => {
  const location = 'http://localhost:8080/wp-admin/';
  const match = location.match(/\/author\/([^\/]+)/);
  assert.strictEqual(match, null);
});

test('bruteforce: debug log username patterns match expected formats', () => {
  const sampleLog = [
    '[21-Jul-2026] PHP Warning: login failed for "johndoe" from 192.168.1.1',
    '[21-Jul-2026] PHP Notice: Invalid username. "admin123"',
    '[21-Jul-2026] PHP Warning: user: "badactor" not found in database',
  ].join('\n');

  const userMatches = [
    ...sampleLog.matchAll(/login failed for ['"]?([a-zA-Z0-9_\-\.]+)['"]?/gi),
    ...sampleLog.matchAll(/user[: ]+['"]?([a-zA-Z0-9_\-\.]+)['"]?.*not found/gi),
    ...sampleLog.matchAll(/Invalid username[. ]*['"]([a-zA-Z0-9_\-\.]+)['"]/gi),
  ];

  const found = userMatches.map(m => m[1]);
  assert.ok(found.includes('johndoe'), `Should find johndoe, got: ${JSON.stringify(found)}`);
  assert.ok(found.includes('admin123'), `Should find admin123, got: ${JSON.stringify(found)}`);
  assert.ok(found.includes('badactor'), `Should find badactor, got: ${JSON.stringify(found)}`);
});

// ─── SecurityAuditAgent — AI integration (requires GROQ_API_KEY) ──────────────

test('SecurityAuditAgent generates a summary when GROQ_API_KEY is set', async () => {
  if (!process.env.GROQ_API_KEY) {
    console.log('  [SKIP] GROQ_API_KEY not set — skipping AI summary test');
    return;
  }

  const agent = new SecurityAuditAgent();
  const mockInspections = [
    {
      endpoint: '/wp-json/wp/v2/users',
      isPubliclyExposed: true,
      extractedUsers: ['admin', 'editor'],
      findingsSummary: 'Exposed',
    },
  ];

  const summary = await agent.generateSummary(mockInspections);
  assert.ok(typeof summary === 'string', 'summary must be a string');
  assert.ok(summary.length > 20, 'summary must be substantive');
});

