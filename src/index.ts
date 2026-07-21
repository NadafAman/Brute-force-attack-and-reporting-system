import { AuditReporter } from './reporter.js';
import { AuditReportSchema } from './types.js';
import { wpSecurityAgent } from './agent.js';

export function parseTargetUrl(args: string[] = process.argv.slice(2)): string {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--target=')) return arg.split('=')[1];
    if ((arg === '--target' || arg === '-t') && args[i + 1]) return args[i + 1];
  }
  return process.env.TARGET_URL || 'http://localhost:8080';
}

async function main() {
  const targetUrl = parseTargetUrl();
  console.log(`[+] Target: ${targetUrl}`);
  console.log(`[+] Starting WordPress user enumeration...\n`);

  const { results, techniquesUsed, summary, bruteForceResults } =
    await wpSecurityAgent.runEnumerationLoop(targetUrl);

  const bruteForceSummary = bruteForceResults
    ? {
        username: bruteForceResults.username,
        attempts: bruteForceResults.attempts,
        successful: bruteForceResults.successful,
        password: bruteForceResults.password ?? null,
        needs_2fa: bruteForceResults.needs2fa ?? false,
        attempts_per_second: bruteForceResults.attemptsPerSecond,
      }
    : undefined;

  const report: AuditReportSchema = {
    target: targetUrl,
    timestamp: new Date().toISOString(),
    techniquesUsed,
    inspections: results,
    aiExecutiveSummary: summary,
    defensiveRecommendations: [
      'Restrict /wp-json/wp/v2/users access via custom theme filters (require authentication).',
      'Configure WAF rules to return HTTP 403 on ?author= query parameters.',
      'Disable or block xmlrpc.php at the web server level.',
      'Move or restrict access to /wp-content/debug.log.',
      ...(bruteForceResults?.successful
        ? [
            'CRITICAL: Change the compromised password immediately.',
            'Enforce 2FA for all administrator accounts.',
            'Deploy brute force protection (e.g. Wordfence, Fail2ban).',
          ]
        : [
            'Implement rate limiting on wp-login.php.',
            'Use strong, unique passwords (minimum 16 characters).',
          ]),
    ],
    bruteForce: bruteForceSummary,
  };

  AuditReporter.formatConsoleOutput(report);

  if (bruteForceResults) {
    console.log(
      `\n🔐 Brute Force: ${bruteForceResults.successful ? '✅ SUCCESS' : '❌ FAILED'}`,
    );
    console.log(
      `   Attempts: ${bruteForceResults.attempts.toLocaleString()} | Speed: ${bruteForceResults.attemptsPerSecond.toFixed(1)} pwd/s`,
    );
    if (bruteForceResults.successful) {
      console.log(`   Password: ${bruteForceResults.password}`);
    }
    console.log('');
  }

  const jsonOutput = AuditReporter.buildJsonOutput(report);
  const reportFile = await AuditReporter.writeJsonReport(jsonOutput);
  console.log(`[✔] Enumeration complete.`);
  console.log(`[✔] Report → ${reportFile}`);
}

main().catch((err) => {
  console.error('[!] Fatal error:', err instanceof Error ? err.message : err);
  process.exit(1);
});