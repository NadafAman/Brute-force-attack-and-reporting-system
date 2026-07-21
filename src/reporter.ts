import { writeFile } from 'node:fs/promises';
import { AuditReportSchema, JsonReportOutput, UserFinding } from './types.js';

export class AuditReporter {
  static formatConsoleOutput(report: AuditReportSchema): void {
    console.log('\n==================================================');
    console.log(`[+] Security Telemetry Report: ${report.target}`);
    console.log(`[+] Timestamp: ${report.timestamp}`);
    console.log('==================================================\n');

    for (const item of report.inspections) {
      const statusIcon = item.isPubliclyExposed ? '[!] EXPOSED' : '[✔] HARDENED';
      console.log(`${statusIcon} ${item.endpoint} (HTTP ${item.statusCode})`);
      console.log(`    Detail: ${item.findingsSummary}`);
    }

    console.log('\n--- AI Executive Summary ---');
    console.log(report.aiExecutiveSummary);

    console.log('\n--- Defensive Recommendations ---');
    for (const rec of report.defensiveRecommendations) {
      console.log(`- ${rec}`);
    }
    console.log('==================================================\n');
  }

  /**
   * Derives the assignment-spec JSON shape from the internal report.
   * Users are deduplicated; the first endpoint that revealed each username
   * is used as the evidence field.
   */
  static buildJsonOutput(report: AuditReportSchema): JsonReportOutput {
    const seen = new Map<string, string>(); // username → evidence endpoint

    for (const inspection of report.inspections) {
      if (!inspection.extractedUsers) continue;
      for (const username of inspection.extractedUsers) {
        if (!seen.has(username)) {
          seen.set(username, inspection.endpoint);
        }
      }
    }

    const users: UserFinding[] = Array.from(seen.entries()).map(
      ([username, evidence]) => ({ username, evidence })
    );

    return {
      target: report.target,
      timestamp: report.timestamp,
      techniques_used: report.techniquesUsed,
      users,
      ai_summary: report.aiExecutiveSummary,
      brute_force: report.bruteForce
    };
  }

  /**
   * Writes the JSON report to disk as report-<epoch>.json in the cwd.
   * Returns the resolved file path so main() can print it.
   */
  static async writeJsonReport(output: JsonReportOutput): Promise<string> {
    const filename = `report-${Date.now()}.json`;
    await writeFile(filename, JSON.stringify(output, null, 2), 'utf-8');
    return filename;
  }
}
