import { createOpenAI } from '@ai-sdk/openai';
import { generateText, isStepCount } from 'ai';
import { inspectEndpointTool, probeXmlRpcTool, bruteForceLoginTool } from './tools/inspectTool.js';
import { InspectionResult } from './types.js';
import { BruteForceResult } from './bruteforce.js';

export class SecurityAuditAgent {
  public readonly name = 'WordPress Security Auditor';

  private getGroqModel() {
    const groqKey = process.env.GROQ_API_KEY;
    if (!groqKey) {
      throw new Error('[SecurityAgent] GROQ_API_KEY is not set in .env file.');
    }
    const groq = createOpenAI({
      baseURL: 'https://api.groq.com/openai/v1',
      apiKey: groqKey.trim(),
    });
    return groq('llama-3.3-70b-versatile');
  }

  /** Public for test-level AI validation without running the full loop. */
  async generateSummary(
    inspections: Array<{ endpoint: string; isPubliclyExposed: boolean; extractedUsers?: string[]; findingsSummary: string }>,
  ): Promise<string> {
    const model = this.getGroqModel();
    const users = [...new Set(inspections.flatMap(i => i.extractedUsers ?? []))];
    const exposed = inspections.filter(i => i.isPubliclyExposed).map(i => i.endpoint);
    const prompt =
      `WordPress security audit summary (2-3 sentences).\n` +
      `Exposed endpoints: ${exposed.join(', ') || 'none'}\n` +
      `Discovered users: ${users.join(', ') || 'none'}`;
    const { text } = await generateText({ model, prompt });
    return `[AI Security Agent — Groq llama-3.3-70b]:\n${text.trim()}`;
  }

  /**
   * Runs a real multi-step agentic loop via Vercel AI SDK generateText.
   * The LLM receives each tool result and autonomously decides the next action.
   * Falls back to a standalone summary call if Groq's function-call parser fails mid-run.
   */
  async runEnumerationLoop(targetUrl: string): Promise<{
    results: InspectionResult[];
    techniquesUsed: string[];
    summary: string;
    bruteForceResults?: BruteForceResult;
  }> {
    const model = this.getGroqModel();
    const results: InspectionResult[] = [];
    const techniquesUsed: string[] = [];
    let bruteForceResults: BruteForceResult | undefined;

    console.log('\n[AI Agent] Starting agentic enumeration loop...');
    console.log('[AI Agent] Model: Groq llama-3.3-70b-versatile\n');

    const systemPrompt = `You are a WordPress security auditor on an authorized pentest of ${targetUrl}.

Call tools in this order:
1. inspectEndpoint: /wp-json/wp/v2/users
2. If no users found: inspectEndpoint /?author=1, /?author=2, /?author=3
3. inspectEndpoint: /wp-content/debug.log
4. inspectEndpoint: /readme.html
5. probeXmlRpc with the best username found (or "admin")
6. bruteForceLogin ONCE with the admin or first discovered username

Do not repeat endpoints. Do not call bruteForceLogin more than once.
After all tools finish, write a 3-sentence executive risk summary.`;

    let agentText = '';
    let agentSteps: any[] = [];

    try {
      const { text, steps } = await generateText({
        model,
        system: systemPrompt,
        prompt: `Start the WordPress security audit of ${targetUrl}.`,
        tools: {
          inspectEndpoint: inspectEndpointTool,
          probeXmlRpc: probeXmlRpcTool,
          bruteForceLogin: bruteForceLoginTool,
        },
        stopWhen: isStepCount(10),
        onStepFinish: (step: any) => {
          for (const tc of step.toolCalls ?? []) {
            const args = (tc.input ?? tc.args ?? {}) as Record<string, unknown>;
            const label =
              tc.toolName === 'inspectEndpoint'
                ? `→ inspectEndpoint: ${args['endpointPath']}`
                : tc.toolName === 'probeXmlRpc'
                ? `→ probeXmlRpc (username: ${args['usernameToValidate']})`
                : `→ bruteForceLogin (user: ${args['username']})`;
            console.log(`[AI Agent] ${label}`);
          }

          for (const tr of step.toolResults ?? []) {
            const r = (tr.output ?? tr.result) as Record<string, unknown>;
            if (!r) continue;
            const users = r['extractedUsers'] as string[] | undefined;
            if (users && users.length > 0) {
              console.log(`[+] Found users: ${users.join(', ')}`);
            } else if (r['statusCode'] !== undefined) {
              console.log(`[~] HTTP ${r['statusCode']} — ${r['endpoint'] ?? ''}`);
            }
            if (r['successful'] !== undefined) {
              console.log(
                r['successful']
                  ? `[+] Brute force SUCCESS — password: ${r['password']}`
                  : `[-] Brute force failed after ${r['attempts']} attempts`,
              );
            }
          }
        },
      });

      agentText = text;
      agentSteps = steps as any[];
    } catch (err: any) {
      const isGroqFunctionCallError =
        err?.message?.includes('Failed to call a function') ||
        err?.message?.includes('failed_generation') ||
        err?.errors?.some((e: any) => e?.message?.includes('Failed to call a function'));

      if (!isGroqFunctionCallError) throw err;

      console.log('\n[AI Agent] Groq function-call parse error — recovering with collected results...');
      agentSteps = err?.steps ?? [];
      agentText = await this.generateSummary(
        results.length > 0
          ? results.map(r => ({
              endpoint: r.endpoint,
              isPubliclyExposed: r.isPubliclyExposed,
              extractedUsers: r.extractedUsers,
              findingsSummary: r.findingsSummary,
            }))
          : [{ endpoint: targetUrl, isPubliclyExposed: false, findingsSummary: 'Enumeration incomplete due to API error' }],
      );
    }

    // ── Extract structured results from completed steps ───────────────────────
    for (const step of agentSteps) {
      for (const tc of step.toolCalls ?? []) {
        const matchingResult = (step.toolResults ?? []).find(
          (tr: any) => tr.toolCallId === tc.toolCallId,
        );
        if (!matchingResult) continue;

        const output = matchingResult.output ?? matchingResult.result;

        if (tc.toolName === 'inspectEndpoint' || tc.toolName === 'probeXmlRpc') {
          results.push(output as InspectionResult);
          const args = (tc.input ?? tc.args ?? {}) as Record<string, unknown>;
          techniquesUsed.push(
            tc.toolName === 'probeXmlRpc'
              ? 'XML-RPC Multicall Probe'
              : String(args['endpointPath'] ?? 'unknown'),
          );
        } else if (tc.toolName === 'bruteForceLogin') {
          bruteForceResults = output as BruteForceResult;
          techniquesUsed.push('Brute Force (wp-login.php)');
        }
      }
    }

    const summary = agentText.startsWith('[AI Security Agent')
      ? agentText
      : `[AI Security Agent — Groq llama-3.3-70b]:\n${agentText.trim()}`;

    return { results, techniquesUsed, summary, bruteForceResults };
  }
}

export const wpSecurityAgent = new SecurityAuditAgent();