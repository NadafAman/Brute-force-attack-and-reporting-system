export interface TelemetryConfig {
  targetUrl: string;
  timeoutMs: number;
}

export interface InspectionResult {
  endpoint: string;
  statusCode: number;
  isPubliclyExposed: boolean;
  rawHeaders: Record<string, string>;
  findingsSummary: string;
  extractedUsers?: string[];
}

export interface BruteForceSummary {
  username: string;
  attempts: number;
  successful: boolean;
  password?: string | null;
  needs_2fa?: boolean;
  attempts_per_second: number;
}

export interface AuditReportSchema {
  target: string;
  timestamp: string;
  techniquesUsed: string[];
  inspections: InspectionResult[];
  aiExecutiveSummary: string;
  defensiveRecommendations: string[];
  bruteForce?: BruteForceSummary;
}

/** A single discovered user with the endpoint that revealed them. */
export interface UserFinding {
  username: string;
  evidence: string;
}

/** The JSON shape written to disk — matches the assignment spec exactly. */
export interface JsonReportOutput {
  target: string;
  timestamp: string;
  techniques_used: string[];
  users: UserFinding[];
  ai_summary: string;
  brute_force?: BruteForceSummary;
}
