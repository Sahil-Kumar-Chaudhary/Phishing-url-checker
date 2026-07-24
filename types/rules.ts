export type RuleCategory = 'URL' | 'SSL' | 'WHOIS' | 'DNS' | 'Headers' | 'Cookies' | 'Redirects' | 'Website';
export type RuleSeverity = 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';

/**
 * Represents a single security detection rule that can trigger during analysis.
 */
export interface SecurityRule {
  id: string;
  title: string;
  description: string;
  recommendation?: string; // Actionable advice to fix the rule violation
  category: RuleCategory;
  severity: RuleSeverity;
  weight: number;      // Positive integer (added to risk score)
  triggered: boolean;  // True if the rule condition was met
}
