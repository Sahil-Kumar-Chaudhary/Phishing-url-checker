import { SecurityRule } from '../../types/rules';
import { SecurityReport, RiskReason } from '../../types/analysis';

/**
 * The RuleEngine is responsible for orchestrating the SecurityRules.
 * It filters triggered rules, calculates the total risk score (capped at 100),
 * determines the final verdict, and translates the rules into the legacy
 * RiskReason format for frontend compatibility.
 */
export class RuleEngine {
  private rules: SecurityRule[] = [];

  /**
   * Registers a single rule or an array of rules into the engine.
   */
  public addRules(rules: SecurityRule | SecurityRule[]) {
    if (Array.isArray(rules)) {
      this.rules.push(...rules);
    } else {
      this.rules.push(rules);
    }
  }

  /**
   * Evaluates all registered rules and produces the final SecurityReport.
   */
  public evaluate(): SecurityReport {
    // 1. Filter only triggered rules
    const triggeredRules = this.rules.filter((rule) => rule.triggered);

    // 2. Calculate raw score
    let score = triggeredRules.reduce((total, rule) => total + rule.weight, 0);

    // 3. Cap score at 100
    score = Math.min(score, 100);

    // 4. Determine status verdict
    let status: 'safe' | 'suspicious' | 'phishing' = 'safe';
    if (score >= 60) {
      status = 'phishing';
    } else if (score >= 25) {
      status = 'suspicious';
    }

    // 5. Map triggered rules to legacy RiskReason format to preserve API compatibility
    const reasons: RiskReason[] = triggeredRules.map((rule) => {
      // Map severity to legacy UI type
      let type: 'negative' | 'positive' | 'neutral' = 'negative';
      if (rule.weight === 0 || rule.severity === 'Info') {
        type = 'neutral';
      }
      
      // If a rule specifically subtracts weight (not standard, but possible) or implies safety
      if (rule.id === 'TRUSTED_DOMAIN') {
        type = 'positive';
      }

      return {
        text: rule.description,
        type: type,
      };
    });

    // If perfectly clean, ensure a positive reason exists (replicating old behavior)
    if (score === 0 && triggeredRules.filter(r => r.id !== 'TRUSTED_DOMAIN').length === 0) {
      // Avoid duplicate clean messages if TRUSTED_DOMAIN already triggered
      if (!triggeredRules.some(r => r.id === 'TRUSTED_DOMAIN')) {
        reasons.push({ text: 'No suspicious indicators found. Domain appears clean.', type: 'positive' });
      }
    }

    return {
      score,
      status,
      reasons,
    };
  }
}
