import { SecurityReport } from '../types/analysis';
import { RuleEngine } from './engine/RiskEngine';
import { evaluateUrlRules } from './rules/urlRules';
import { evaluateSslRules } from './rules/sslRules';
import { evaluateWhoisRules } from './rules/whoisRules';
import { evaluateRedirectRules } from './rules/redirectRules';
import { evaluateTrustedRules } from './rules/trustedRules';

/**
 * Orchestrates the Rule-Based Risk Engine.
 * Evaluates raw data through modular rule engines and computes the final SecurityReport.
 */
export function calculateRiskScore(
  fullUrl: string, 
  urlObj: URL, 
  ssl: any, 
  whois: any, 
  redirectChain: any[],
  htmlContent: string
): SecurityReport {
  const engine = new RuleEngine();

  // 1. Evaluate Trusted Domain Rules (Baseline)
  const trustedRules = evaluateTrustedRules(urlObj);
  engine.addRules(trustedRules);

  const isTrusted = trustedRules.some(r => r.id === 'TRUSTED_DOMAIN' && r.triggered);

  // 2. Evaluate Base URL & Crypto Rules (Always apply these)
  engine.addRules(evaluateSslRules(urlObj, ssl));
  
  // Rule mapping logic dictates we don't punish explicitly trusted domains for 
  // heuristic URL rules, but we always check them.
  if (!isTrusted) {
    engine.addRules(evaluateUrlRules(fullUrl, urlObj));
    engine.addRules(evaluateWhoisRules(whois));
  }

  // 3. Evaluate Advanced Features
  engine.addRules(evaluateRedirectRules(redirectChain));

  // 4. Compute Final Security Report
  return engine.evaluate();
}
