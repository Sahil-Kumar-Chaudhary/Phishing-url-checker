import { SecurityRule } from '../../types/rules';
import { RedirectInfo } from '../../types/analysis';

export function evaluateRedirectRules(redirectChain: RedirectInfo[]): SecurityRule[] {
  const rules: SecurityRule[] = [];

  const hasMultipleRedirects = redirectChain.length > 2;

  rules.push({
    id: 'MULTIPLE_REDIRECTS',
    title: 'Multiple Redirects',
    description: 'Multiple redirects detected, could be evading analysis',
    category: 'Redirects',
    severity: 'Medium',
    weight: 20,
    triggered: hasMultipleRedirects
  });

  return rules;
}
