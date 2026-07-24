import { SecurityRule } from '../../types/rules';
import { TRUSTED_DOMAINS } from '../../utils/constants';

export function evaluateTrustedRules(urlObj: URL): SecurityRule[] {
  const rules: SecurityRule[] = [];

  const isTrusted = TRUSTED_DOMAINS.some(domain => 
    urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain)
  );

  rules.push({
    id: 'TRUSTED_DOMAIN',
    title: 'Trusted Domain',
    description: 'Domain is a well-known trusted website',
    category: 'Website',
    severity: 'Info',
    weight: 0,
    triggered: isTrusted
  });

  return rules;
}
