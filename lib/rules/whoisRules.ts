import { SecurityRule } from '../../types/rules';
import { WhoisInfo } from '../../types/analysis';

export function evaluateWhoisRules(whois: WhoisInfo): SecurityRule[] {
  const rules: SecurityRule[] = [];

  // Rule: Domain Age
  let ageInDays = 9999;
  if (whois && whois.registrationDate) {
    ageInDays = (Date.now() - new Date(whois.registrationDate).getTime()) / (1000 * 60 * 60 * 24);
  }

  const isRecent = whois && whois.registrationDate ? ageInDays < 30 : false;

  rules.push({
    id: 'RECENT_DOMAIN',
    title: 'Recently Registered Domain',
    description: isRecent ? 'Domain was registered very recently (less than 30 days ago)' : `Domain has been registered for ${Math.floor(ageInDays)} days`,
    category: 'WHOIS',
    severity: 'High',
    weight: 40,
    triggered: isRecent
  });

  // Note: We don't trigger a rule if it's old, because we only want to ADD risk score. 
  // Wait, the legacy UI showed a positive reason if it was older than 30 days.
  // We can add a neutral rule for UI purposes.
  rules.push({
    id: 'ESTABLISHED_DOMAIN',
    title: 'Established Domain',
    description: `Domain has been registered for ${Math.floor(ageInDays)} days`,
    category: 'WHOIS',
    severity: 'Info',
    weight: 0,
    triggered: !isRecent && whois !== null && whois.registrationDate !== null
  });

  return rules;
}
