import { SecurityRule } from '../../types/rules';
import { 
  MAX_SAFE_URL_LENGTH, 
  MAX_VERY_LONG_URL_LENGTH, 
  MAX_SAFE_DOMAIN_LENGTH, 
  MAX_SUBDOMAINS, 
  MAX_PATH_DEPTH, 
  MAX_QUERY_PARAMETERS, 
  ENTROPY_THRESHOLD, 
  HIGH_DIGIT_RATIO_THRESHOLD, 
  SUSPICIOUS_TLDS, 
  URL_SHORTENERS, 
  SUSPICIOUS_KEYWORDS, 
  BRAND_MAP 
} from '../../utils/constants';

import {
  calculateShannonEntropy,
  calculateDigitRatio,
  detectHomograph,
  hasUnicode,
  detectRepetition,
  countPathDepth,
  countEncodedCharacters,
  isRawIpAddress
} from '../urlIntelligence';

/**
 * Evaluates a given URL across 19 static intelligence metrics.
 * 
 * @param fullUrl - The full raw URL string.
 * @param urlObj - The parsed URL object.
 * @returns Array of SecurityRule objects.
 */
export function evaluateUrlRules(fullUrl: string, urlObj: URL): SecurityRule[] {
  const rules: SecurityRule[] = [];
  const hostname = urlObj.hostname.toLowerCase();
  
  // 1. URL Length Intelligence
  if (fullUrl.length > MAX_VERY_LONG_URL_LENGTH) {
    rules.push({
      id: 'VERY_LONG_URL',
      title: 'Extremely Long URL',
      description: `URL is exceptionally long (${fullUrl.length} characters), commonly used to push malicious domains out of view on mobile screens.`,
      recommendation: 'Inspect the domain and path closely, as excess characters often obscure the true destination.',
      category: 'URL',
      severity: 'High',
      weight: 20,
      triggered: true
    });
  } else if (fullUrl.length > MAX_SAFE_URL_LENGTH) {
    rules.push({
      id: 'LONG_URL',
      title: 'Long URL',
      description: `URL length (${fullUrl.length} characters) is above average.`,
      recommendation: 'Review URL parameters to ensure they are legitimate.',
      category: 'URL',
      severity: 'Medium',
      weight: 10,
      triggered: true
    });
  } else {
    rules.push({
      id: 'SAFE_URL_LENGTH',
      title: 'Normal URL Length',
      description: `URL length (${fullUrl.length} characters) is well within safe limits.`,
      category: 'URL',
      severity: 'Info',
      weight: 0,
      triggered: true
    });
  }

  // 2. Domain Length
  if (hostname.length > MAX_SAFE_DOMAIN_LENGTH) {
    rules.push({
      id: 'LONG_DOMAIN',
      title: 'Unusually Long Domain',
      description: `The hostname (${hostname.length} chars) is longer than typical domains, a common trait in domain generation algorithms (DGA).`,
      recommendation: 'Verify if the domain name makes logical sense or looks randomly generated.',
      category: 'URL',
      severity: 'Medium',
      weight: 10,
      triggered: true
    });
  }

  // 3. Path Depth
  const pathDepth = countPathDepth(urlObj.pathname);
  if (pathDepth > MAX_PATH_DEPTH * 2) {
    rules.push({
      id: 'VERY_DEEP_PATH',
      title: 'Extremely Deep Directory Path',
      description: `URL contains ${pathDepth} nested folders, a tactic used to bury malicious payloads.`,
      recommendation: 'Analyze the file being requested at the end of the deep path.',
      category: 'URL',
      severity: 'High',
      weight: 15,
      triggered: true
    });
  } else if (pathDepth > MAX_PATH_DEPTH) {
    rules.push({
      id: 'DEEP_PATH',
      title: 'Deep Directory Path',
      description: `URL contains ${pathDepth} nested folders.`,
      recommendation: 'Review the path structure for suspicious nesting.',
      category: 'URL',
      severity: 'Low',
      weight: 5,
      triggered: true
    });
  }

  // 4. Subdomain Intelligence
  const isIp = isRawIpAddress(hostname);
  const domainParts = hostname.split('.');
  if (!isIp && domainParts.length > MAX_SUBDOMAINS) {
    rules.push({
      id: 'EXCESSIVE_SUBDOMAINS',
      title: 'Excessive Subdomains',
      description: `URL contains ${domainParts.length} domain parts, often used to spoof legitimate brands (e.g., login.apple.com.malicious.net).`,
      recommendation: 'Check the root domain (the last two parts) to identify the true owner.',
      category: 'URL',
      severity: 'High',
      weight: 20,
      triggered: true
    });
  } else if (!isIp) {
    rules.push({
      id: 'NORMAL_SUBDOMAIN',
      title: 'Normal Subdomain Count',
      description: 'Domain structure is standard.',
      category: 'URL',
      severity: 'Info',
      weight: 0,
      triggered: true
    });
  }

  // 5. Hyphen Analysis
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount > 2) {
    rules.push({
      id: 'MULTIPLE_HYPHENS',
      title: 'Multiple Hyphens in Domain',
      description: `Domain contains ${hyphenCount} hyphens, a common pattern in cheap phishing domains.`,
      recommendation: 'Look closely at the domain name for brand impersonation.',
      category: 'URL',
      severity: 'Medium',
      weight: 15,
      triggered: true
    });
  }

  // 6. Digit Ratio
  const digitRatio = calculateDigitRatio(hostname);
  if (digitRatio > HIGH_DIGIT_RATIO_THRESHOLD && !isIp) {
    rules.push({
      id: 'HIGH_DIGIT_RATIO',
      title: 'High Digit Ratio in Domain',
      description: `${Math.round(digitRatio * 100)}% of the domain consists of numbers, highly unusual for legitimate services.`,
      recommendation: 'Evaluate if this is a legitimate service that heavily uses numbers in its branding.',
      category: 'URL',
      severity: 'High',
      weight: 20,
      triggered: true
    });
  }

  // 7. Suspicious Keyword Analysis
  const urlLower = fullUrl.toLowerCase();
  SUSPICIOUS_KEYWORDS.forEach(kw => {
    if (urlLower.includes(kw)) {
      // Ignore if the keyword is actually the brand's own domain
      if (BRAND_MAP[kw] && (hostname === BRAND_MAP[kw] || hostname.endsWith('.' + BRAND_MAP[kw]))) {
        return;
      }
      rules.push({
        id: `KEYWORD_${kw.toUpperCase()}`,
        title: `Suspicious Keyword: '${kw}'`,
        description: `The URL contains the sensitive keyword '${kw}', often used to establish fake trust.`,
        recommendation: 'Verify if the root domain actually belongs to the service claiming this keyword.',
        category: 'URL',
        severity: 'High',
        weight: 15,
        triggered: true
      });
    }
  });

  // 8. Punycode Detection
  if (hostname.includes('xn--')) {
    rules.push({
      id: 'PUNYCODE_DOMAIN',
      title: 'Punycode Domain Detected',
      description: 'Domain uses Punycode (xn--), which can be used to spoof visual characters in homograph attacks.',
      recommendation: 'Decode the Punycode to see the actual Unicode representation and compare it to the expected brand.',
      category: 'URL',
      severity: 'High',
      weight: 30,
      triggered: true
    });
  }

  // 9. Unicode Analysis
  if (hasUnicode(fullUrl)) {
    rules.push({
      id: 'UNICODE_DOMAIN',
      title: 'Unicode Characters Detected',
      description: 'URL contains non-ASCII Unicode characters which can be used to bypass visual inspection.',
      recommendation: 'Check the decoded URL string for invisible characters or spoofed letters.',
      category: 'URL',
      severity: 'High',
      weight: 25,
      triggered: true
    });
  }

  // 10. Homograph Detection
  if (detectHomograph(fullUrl)) {
    rules.push({
      id: 'POSSIBLE_HOMOGRAPH_ATTACK',
      title: 'Possible Homograph Attack',
      description: 'The URL mixes distinct character scripts (e.g., Latin with Cyrillic) to visually spoof a legitimate domain.',
      recommendation: 'Do not trust the visual representation. This is almost certainly a malicious link.',
      category: 'URL',
      severity: 'Critical',
      weight: 40,
      triggered: true
    });
  }

  // 11. Encoded Characters
  const encodedCount = countEncodedCharacters(fullUrl);
  if (encodedCount > 10) {
    rules.push({
      id: 'HEAVILY_ENCODED_URL',
      title: 'Heavily Encoded URL',
      description: `URL contains ${encodedCount} URL-encoded sequences, often used to obfuscate malicious payloads.`,
      recommendation: 'Decode the URL string to inspect the true request being made.',
      category: 'URL',
      severity: 'Medium',
      weight: 15,
      triggered: true
    });
  }

  // 12. Shannon Entropy
  const hostEntropy = calculateShannonEntropy(hostname);
  if (hostEntropy > ENTROPY_THRESHOLD && !isIp) {
    rules.push({
      id: 'HIGH_ENTROPY_HOSTNAME',
      title: 'Randomized Hostname (High Entropy)',
      description: `Hostname exhibits high randomness (Entropy: ${hostEntropy.toFixed(2)}), typical of DGAs.`,
      recommendation: 'Treat the domain as highly suspicious unless it is a known CDN.',
      category: 'URL',
      severity: 'High',
      weight: 25,
      triggered: true
    });
  }

  const pathEntropy = calculateShannonEntropy(urlObj.pathname);
  if (pathEntropy > ENTROPY_THRESHOLD + 0.5) { // Paths naturally have slightly higher entropy
    rules.push({
      id: 'HIGH_ENTROPY_PATH',
      title: 'Randomized Path (High Entropy)',
      description: `URL Path exhibits high randomness (Entropy: ${pathEntropy.toFixed(2)}).`,
      recommendation: 'The path may contain an encrypted tracking token or a generated exploit payload.',
      category: 'URL',
      severity: 'Medium',
      weight: 10,
      triggered: true
    });
  }

  // 13. Suspicious TLD
  const tldMatch = hostname.match(/\.[a-z]+$/i);
  const tld = tldMatch ? tldMatch[0].toLowerCase() : '';
  if (SUSPICIOUS_TLDS.includes(tld)) {
    rules.push({
      id: 'SUSPICIOUS_TLD',
      title: 'Suspicious Top-Level Domain (TLD)',
      description: `Domain uses '${tld}', a TLD frequently abused by scammers due to low cost or weak registration checks.`,
      recommendation: 'Exercise extreme caution when interacting with domains on this TLD.',
      category: 'URL',
      severity: 'High',
      weight: 25,
      triggered: true
    });
  }

  // 14. Raw IP Address
  if (isIp) {
    rules.push({
      id: 'RAW_IP_ADDRESS',
      title: 'Raw IP Address Usage',
      description: 'Uses a raw IP address instead of a registered domain name, avoiding DNS blacklists.',
      recommendation: 'Legitimate services almost never require raw IP addresses for user navigation.',
      category: 'URL',
      severity: 'Critical',
      weight: 40,
      triggered: true
    });
  }

  // 15. URL Shortener Detection
  const isShortener = URL_SHORTENERS.some(shortener => hostname === shortener || hostname.endsWith(`.${shortener}`));
  if (isShortener) {
    rules.push({
      id: 'URL_SHORTENER',
      title: 'URL Shortener Detected',
      description: 'The URL uses a shortening service to hide the final destination.',
      recommendation: 'Use a URL un-shortener tool to reveal the true destination before clicking.',
      category: 'URL',
      severity: 'High',
      weight: 25,
      triggered: true
    });
  }

  // 16. Port Detection
  if (urlObj.port && urlObj.port !== '80' && urlObj.port !== '443') {
    rules.push({
      id: 'NON_STANDARD_PORT',
      title: 'Non-Standard Port Detected',
      description: `URL explicitly requests port ${urlObj.port}, which is highly unusual for web browsing.`,
      recommendation: 'Ensure the port requested is expected for this specific application.',
      category: 'URL',
      severity: 'Medium',
      weight: 15,
      triggered: true
    });
  }

  // 17. Fragment Analysis
  if (urlObj.hash && urlObj.hash.length > 50) {
    rules.push({
      id: 'LARGE_FRAGMENT',
      title: 'Unusually Large Fragment',
      description: 'URL contains a very large hash fragment, which can be used to pass payloads to client-side scripts without sending them to the server.',
      recommendation: 'Inspect the fragment payload for base64 encoded strings or javascript.',
      category: 'URL',
      severity: 'Medium',
      weight: 15,
      triggered: true
    });
  }

  // 18. Query Parameter Analysis
  const queryParamCount = Array.from(urlObj.searchParams.keys()).length;
  if (queryParamCount > MAX_QUERY_PARAMETERS) {
    rules.push({
      id: 'EXCESSIVE_QUERY_PARAMETERS',
      title: 'Excessive Query Parameters',
      description: `URL contains ${queryParamCount} parameters, which can be used to inject data or bypass filters.`,
      recommendation: 'Review the query parameters for malicious injection payloads.',
      category: 'URL',
      severity: 'Low',
      weight: 5,
      triggered: true
    });
  }

  // 19. Character Repetition
  if (detectRepetition(hostname)) {
    rules.push({
      id: 'REPEATED_CHARACTERS',
      title: 'Repeated Characters in Domain',
      description: 'Domain contains highly repetitive characters (e.g., goooogle), used to spoof brands or evade simple regex blocks.',
      recommendation: 'Verify the spelling of the brand name carefully.',
      category: 'URL',
      severity: 'Medium',
      weight: 15,
      triggered: true
    });
  }

  return rules;
}
