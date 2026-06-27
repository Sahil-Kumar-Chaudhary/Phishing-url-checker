import { AnalysisReport, SecurityReport, RiskReason } from '../types/analysis';
import { getWebsiteInfo } from './website';
import { getIpInfo } from './ipinfo';
import { getWhoisInfo } from './whois';
import { getDnsRecords } from './dns';
import { getSslInfo } from './ssl';
import { getHeaders } from './headers';
import { getCookies } from './cookies';
import { getRedirectChain } from './redirects';
import { getLinks } from './links';
import { getEmails } from './emails';
import { getPhones } from './phones';
import { getOpenPorts } from './ports';
import { getSitemapInfo } from './sitemap';

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'update', 'free', 'bank', 'secure', 'account', 
  'wallet', 'crypto', 'support', 'service', 'auth', 'confirm', 'paypal',
  'apple', 'microsoft', 'google', 'amazon', 'netflix', 'win', 'prize'
];

export async function analyzeUrl(inputUrl: string): Promise<AnalysisReport> {
  let urlToParse = inputUrl.trim();
  if (!/^https?:\/\//i.test(urlToParse)) {
    urlToParse = 'http://' + urlToParse;
  }

  const urlObj = new URL(urlToParse);
  const hostname = urlObj.hostname;
  const finalUrl = urlObj.href;

  // 1. Fetch HTML Content
  let htmlContent = '';
  try {
    const res = await fetch(finalUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard/1.0' },
      signal: AbortSignal.timeout(5000),
    });
    htmlContent = await res.text();
  } catch (e) {
    console.error('Failed to fetch HTML content:', e);
  }

  // 2. Run all services concurrently
  const [
    website,
    { ip, info: ipInfo },
    whois,
    dns,
    ssl,
    headers,
    cookies,
    redirectChain,
    links,
    emails,
    phones,
    ports,
    sitemap
  ] = await Promise.all([
    getWebsiteInfo(finalUrl, htmlContent),
    getIpInfo(hostname),
    getWhoisInfo(hostname),
    getDnsRecords(hostname),
    getSslInfo(hostname),
    getHeaders(finalUrl),
    getCookies(finalUrl),
    getRedirectChain(finalUrl),
    getLinks(finalUrl, htmlContent),
    getEmails(htmlContent),
    getPhones(htmlContent),
    getOpenPorts(hostname),
    getSitemapInfo(finalUrl),
  ]);

  website.ipAddress = ip;

  // 3. Calculate Risk Score and Security Report
  const security = calculateRiskScore(finalUrl, urlObj, ssl, whois, redirectChain, htmlContent);

  return {
    id: Math.random().toString(36).substring(2, 9),
    url: inputUrl,
    timestamp: Date.now(),
    website,
    ip: ipInfo,
    whois,
    dns,
    ssl,
    headers,
    cookies,
    redirectChain,
    links,
    emails,
    phones,
    ports,
    sitemap,
    security,
  };
}

function calculateRiskScore(
  fullUrl: string, 
  urlObj: URL, 
  ssl: any, 
  whois: any, 
  redirectChain: any[],
  htmlContent: string
): SecurityReport {
  let score = 0;
  const reasons: RiskReason[] = [];

  // 1. HTTPS Check
  if (urlObj.protocol !== 'https:') {
    score += 25;
    reasons.push({ text: 'Connection is not encrypted (HTTP instead of HTTPS)', type: 'negative' });
  } else {
    reasons.push({ text: 'Uses secure HTTPS connection', type: 'positive' });
  }

  // 2. IP Address Check
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  if (ipRegex.test(urlObj.hostname)) {
    score += 40;
    reasons.push({ text: 'Uses a raw IP address instead of a domain name', type: 'negative' });
  }

  // 3. Length Check
  if (fullUrl.length > 75) {
    score += 15;
    reasons.push({ text: 'URL is unusually long, often used to obscure the real destination', type: 'negative' });
  }

  // 4. Subdomain Check
  const domainParts = urlObj.hostname.split('.');
  if (domainParts.length > 3 && !ipRegex.test(urlObj.hostname)) {
    score += 20;
    reasons.push({ text: 'Contains multiple subdomains, a common phishing tactic', type: 'negative' });
  }

  // 5. Keyword Check
  const urlLower = fullUrl.toLowerCase();
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => urlLower.includes(kw));
  if (foundKeywords.length > 0) {
    score += foundKeywords.length * 15;
    reasons.push({ text: `Contains suspicious keywords: ${foundKeywords.join(', ')}`, type: 'negative' });
  }

  // 6. SSL Check
  if (urlObj.protocol === 'https:' && (!ssl.issuer || !ssl.validFrom)) {
    score += 30;
    reasons.push({ text: 'Invalid or missing SSL Certificate despite HTTPS', type: 'negative' });
  }

  // 7. Domain Age Check (Heuristic if whois is available)
  if (whois.registrationDate) {
    const ageInDays = (Date.now() - new Date(whois.registrationDate).getTime()) / (1000 * 60 * 60 * 24);
    if (ageInDays < 30) {
      score += 40;
      reasons.push({ text: 'Domain was registered very recently (less than 30 days ago)', type: 'negative' });
    } else {
      reasons.push({ text: `Domain has been registered for ${Math.floor(ageInDays)} days`, type: 'positive' });
    }
  }

  // 8. Redirects Check
  if (redirectChain.length > 2) {
    score += 20;
    reasons.push({ text: 'Multiple redirects detected, could be evading analysis', type: 'negative' });
  }

  score = Math.min(score, 100);

  let status: 'safe' | 'suspicious' | 'phishing' = 'safe';
  if (score >= 60) {
    status = 'phishing';
  } else if (score >= 25) {
    status = 'suspicious';
  }

  if (score === 0) {
    reasons.push({ text: 'No suspicious indicators found. Domain appears clean.', type: 'positive' });
  }

  return {
    score,
    status,
    reasons,
  };
}
