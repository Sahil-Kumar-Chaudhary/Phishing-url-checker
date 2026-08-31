import { AnalysisReport } from '../types/analysis';
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
import { calculateRiskScore } from './scoring';
import { normalizeUrl } from '../utils/url';
import { NetworkValidationError, validateNetworkTarget, fetchWithValidation } from './security/networkValidation';

export async function analyzeUrl(inputUrl: string): Promise<AnalysisReport> {
  const urlToParse = normalizeUrl(inputUrl);

  const urlObj = new URL(urlToParse);
  const hostname = urlObj.hostname;
  const finalUrl = urlObj.href;

  const targetValidation = await validateNetworkTarget(finalUrl);
  if (!targetValidation.ok) {
    throw new NetworkValidationError(targetValidation);
  }

  // 1. Fetch HTML Content
  let htmlContent = '';
  try {
    const res = await fetchWithValidation(finalUrl, {
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
