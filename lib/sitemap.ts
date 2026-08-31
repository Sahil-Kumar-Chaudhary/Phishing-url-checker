import { SitemapInfo } from '../types/analysis';
import { validateNetworkTarget, fetchWithValidation } from './security/networkValidation';

export async function getSitemapInfo(baseUrl: string): Promise<SitemapInfo> {
  const info: SitemapInfo = {
    hasRobotsTxt: false,
    hasSitemapXml: false,
    robotsTxtUrl: null,
    sitemapXmlUrl: null,
  };

  try {
    const urlObj = new URL(baseUrl);
    const origin = urlObj.origin;

    const robotsUrl = `${origin}/robots.txt`;
    const sitemapUrl = `${origin}/sitemap.xml`;

    const [robotsValidation, sitemapValidation] = await Promise.all([
      validateNetworkTarget(robotsUrl),
      validateNetworkTarget(sitemapUrl),
    ]);

    const [robotsRes, sitemapRes] = await Promise.all([
      robotsValidation.ok ? fetchWithValidation(robotsUrl, { method: 'HEAD' }).catch(() => null) : null,
      sitemapValidation.ok ? fetchWithValidation(sitemapUrl, { method: 'HEAD' }).catch(() => null) : null,
    ]);

    if (robotsRes && robotsRes.status === 200) {
      info.hasRobotsTxt = true;
      info.robotsTxtUrl = robotsUrl;
    }

    if (sitemapRes && sitemapRes.status === 200) {
      info.hasSitemapXml = true;
      info.sitemapXmlUrl = sitemapUrl;
    }

  } catch (error) {
    console.error('Error checking sitemap info:', error);
  }

  return info;
}
