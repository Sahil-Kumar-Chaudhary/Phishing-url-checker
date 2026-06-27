import { SitemapInfo } from '../types/analysis';

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

    const [robotsRes, sitemapRes] = await Promise.all([
      fetch(robotsUrl, { method: 'HEAD' }).catch(() => null),
      fetch(sitemapUrl, { method: 'HEAD' }).catch(() => null),
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
