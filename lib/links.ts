import { LinksInfo } from '../types/analysis';

export async function getLinks(url: string, htmlContent: string): Promise<LinksInfo> {
  const internal = new Set<string>();
  const external = new Set<string>();

  try {
    const baseUrl = new URL(url);
    const regex = /<a[^>]+href=["']?([^"'>\s]+)["']?[^>]*>/gi;
    let match;

    while ((match = regex.exec(htmlContent)) !== null) {
      const link = match[1];
      
      // Ignore javascript:, mailto:, tel:, etc.
      if (link.startsWith('javascript:') || link.startsWith('mailto:') || link.startsWith('tel:')) {
        continue;
      }

      try {
        const linkUrl = new URL(link, baseUrl.href);
        // Only keep http and https
        if (linkUrl.protocol !== 'http:' && linkUrl.protocol !== 'https:') {
          continue;
        }

        if (linkUrl.hostname === baseUrl.hostname || linkUrl.hostname.endsWith(`.${baseUrl.hostname}`)) {
          internal.add(linkUrl.href);
        } else {
          external.add(linkUrl.href);
        }
      } catch (e) {
        // Invalid URL, ignore
      }
    }
  } catch (error) {
    console.error('Error extracting links:', error);
  }

  return {
    internal: Array.from(internal),
    external: Array.from(external),
  };
}
