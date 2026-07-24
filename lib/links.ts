import { LinksInfo } from '../types/analysis';

/**
 * Parses raw HTML to extract all internal and external HTTP/HTTPS links.
 * Ignores mailto:, javascript:, and tel: schemes.
 * @param url - The base URL used for resolving relative links.
 * @param htmlContent - The HTML string to parse for anchor tags.
 * @returns A promise resolving to an object containing arrays of internal and external links.
 */
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
