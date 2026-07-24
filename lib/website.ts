import { WebsiteInfo } from '../types/analysis';

/**
 * Extracts basic website information like page title and favicon from raw HTML content.
 * @param url - The fully qualified URL of the website.
 * @param htmlContent - The raw HTML string of the webpage.
 * @returns A promise that resolves to WebsiteInfo containing parsed details.
 */
export async function getWebsiteInfo(url: string, htmlContent: string): Promise<WebsiteInfo> {
  const urlObj = new URL(url);
  
  let pageTitle = null;
  let favicon = null;
  
  // Basic regex to extract title
  const titleMatch = htmlContent.match(/<title[^>]*>([^<]+)<\/title>/i);
  if (titleMatch && titleMatch[1]) {
    pageTitle = titleMatch[1].trim();
  }
  
  // Basic regex to extract favicon
  const iconMatch = htmlContent.match(/<link[^>]*rel=["']?(?:shortcut )?icon["']?[^>]*href=["']?([^"'>\s]+)["']?[^>]*>/i);
  if (iconMatch && iconMatch[1]) {
    favicon = iconMatch[1].trim();
    if (favicon.startsWith('//')) {
      favicon = `${urlObj.protocol}${favicon}`;
    } else if (favicon.startsWith('/')) {
      favicon = `${urlObj.origin}${favicon}`;
    } else if (!favicon.startsWith('http')) {
      favicon = `${urlObj.origin}/${favicon}`;
    }
  } else {
    // default favicon
    favicon = `${urlObj.origin}/favicon.ico`;
  }
  
  return {
    pageTitle,
    domain: urlObj.hostname.replace(/^www\./, ''),
    hostname: urlObj.hostname,
    protocol: urlObj.protocol.replace(':', ''),
    ipAddress: null, // Will be filled by IPInfo service
    favicon,
  };
}
