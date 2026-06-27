import { RedirectInfo } from '../types/analysis';

export async function getRedirectChain(initialUrl: string): Promise<RedirectInfo[]> {
  const chain: RedirectInfo[] = [];
  let currentUrl = initialUrl;
  let redirects = 0;
  const maxRedirects = 10;

  try {
    while (redirects < maxRedirects) {
      const response = await fetch(currentUrl, {
        method: 'HEAD',
        redirect: 'manual',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard/1.0',
        },
      });

      chain.push({
        url: currentUrl,
        status: response.status,
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (location) {
          // Resolve relative URLs
          const nextUrl = new URL(location, currentUrl).toString();
          currentUrl = nextUrl;
          redirects++;
        } else {
          break;
        }
      } else {
        // Not a redirect
        break;
      }
    }
  } catch (error) {
    console.error('Error fetching redirect chain:', error);
    // If it failed on HEAD, it might still just be a 1-step chain or a network error.
    if (chain.length === 0) {
      chain.push({ url: currentUrl, status: 0 });
    }
  }

  return chain;
}
