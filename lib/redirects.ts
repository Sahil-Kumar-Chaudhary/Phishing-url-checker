import { RedirectInfo } from '../types/analysis';
import { validateRedirectTarget, fetchWithValidation } from './security/networkValidation';

export async function getRedirectChain(initialUrl: string): Promise<RedirectInfo[]> {
  const chain: RedirectInfo[] = [];
  let currentUrl = initialUrl;
  let redirects = 0;
  const maxRedirects = 10;

  try {
    while (redirects < maxRedirects) {
      const response = await fetchWithValidation(currentUrl, {
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
          const redirectValidation = await validateRedirectTarget(currentUrl, location);
          if (!redirectValidation.ok) {
            chain.push({ url: location, status: 0 });
            break;
          }
          currentUrl = redirectValidation.url.toString();
          redirects++;
        } else {
          break;
        }
      } else {
        break;
      }
    }
  } catch (error) {
    console.error('Error fetching redirect chain:', error);
    if (chain.length === 0) {
      chain.push({ url: currentUrl, status: 0 });
    }
  }

  return chain;
}
