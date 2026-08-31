import { CookieInfo } from '../types/analysis';
import { fetchWithValidation } from './security/networkValidation';

export async function getCookies(url: string): Promise<CookieInfo[]> {
  const cookiesList: CookieInfo[] = [];

  try {
    const response = await fetchWithValidation(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard/1.0',
      },
    });

    const setCookieHeaders = response.headers.getSetCookie ? response.headers.getSetCookie() : [];
    
    // Fallback if getSetCookie is not available (e.g. some fetch polyfills)
    let rawCookies = setCookieHeaders;
    if (rawCookies.length === 0) {
      const singleHeader = response.headers.get('set-cookie');
      if (singleHeader) {
        // This splits multiple cookies if comma separated, but it's imperfect because dates contain commas.
        // Good enough for simple fallback.
        rawCookies = [singleHeader];
      }
    }

    rawCookies.forEach((cookieStr) => {
      const parts = cookieStr.split(';').map(p => p.trim());
      const [nameValue, ...attributes] = parts;
      
      const eqIdx = nameValue.indexOf('=');
      if (eqIdx === -1) return;
      
      const name = nameValue.substring(0, eqIdx);
      const value = nameValue.substring(eqIdx + 1);

      const cookieObj: CookieInfo = { name, value };

      attributes.forEach(attr => {
        const lowerAttr = attr.toLowerCase();
        if (lowerAttr.startsWith('domain=')) cookieObj.domain = attr.substring(7);
        else if (lowerAttr.startsWith('path=')) cookieObj.path = attr.substring(5);
        else if (lowerAttr.startsWith('expires=')) cookieObj.expires = attr.substring(8);
        else if (lowerAttr === 'httponly') cookieObj.httpOnly = true;
        else if (lowerAttr === 'secure') cookieObj.secure = true;
        else if (lowerAttr.startsWith('samesite=')) cookieObj.sameSite = attr.substring(9);
      });

      cookiesList.push(cookieObj);
    });

  } catch (error) {
    console.error('Error fetching cookies:', error);
  }

  return cookiesList;
}
