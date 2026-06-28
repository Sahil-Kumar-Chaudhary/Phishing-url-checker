export function normalizeUrl(input: string): string {
  let url = input.trim();
  
  // Detect whether a protocol exists
  if (!/^https?:\/\//i.test(url)) {
    // Edge case: local environments usually run on http
    if (/^(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(url)) {
       url = 'http://' + url;
    } else {
       url = 'https://' + url;
    }
  }

  // Validate the resulting URL
  try {
    new URL(url);
    return url;
  } catch (e) {
    throw new Error('Invalid URL format');
  }
}

export async function resolveProtocol(url: string): Promise<string> {
  if (url.startsWith('http://')) return url;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000); // 4s timeout for quick fallback
    
    // Test if HTTPS is reachable
    await fetch(url, { method: 'HEAD', signal: controller.signal });
    clearTimeout(timeoutId);
    
    return url; // HTTPS works
  } catch (err) {
    // If fetch throws (SSL error, connection refused, DNS error, timeout), fallback to HTTP
    return url.replace('https://', 'http://');
  }
}
