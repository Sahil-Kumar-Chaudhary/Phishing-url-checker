export function normalizeUrl(input: string): string {
  let url = input.trim();

  if (!/^https?:\/\//i.test(url)) {
    if (/^(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(url)) {
      url = 'http://' + url;
    } else {
      url = 'https://' + url;
    }
  }

  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('Unsupported protocol');
    }
    return url;
  } catch {
    throw new Error('Invalid URL format');
  }
}

export async function resolveProtocol(url: string): Promise<string> {
  const validated = normalizeUrl(url);
  return validated.startsWith('https://') ? validated : validated.replace('http://', 'https://');
}
