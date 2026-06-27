export async function getHeaders(url: string): Promise<Record<string, string>> {
  const headersObj: Record<string, string> = {};
  
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard/1.0',
      },
    });

    response.headers.forEach((value, key) => {
      headersObj[key] = value;
    });
  } catch (error) {
    console.error('Error fetching headers:', error);
  }

  return headersObj;
}
