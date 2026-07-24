/**
 * Computes the Shannon entropy of a given string.
 * High entropy indicates a random string, commonly used in phishing/DGA domains.
 */
export function calculateShannonEntropy(text: string): number {
  if (!text) return 0;
  
  const charMap: Record<string, number> = {};
  for (const char of text) {
    charMap[char] = (charMap[char] || 0) + 1;
  }
  
  let entropy = 0;
  const len = text.length;
  
  for (const char in charMap) {
    const p = charMap[char] / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}

/**
 * Calculates the percentage of numerical digits in a string.
 */
export function calculateDigitRatio(text: string): number {
  if (!text) return 0;
  const digits = text.replace(/[^0-9]/g, '').length;
  return digits / text.length;
}

/**
 * Detects possible homograph attacks by checking if a string mixes 
 * Cyrillic/Greek characters with standard Latin characters.
 */
export function detectHomograph(text: string): boolean {
  if (!text) return false;
  
  // Basic detection: If string has both Latin and (Cyrillic or Greek)
  const hasLatin = /[a-zA-Z]/.test(text);
  const hasCyrillic = /[\u0400-\u04FF]/.test(text);
  const hasGreek = /[\u0370-\u03FF]/.test(text);
  
  return hasLatin && (hasCyrillic || hasGreek);
}

/**
 * Detects presence of Unicode or invisible characters.
 */
export function hasUnicode(text: string): boolean {
  if (!text) return false;
  // If removing ascii characters leaves anything behind, it has unicode
  const nonAscii = text.replace(/[\x00-\x7F]/g, '');
  return nonAscii.length > 0;
}

/**
 * Detects 5 or more consecutive repeating characters (e.g., 'goooogle').
 */
export function detectRepetition(text: string): boolean {
  if (!text) return false;
  return /(.)\1{4,}/.test(text);
}

/**
 * Counts the depth of the URL path (number of folders).
 */
export function countPathDepth(pathname: string): number {
  if (!pathname || pathname === '/') return 0;
  const parts = pathname.split('/').filter(p => p.length > 0);
  return parts.length;
}

/**
 * Counts the number of URL encoded characters (e.g., %20, %3D) in a string.
 */
export function countEncodedCharacters(text: string): number {
  if (!text) return 0;
  const matches = text.match(/%[0-9A-Fa-f]{2}/g);
  return matches ? matches.length : 0;
}

/**
 * Detects if the hostname is an IPv4 or IPv6 address.
 */
export function isRawIpAddress(hostname: string): boolean {
  if (!hostname) return false;
  // Simple IPv4 regex
  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  // Simple IPv6 regex (basic, not fully RFC compliant but covers most raw IPs in URLs)
  const ipv6Regex = /^\[?[0-9a-fA-F:]+\]?$/;
  return ipv4Regex.test(hostname) || (ipv6Regex.test(hostname) && hostname.includes(':'));
}
