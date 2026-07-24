/**
 * Constants used across the application for phishing analysis.
 * Centralizing these values improves maintainability and ensures consistency.
 */

export const MAX_SAFE_URL_LENGTH = 75;
export const MAX_VERY_LONG_URL_LENGTH = 120;
export const MAX_SAFE_DOMAIN_LENGTH = 30;
export const MAX_SUBDOMAINS = 3;
export const MAX_PATH_DEPTH = 4;
export const MAX_QUERY_PARAMETERS = 4;
export const ENTROPY_THRESHOLD = 4.5;
export const HIGH_DIGIT_RATIO_THRESHOLD = 0.3; // 30%

export const SUSPICIOUS_TLDS = [
  '.zip', '.review', '.click', '.gq', '.cf', '.tk', '.ml', '.work', '.top', '.xyz'
];

export const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'rb.gy', 'ow.ly', 'cutt.ly', 'buff.ly'
];

export const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'update', 'free', 'bank', 'secure', 'account', 
  'wallet', 'crypto', 'support', 'service', 'auth', 'confirm', 'paypal',
  'apple', 'microsoft', 'google', 'amazon', 'netflix', 'win', 'prize'
];

export const BRAND_MAP: Record<string, string> = {
  'google': 'google.com',
  'apple': 'apple.com',
  'microsoft': 'microsoft.com',
  'amazon': 'amazon.com',
  'netflix': 'netflix.com',
  'paypal': 'paypal.com'
};

export const TRUSTED_DOMAINS = [
  'google.com', 'google.co.in', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
  'linkedin.com', 'apple.com', 'microsoft.com', 'github.com', 'amazon.com',
  'netflix.com', 'paypal.com', 'reddit.com', 'wikipedia.org', 'yahoo.com',
  'bing.com', 'duckduckgo.com', 'whatsapp.com', 'tiktok.com', 'twitch.tv',
  'adobe.com', 'zoom.us', 'canva.com', 'spotify.com', 'pinterest.com',
  'cloudflare.com', 'vimeo.com', 'wordpress.org', 'slack.com', 'medium.com',
  'dropbox.com', 'salesforce.com', 'tumblr.com', 'quora.com', 'stackoverflow.com',
  'gitlab.com', 'bitbucket.org', 'discord.com', 'openai.com', 'x.com', 't.co', 
  'gmail.com', 'outlook.live.com', 'office.com', 'yahoo.co.jp', 'baidu.com', 'yandex.ru'
];
