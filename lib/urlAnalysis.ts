export interface HttpsAnalysis {
  protocol: string | null;
  encrypted: boolean;
  risk: number;
  severity: "Info" | "Low" | "Medium" | "High" | "Critical";
  description: string;
}

export interface HttpsAnalysisResult {
  https: HttpsAnalysis;
}

/**
 * Analyzes the submitted URL to determine its protocol (HTTP vs HTTPS)
 * and evaluates the associated security risks.
 * 
 * @param urlString - The raw URL string to analyze.
 * @returns A Promise that resolves to the HttpsAnalysisResult.
 */
export async function analyzeProtocol(urlString: string): Promise<HttpsAnalysisResult> {
  if (!urlString || typeof urlString !== 'string') {
    throw new Error("Invalid input: URL must be a non-empty string.");
  }

  let parsedUrl: URL;

  try {
    // Attempt to parse the URL. If it lacks a scheme, we default to http:// 
    // to allow parsing of the domain for analysis purposes.
    const urlToParse = urlString.includes("://") ? urlString : `http://${urlString}`;
    parsedUrl = new URL(urlToParse);
  } catch (error) {
    throw new Error("Invalid URL format provided.");
  }

  const protocol = parsedUrl.protocol.replace(":", "").toLowerCase();

  // Handle HTTPS protocol
  if (protocol === "https") {
    return {
      https: {
        protocol: "https",
        encrypted: true,
        risk: 0,
        severity: "Info",
        description: "The connection is encrypted using HTTPS. This protects data in transit but does not guarantee that the website is legitimate because phishing websites can also obtain valid SSL certificates."
      }
    };
  }

  // Handle HTTP protocol
  if (protocol === "http") {
    return {
      https: {
        protocol: "http",
        encrypted: false,
        risk: 5,
        severity: "Medium",
        description: "The connection uses unencrypted HTTP. Data sent to this site can be intercepted, and the lack of encryption is a potential security risk."
      }
    };
  }

  // Fallback for other protocols (e.g., ftp://, wss://)
  return {
    https: {
      protocol,
      encrypted: false,
      risk: 3, // Assigned a moderate risk for non-standard web protocols
      severity: "Low",
      description: `The URL uses the '${protocol}' protocol instead of HTTP or HTTPS. Ensure this is expected for your specific use case.`
    }
  };
}

export interface UrlLengthAnalysis {
  length: number;
  severity: "Safe" | "Low" | "Medium" | "High";
  risk: number;
  description: string;
}

export interface UrlLengthAnalysisResult {
  urlLength: UrlLengthAnalysis;
}

/**
 * Analyzes the length of the submitted URL.
 * Attackers often use excessively long URLs to hide the actual destination from users.
 * 
 * @param urlString - The raw URL string to analyze.
 * @returns A Promise that resolves to the UrlLengthAnalysisResult.
 */
export async function analyzeUrlLength(urlString: string): Promise<UrlLengthAnalysisResult> {
  if (!urlString || typeof urlString !== 'string') {
    throw new Error("Invalid input: URL must be a non-empty string.");
  }

  const length = urlString.length;
  let severity: "Safe" | "Low" | "Medium" | "High";
  let risk: number;
  let description: string;

  if (length < 50) {
    severity = "Safe";
    risk = 0;
    description = "The URL length is short and standard. It is unlikely to be used for obfuscating the true destination.";
  } else if (length <= 75) { // 50-75
    severity = "Low";
    risk = 5;
    description = "The URL length is moderately long. This is typical for URLs with query parameters.";
  } else if (length <= 120) { // 75-120
    severity = "Medium";
    risk = 10;
    description = "The URL is long. Attackers occasionally use this length to push suspicious domain components out of view on smaller screens.";
  } else { // >120
    severity = "High";
    risk = 20;
    description = "Long URLs are commonly used by phishing websites to hide the actual destination.";
  }

  return {
    urlLength: {
      length,
      severity,
      risk,
      description
    }
  };
}

export interface UrlShortenerAnalysis {
  detected: boolean;
  service: string | null;
  risk: number;
  severity: "Safe" | "Info" | "Low" | "Medium" | "High" | "Critical";
  description: string;
}

export interface UrlShortenerAnalysisResult {
  urlShortener: UrlShortenerAnalysis;
}

const SHORTENER_DOMAINS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "buff.ly",
  "rebrand.ly",
  "cutt.ly",
  "shorturl.at"
];

/**
 * Detects if the submitted URL is from a known URL shortening service.
 * URL shorteners are frequently abused in phishing attacks to hide the real destination.
 * 
 * @param urlString - The raw URL string to analyze.
 * @returns A Promise that resolves to the UrlShortenerAnalysisResult.
 */
export async function analyzeUrlShortener(urlString: string): Promise<UrlShortenerAnalysisResult> {
  if (!urlString || typeof urlString !== 'string') {
    throw new Error("Invalid input: URL must be a non-empty string.");
  }

  let hostname = "";
  try {
    const urlToParse = urlString.includes("://") ? urlString : `http://${urlString}`;
    const parsedUrl = new URL(urlToParse);
    hostname = parsedUrl.hostname.toLowerCase();
  } catch (error) {
    throw new Error("Invalid URL format provided.");
  }

  // Check if any shortener domain matches the hostname (allowing for www. prefix)
  const detectedService = SHORTENER_DOMAINS.find(domain => hostname === domain || hostname.endsWith(`.${domain}`));

  if (detectedService) {
    return {
      urlShortener: {
        detected: true,
        service: detectedService,
        risk: 25,
        severity: "High",
        description: "URL shorteners hide the real destination and are frequently abused in phishing attacks."
      }
    };
  }

  return {
    urlShortener: {
      detected: false,
      service: null,
      risk: 0,
      severity: "Info",
      description: "No known URL shortener service was detected."
    }
  };
}
