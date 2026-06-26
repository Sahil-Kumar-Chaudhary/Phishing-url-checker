export interface WebsiteInfo {
  pageTitle: string | null;
  domain: string;
  hostname: string;
  protocol: string;
  ipAddress: string | null;
  favicon: string | null;
}

export interface IPInfo {
  country: string | null;
  region: string | null;
  city: string | null;
  isp: string | null;
  asn: string | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string | null;
}

export interface WhoisInfo {
  registrar: string | null;
  registrationDate: string | null;
  expiryDate: string | null;
  updatedDate: string | null;
  nameServers: string[];
}

export interface DNSRecords {
  A: string[];
  AAAA: string[];
  MX: { exchange: string; priority: number }[];
  TXT: string[];
  NS: string[];
  SOA: {
    nsname: string;
    hostmaster: string;
    serial: number;
    refresh: number;
    retry: number;
    expire: number;
    minttl: number;
  } | null;
  CNAME: string[];
  CAA: { critical: number; issue?: string; iodef?: string; contactemail?: string; contactphone?: string }[];
}

export interface SSLInfo {
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validUntil: string | null;
  serialNumber: string | null;
}

export interface CookieInfo {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  expires?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: string;
}

export interface RedirectInfo {
  url: string;
  status: number;
}

export interface LinksInfo {
  internal: string[];
  external: string[];
}

export interface PortsInfo {
  [port: number]: boolean | string;
}

export interface SitemapInfo {
  hasRobotsTxt: boolean;
  hasSitemapXml: boolean;
  robotsTxtUrl: string | null;
  sitemapXmlUrl: string | null;
}

export interface RiskReason {
  text: string;
  type: 'positive' | 'negative' | 'neutral';
}

export interface SecurityReport {
  score: number; // 0 to 100
  status: 'safe' | 'suspicious' | 'phishing';
  reasons: RiskReason[];
}

export interface AnalysisReport {
  id: string;
  url: string;
  timestamp: number;
  website: WebsiteInfo;
  ip: IPInfo;
  whois: WhoisInfo;
  dns: DNSRecords;
  ssl: SSLInfo;
  headers: Record<string, string>;
  cookies: CookieInfo[];
  redirectChain: RedirectInfo[];
  links: LinksInfo;
  emails: string[];
  phones: string[];
  ports: PortsInfo;
  sitemap: SitemapInfo;
  security: SecurityReport;
}
