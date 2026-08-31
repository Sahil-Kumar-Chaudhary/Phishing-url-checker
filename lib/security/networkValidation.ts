/**
 * Centralized outbound-target validation for SSRF hardening.
 *
 * The project accepts user-controlled URLs and performs server-side HTTP/TLS/DNS
 * operations against them. Each network boundary must validate the destination and
 * the resolved IP before making the connection. This is the safest practical
 * approach available in the current Next.js + Node architecture:
 *
 * - reject unsupported protocols
 * - reject localhost/private/link-local/metadata destinations
 * - resolve the hostname and inspect the actual IPs before request formation
 * - re-validate redirect targets independently before following them
 *
 * Remaining limitation: DNS rebinding can still be attempted by a hostile resolver
 * between validation and the actual socket connection. This layer minimizes the risk
 * by validating the resolved addresses immediately before the request and by refusing
 * private/local destinations. It does not provide perfect defense against every
 * adversarial resolver condition in a public networked environment.
 */
import dns from 'node:dns/promises';
import net from 'node:net';

export type NetworkValidationCode =
  | 'INVALID_URL'
  | 'UNSUPPORTED_PROTOCOL'
  | 'BLOCKED_DESTINATION'
  | 'DNS_RESOLUTION_FAILED'
  | 'DNS_REBINDING_BLOCKED';

export interface NetworkValidationSuccess {
  ok: true;
  url: URL;
  hostname: string;
  resolvedIp: string;
}

export interface NetworkValidationFailure {
  ok: false;
  code: NetworkValidationCode;
  message: string;
}

export type NetworkValidationResult = NetworkValidationSuccess | NetworkValidationFailure;

export class NetworkValidationError extends Error {
  public readonly code: NetworkValidationCode;

  constructor(result: NetworkValidationFailure) {
    super(result.message);
    this.name = 'NetworkValidationError';
    this.code = result.code;
  }
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'localhost6',
  'localhost6.localdomain6',
  'metadata.google.internal',
  'metadata',
]);

function normalizeHostname(hostname: string): string {
  return hostname.trim().replace(/\.$/, '').toLowerCase();
}

function isIpv4MappedIpv6(address: string): boolean {
  return address.toLowerCase().startsWith('::ffff:');
}

function parseIpv4(address: string): number[] | null {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(address)) {
    return null;
  }

  const octets = address.split('.').map((part) => Number(part));
  if (octets.some((part) => Number.isNaN(part) || part < 0 || part > 255)) {
    return null;
  }

  return octets;
}

function ipv4ToNumber(address: string): number | null {
  const octets = parseIpv4(address);
  if (!octets) {
    return null;
  }

  return octets.reduce((total, octet) => (total << 8) + octet, 0);
}

function ipv4InRange(address: string, network: string, prefixLength: number): boolean {
  const ipValue = ipv4ToNumber(address);
  const networkValue = ipv4ToNumber(network);

  if (ipValue === null || networkValue === null) {
    return false;
  }

  if (prefixLength === 0) {
    return true;
  }

  const mask = prefixLength >= 32 ? 0xffffffff : ((0xffffffff << (32 - prefixLength)) >>> 0);
  return (ipValue & mask) === (networkValue & mask);
}

function isBlockedIpv4(address: string): boolean {
  const normalized = address.trim();
  const ipValue = parseIpv4(normalized);
  if (!ipValue) {
    return false;
  }

  if (normalized === '0.0.0.0') {
    return true;
  }

  const checks = [
    { network: '127.0.0.0', prefixLength: 8 },
    { network: '10.0.0.0', prefixLength: 8 },
    { network: '172.16.0.0', prefixLength: 12 },
    { network: '192.168.0.0', prefixLength: 16 },
    { network: '169.254.0.0', prefixLength: 16 },
  ];

  return checks.some(({ network, prefixLength }) => ipv4InRange(normalized, network, prefixLength));
}

function isBlockedIpv6(address: string): boolean {
  const normalized = address.trim().toLowerCase();

  if (normalized === '::1') {
    return true;
  }

  if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
    return true;
  }

  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
    return true;
  }

  return false;
}

export function isBlockedIpAddress(address: string): boolean {
  const normalized = address.trim();

  if (normalized === '') {
    return false;
  }

  if (isIpv4MappedIpv6(normalized)) {
    return isBlockedIpAddress(normalized.replace(/^::ffff:/i, ''));
  }

  if (net.isIP(normalized) === 4) {
    return isBlockedIpv4(normalized);
  }

  if (net.isIP(normalized) === 6) {
    return isBlockedIpv6(normalized);
  }

  return false;
}

export function isBlockedHostname(hostname: string): boolean {
  const normalized = normalizeHostname(hostname);
  if (!normalized) {
    return true;
  }

  if (BLOCKED_HOSTNAMES.has(normalized)) {
    return true;
  }

  if (normalized.endsWith('.localhost') || normalized.endsWith('.localhost.localdomain')) {
    return true;
  }

  if (normalized === 'metadata.google.internal' || normalized.endsWith('.internal')) {
    return true;
  }

  if (normalized === '169.254.169.254' || normalized === 'metadata') {
    return true;
  }

  if (normalized.endsWith('.local') || normalized.endsWith('.localdomain')) {
    return true;
  }

  return false;
}

export async function resolveHostnameIp(hostname: string): Promise<string[] | null> {
  const normalized = normalizeHostname(hostname);
  if (!normalized) {
    return null;
  }

  try {
    const records = await dns.lookup(normalized, { all: true, verbatim: false });
    return records.map((record) => record.address);
  } catch {
    return null;
  }
}

export async function validateHostnameForNetwork(hostname: string): Promise<NetworkValidationResult> {
  const normalized = normalizeHostname(hostname);
  if (!normalized) {
    return { ok: false, code: 'INVALID_URL', message: 'This destination is not valid.' };
  }

  if (net.isIP(normalized) !== 0) {
    if (isBlockedIpAddress(normalized)) {
      return { ok: false, code: 'BLOCKED_DESTINATION', message: 'This destination is blocked for security reasons.' };
    }
    return { ok: true, url: new URL(`https://${normalized}`), hostname: normalized, resolvedIp: normalized };
  }

  if (isBlockedHostname(normalized)) {
    return { ok: false, code: 'BLOCKED_DESTINATION', message: 'This destination is blocked for security reasons.' };
  }

  const addresses = await resolveHostnameIp(normalized);
  if (!addresses || addresses.length === 0) {
    return { ok: false, code: 'DNS_RESOLUTION_FAILED', message: 'This destination could not be resolved securely.' };
  }

  const blockedAddress = addresses.find((address) => isBlockedIpAddress(address));
  if (blockedAddress) {
    return { ok: false, code: 'BLOCKED_DESTINATION', message: 'This destination is blocked for security reasons.' };
  }

  return {
    ok: true,
    url: new URL(`https://${normalized}`),
    hostname: normalized,
    resolvedIp: addresses[0],
  };
}

export async function validateNetworkTarget(rawTarget: string | URL): Promise<NetworkValidationResult> {
  let urlObject: URL;

  try {
    urlObject = rawTarget instanceof URL ? rawTarget : new URL(rawTarget);
  } catch {
    return { ok: false, code: 'INVALID_URL', message: 'This destination is not valid.' };
  }

  const protocol = urlObject.protocol.toLowerCase();
  if (protocol !== 'http:' && protocol !== 'https:') {
    return { ok: false, code: 'UNSUPPORTED_PROTOCOL', message: 'Only HTTP and HTTPS destinations are allowed.' };
  }

  const hostname = normalizeHostname(urlObject.hostname);
  const hostValidation = await validateHostnameForNetwork(hostname);
  if (!hostValidation.ok) {
    return hostValidation;
  }

  return {
    ok: true,
    url: urlObject,
    hostname: hostValidation.hostname,
    resolvedIp: hostValidation.resolvedIp,
  };
}

export async function validateRedirectTarget(currentUrl: string, locationHeader: string): Promise<NetworkValidationResult> {
  try {
    const nextUrl = new URL(locationHeader, currentUrl);
    return validateNetworkTarget(nextUrl.toString());
  } catch {
    return { ok: false, code: 'INVALID_URL', message: 'This redirect destination is invalid.' };
  }
}

export async function fetchWithValidation(input: string | URL, init?: RequestInit): Promise<Response> {
  const validation = await validateNetworkTarget(String(input));
  if (!validation.ok) {
    throw new NetworkValidationError(validation);
  }

  return fetch(validation.url.toString(), init);
}
