import { PortsInfo } from '../types/analysis';

/**
 * The public analysis API must not perform unrestricted server-side port scanning.
 * This module is kept for future controlled use, but the public flow disables it to
 * avoid turning the application into an SSRF-capable scanner. If the function is ever
 * re-enabled, strict validation must be enforced before any socket attempt.
 */
export async function getOpenPorts(hostname: string): Promise<PortsInfo> {
  void hostname;
  return { status: 'disabled' };
}
