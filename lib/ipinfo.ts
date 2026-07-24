import dns from 'dns';
import { promisify } from 'util';
import { IPInfo } from '../types/analysis';

const resolve4 = promisify(dns.resolve4);

/**
 * Resolves a hostname to an IP address and fetches geolocation/ISP data.
 * Useful for identifying hosting anomalies (e.g. unexpected foreign servers).
 * @param hostname - The domain name or IP string to query.
 * @returns An object containing the resolved IP and detailed location/ISP metadata.
 */
export async function getIpInfo(hostname: string): Promise<{ ip: string | null; info: IPInfo }> {
  let ip: string | null = null;
  const defaultInfo: IPInfo = {
    country: null,
    region: null,
    city: null,
    isp: null,
    asn: null,
    latitude: null,
    longitude: null,
    timezone: null,
  };

  try {
    // Check if hostname is already an IP
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (ipRegex.test(hostname)) {
      ip = hostname;
    } else {
      const addresses = await resolve4(hostname);
      if (addresses.length > 0) {
        ip = addresses[0];
      }
    }

    if (ip) {
      // Use ip-api.com (free, no auth needed for basic usage, HTTP only or HTTPS for pro)
      // Using http because free tier of ip-api is http only
      const response = await fetch(`http://ip-api.com/json/${ip}`);
      const data = await response.json();

      if (data.status === 'success') {
        return {
          ip,
          info: {
            country: data.country || null,
            region: data.regionName || null,
            city: data.city || null,
            isp: data.isp || null,
            asn: data.as || null,
            latitude: data.lat || null,
            longitude: data.lon || null,
            timezone: data.timezone || null,
          }
        };
      }
    }
  } catch (error) {
    console.error('Error fetching IP info:', error);
  }

  return { ip, info: defaultInfo };
}
