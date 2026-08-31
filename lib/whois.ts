import { WhoisInfo } from '../types/analysis';
import { validateNetworkTarget } from './security/networkValidation';

export async function getWhoisInfo(domain: string): Promise<WhoisInfo> {
  const defaultInfo: WhoisInfo = {
    registrar: null,
    registrationDate: null,
    expiryDate: null,
    updatedDate: null,
    nameServers: [],
  };

  try {
    const target = `https://networkcalc.com/api/dns/whois/${domain}`;
    const validation = await validateNetworkTarget(target);
    if (!validation.ok) {
      return defaultInfo;
    }

    const response = await fetch(validation.url.toString());
    const data = await response.json();

    if (data && data.status === 'OK' && data.whois) {
      const whois = data.whois;
      
      return {
        registrar: whois.registrar || null,
        registrationDate: whois.creation_date || null,
        expiryDate: whois.registrar_registration_expiration_date || null,
        updatedDate: whois.updated_date || null,
        nameServers: whois.name_servers || [],
      };
    }
  } catch (error) {
    console.error('Error fetching WHOIS info:', error);
  }

  return defaultInfo;
}
