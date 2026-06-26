import { WhoisInfo } from '../types/analysis';

export async function getWhoisInfo(domain: string): Promise<WhoisInfo> {
  const defaultInfo: WhoisInfo = {
    registrar: null,
    registrationDate: null,
    expiryDate: null,
    updatedDate: null,
    nameServers: [],
  };

  try {
    // NetworkCalc provides a free WHOIS API
    const response = await fetch(`https://networkcalc.com/api/dns/whois/${domain}`);
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
