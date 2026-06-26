import dns from 'dns';
import { promisify } from 'util';
import { DNSRecords } from '../types/analysis';

const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);
const resolveMx = promisify(dns.resolveMx);
const resolveTxt = promisify(dns.resolveTxt);
const resolveNs = promisify(dns.resolveNs);
const resolveSoa = promisify(dns.resolveSoa);
const resolveCname = promisify(dns.resolveCname);
const resolveCaa = promisify(dns.resolveCaa);

export async function getDnsRecords(hostname: string): Promise<DNSRecords> {
  const records: DNSRecords = {
    A: [],
    AAAA: [],
    MX: [],
    TXT: [],
    NS: [],
    SOA: null,
    CNAME: [],
    CAA: [],
  };

  const resolveSafe = async <T>(resolver: (hostname: string) => Promise<T>): Promise<T | null> => {
    try {
      return await resolver(hostname);
    } catch (e) {
      return null;
    }
  };

  const [a, aaaa, mx, txt, ns, soa, cname, caa] = await Promise.all([
    resolveSafe(resolve4),
    resolveSafe(resolve6),
    resolveSafe(resolveMx),
    resolveSafe(resolveTxt),
    resolveSafe(resolveNs),
    resolveSafe(resolveSoa),
    resolveSafe(resolveCname),
    resolveSafe(resolveCaa),
  ]);

  if (a) records.A = a;
  if (aaaa) records.AAAA = aaaa;
  if (mx) records.MX = mx;
  if (txt) records.TXT = txt.map(t => t.join(' ')); // TXT records can be chunks
  if (ns) records.NS = ns;
  if (soa) records.SOA = soa;
  if (cname) records.CNAME = cname;
  if (caa) records.CAA = caa;

  return records;
}
