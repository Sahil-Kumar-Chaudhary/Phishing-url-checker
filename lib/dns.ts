import { promises as dns } from "dns";
import { DNSRecords } from "../types/analysis";

const resolve4 = (host: string) => dns.resolve4(host, { ttl: false });
const resolve6 = (host: string) => dns.resolve6(host);
const resolveMx = dns.resolveMx;
const resolveTxt = dns.resolveTxt;
const resolveNs = dns.resolveNs;
const resolveSoa = dns.resolveSoa;
const resolveCname = dns.resolveCname;
const resolveCaa = dns.resolveCaa;

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

  const resolveSafe = async <T>(
    resolver: (hostname: string) => Promise<T>
  ): Promise<T | null> => {
    try {
      return await resolver(hostname);
    } catch {
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
  if (txt) records.TXT = txt.map((t) => t.join(" "));
  if (ns) records.NS = ns;
  if (soa) records.SOA = soa;
  if (cname) records.CNAME = cname;
  if (caa) records.CAA = caa;

  return records;
}
