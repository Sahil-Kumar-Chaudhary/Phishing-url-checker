import React from 'react';
import { 
  Globe, Server, Shield, FileText, Link as LinkIcon, 
  Mail, Phone, Activity, Search, ExternalLink, 
  Database, Fingerprint, MapPin, Hash, Lock, 
  Clock, AlertCircle, Cookie, ArrowRightLeft
} from 'lucide-react';
import { AnalysisReport } from '../types/analysis';

const Card = ({ title, icon: Icon, children, colSpan = 1 }: any) => (
  <div className={`group bg-[#151A2D]/80 backdrop-blur-sm border border-white/5 hover:border-indigo-500/30 rounded-2xl p-6 transition-all duration-300 hover:shadow-[0_8px_30px_rgb(0,0,0,0.12)] hover:shadow-indigo-500/10 relative overflow-hidden ${colSpan === 2 ? 'md:col-span-2' : ''}`}>
    <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/0 via-purple-500/0 to-indigo-500/0 group-hover:from-indigo-500/5 group-hover:to-purple-500/5 transition-all duration-500"></div>
    <div className="relative z-10">
      <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <Icon className="w-5 h-5 text-indigo-400 group-hover:text-indigo-300 transition-colors" />
        {title}
      </h3>
      <div className="space-y-3">
        {children}
      </div>
    </div>
  </div>
);

const Row = ({ label, value }: { label: string, value: React.ReactNode }) => (
  <div className="flex flex-col sm:flex-row sm:justify-between py-2 border-b border-white/5 last:border-0">
    <span className="text-slate-400 text-sm font-medium mb-1 sm:mb-0">{label}</span>
    <span className="text-slate-200 text-sm break-all sm:text-right max-w-[70%]">{value || '-'}</span>
  </div>
);

export const WebsiteCard = ({ data }: { data: AnalysisReport['website'] }) => (
  <Card title="Website Information" icon={Globe}>
    <Row label="Page Title" value={data.pageTitle} />
    <Row label="Domain" value={data.domain} />
    <Row label="Hostname" value={data.hostname} />
    <Row label="Protocol" value={data.protocol} />
    <Row label="IP Address" value={data.ipAddress} />
    {data.favicon && (
      <div className="flex justify-between items-center py-2">
        <span className="text-slate-400 text-sm font-medium">Favicon</span>
        <img src={data.favicon} alt="favicon" className="w-6 h-6 rounded" onError={(e) => e.currentTarget.style.display = 'none'} />
      </div>
    )}
  </Card>
);

export const IPInfoCard = ({ data }: { data: AnalysisReport['ip'] }) => (
  <Card title="IP / Server Information" icon={Server}>
    <Row label="Country" value={data.country} />
    <Row label="Region" value={data.region} />
    <Row label="City" value={data.city} />
    <Row label="ISP" value={data.isp} />
    <Row label="ASN" value={data.asn} />
    <Row label="Timezone" value={data.timezone} />
    {data.latitude && data.longitude && (
      <Row label="Coordinates" value={`${data.latitude}, ${data.longitude}`} />
    )}
  </Card>
);

export const WhoisCard = ({ data }: { data: AnalysisReport['whois'] }) => (
  <Card title="Domain (WHOIS)" icon={Database}>
    <Row label="Registrar" value={data.registrar} />
    <Row label="Registered On" value={data.registrationDate ? new Date(data.registrationDate).toLocaleDateString() : null} />
    <Row label="Expires On" value={data.expiryDate ? new Date(data.expiryDate).toLocaleDateString() : null} />
    <Row label="Updated On" value={data.updatedDate ? new Date(data.updatedDate).toLocaleDateString() : null} />
    <div className="pt-2">
      <span className="text-slate-400 text-sm font-medium block mb-2">Name Servers</span>
      <div className="bg-[#0B0F19] rounded-lg p-3 text-xs text-slate-300 font-mono">
        {data.nameServers.length > 0 ? data.nameServers.join('\n') : '-'}
      </div>
    </div>
  </Card>
);

export const DNSCard = ({ data }: { data: AnalysisReport['dns'] }) => (
  <Card title="DNS Records" icon={Hash}>
    <div className="space-y-4 max-h-[300px] overflow-y-auto custom-scrollbar pr-2">
      {Object.entries(data).map(([type, records]) => {
        if (!records) return null;
        let display = '';
        if (Array.isArray(records)) {
          if (records.length === 0) return null;
          display = records.map(r => typeof r === 'string' ? r : JSON.stringify(r)).join('\n');
        } else {
          display = JSON.stringify(records, null, 2);
        }
        
        return (
          <div key={type}>
            <span className="text-slate-400 text-sm font-bold block mb-1">{type} Records</span>
            <pre className="bg-[#0B0F19] rounded-lg p-3 text-xs text-slate-300 font-mono whitespace-pre-wrap">
              {display}
            </pre>
          </div>
        );
      })}
    </div>
  </Card>
);

export const SSLCard = ({ data }: { data: AnalysisReport['ssl'] }) => (
  <Card title="SSL Certificate" icon={Lock}>
    <Row label="Issuer" value={data.issuer} />
    <Row label="Subject" value={data.subject} />
    <Row label="Valid From" value={data.validFrom} />
    <Row label="Valid Until" value={data.validUntil} />
    <Row label="Serial Number" value={data.serialNumber} />
  </Card>
);

export const HeadersCard = ({ data }: { data: AnalysisReport['headers'] }) => (
  <Card title="HTTP Headers" icon={FileText} colSpan={2}>
    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-1 max-h-[300px] overflow-y-auto custom-scrollbar">
      {Object.entries(data).map(([key, value]) => (
        <Row key={key} label={key} value={value} />
      ))}
    </div>
  </Card>
);

export const CookiesCard = ({ data }: { data: AnalysisReport['cookies'] }) => (
  <Card title="Cookies" icon={Cookie} colSpan={2}>
    {data.length === 0 ? (
      <span className="text-slate-500 text-sm">No cookies found</span>
    ) : (
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left text-slate-300">
          <thead className="text-xs text-slate-400 uppercase bg-[#0B0F19]/80 backdrop-blur-sm rounded-t-lg">
            <tr>
              <th className="px-4 py-3 rounded-tl-lg font-semibold">Name</th>
              <th className="px-4 py-3 font-semibold">Domain</th>
              <th className="px-4 py-3 font-semibold">Expires</th>
              <th className="px-4 py-3 text-center font-semibold">Secure</th>
              <th className="px-4 py-3 text-center rounded-tr-lg font-semibold">HttpOnly</th>
            </tr>
          </thead>
          <tbody>
            {data.map((c, i) => (
              <tr key={i} className="border-b border-white/5 last:border-0 hover:bg-white/5 transition-colors">
                <td className="px-4 py-3 font-medium truncate max-w-[150px]" title={c.name}>{c.name}</td>
                <td className="px-4 py-3">{c.domain || '-'}</td>
                <td className="px-4 py-3 truncate max-w-[150px]">{c.expires || 'Session'}</td>
                <td className="px-4 py-3 text-center">{c.secure ? '✅' : '❌'}</td>
                <td className="px-4 py-3 text-center">{c.httpOnly ? '✅' : '❌'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}
  </Card>
);

export const RedirectsCard = ({ data }: { data: AnalysisReport['redirectChain'] }) => (
  <Card title="Redirect Chain" icon={ArrowRightLeft}>
    <div className="space-y-4">
      {data.map((step, i) => (
        <div key={i} className="relative pl-6">
          <div className="absolute left-1.5 top-2 w-2 h-2 rounded-full bg-indigo-500"></div>
          {i < data.length - 1 && <div className="absolute left-2 top-4 w-0.5 h-full bg-white/10"></div>}
          <div className="text-sm font-medium text-slate-200 break-all">{step.url}</div>
          <div className="text-xs text-slate-400 mt-1">Status: {step.status}</div>
        </div>
      ))}
    </div>
  </Card>
);

export const LinksCard = ({ data }: { data: AnalysisReport['links'] }) => (
  <Card title="Links" icon={LinkIcon}>
    <div className="grid grid-cols-2 gap-4">
      <div className="bg-[#0B0F19]/80 border border-white/5 rounded-xl p-4 text-center hover:border-indigo-500/30 transition-colors">
        <div className="text-3xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-cyan-400">{data.internal.length}</div>
        <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mt-1">Internal</div>
      </div>
      <div className="bg-[#0B0F19]/80 border border-white/5 rounded-xl p-4 text-center hover:border-purple-500/30 transition-colors">
        <div className="text-3xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-purple-400 to-pink-400">{data.external.length}</div>
        <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mt-1">External</div>
      </div>
    </div>
    <div className="mt-4 max-h-[200px] overflow-y-auto custom-scrollbar space-y-1">
      {data.external.slice(0, 50).map((link, i) => (
        <div key={i} className="text-xs text-slate-400 truncate hover:text-white cursor-pointer" title={link}>
          {link}
        </div>
      ))}
      {data.external.length > 50 && <div className="text-xs text-slate-500 italic mt-2">...and {data.external.length - 50} more external links</div>}
    </div>
  </Card>
);

export const ContactCard = ({ emails, phones }: { emails: string[], phones: string[] }) => (
  <Card title="Contact Information" icon={Mail}>
    <div className="mb-4">
      <span className="text-slate-400 text-sm font-bold block mb-2 flex items-center gap-2">
        <Mail className="w-4 h-4" /> Emails ({emails.length})
      </span>
      <div className="bg-[#0B0F19] rounded-lg p-3 text-xs text-slate-300 font-mono max-h-[100px] overflow-y-auto custom-scrollbar">
        {emails.length > 0 ? emails.join('\n') : 'No emails found'}
      </div>
    </div>
    <div>
      <span className="text-slate-400 text-sm font-bold block mb-2 flex items-center gap-2">
        <Phone className="w-4 h-4" /> Phones ({phones.length})
      </span>
      <div className="bg-[#0B0F19] rounded-lg p-3 text-xs text-slate-300 font-mono max-h-[100px] overflow-y-auto custom-scrollbar">
        {phones.length > 0 ? phones.join('\n') : 'No phone numbers found'}
      </div>
    </div>
  </Card>
);

export const PortsCard = ({ data }: { data: AnalysisReport['ports'] }) => (
  <Card title="Common Ports" icon={Activity}>
    <div className="grid grid-cols-3 sm:grid-cols-4 gap-3">
      {Object.entries(data).map(([port, isOpen]) => (
        <div key={port} className={`p-3 rounded-xl border transition-all duration-300 flex flex-col items-center justify-center gap-1 ${isOpen ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.15)]' : 'bg-[#0B0F19]/80 border-white/5 text-slate-500 hover:border-white/10'}`}>
          <div className="text-xl font-bold">{port}</div>
          <div className="text-[10px] uppercase font-bold tracking-wider">{isOpen ? 'Open' : 'Closed'}</div>
        </div>
      ))}
    </div>
  </Card>
);

export const SitemapCard = ({ data }: { data: AnalysisReport['sitemap'] }) => (
  <Card title="Crawling Files" icon={Search}>
    <div className="flex items-center justify-between p-3 bg-[#0B0F19] rounded-lg mb-3 border border-white/5">
      <span className="text-sm font-medium text-slate-300">robots.txt</span>
      {data.hasRobotsTxt ? (
        <a href={data.robotsTxtUrl!} target="_blank" rel="noreferrer" className="text-emerald-400 flex items-center gap-1 text-sm hover:underline">
          Found <ExternalLink className="w-3 h-3" />
        </a>
      ) : <span className="text-slate-500 text-sm">Not Found</span>}
    </div>
    <div className="flex items-center justify-between p-3 bg-[#0B0F19] rounded-lg border border-white/5">
      <span className="text-sm font-medium text-slate-300">sitemap.xml</span>
      {data.hasSitemapXml ? (
        <a href={data.sitemapXmlUrl!} target="_blank" rel="noreferrer" className="text-emerald-400 flex items-center gap-1 text-sm hover:underline">
          Found <ExternalLink className="w-3 h-3" />
        </a>
      ) : <span className="text-slate-500 text-sm">Not Found</span>}
    </div>
  </Card>
);
