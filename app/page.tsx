'use client';

import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  ShieldAlert, 
  Copy, 
  Trash2, 
  Search, 
  History,
  XCircle,
  CheckCircle2,
  Info,
  ArrowRight,
  Lock,
  Globe,
  Activity,
  Server,
  ChevronRight,
  ExternalLink
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { AnalysisReport } from '../types/analysis';
import { 
  WebsiteCard, IPInfoCard, WhoisCard, DNSCard, 
  SSLCard, HeadersCard, CookiesCard, RedirectsCard, 
  LinksCard, ContactCard, PortsCard, SitemapCard 
} from '../components/AnalysisCards';

const SCAN_STEPS = [
  "Initializing secure connection...",
  "Resolving DNS records...",
  "Verifying SSL/TLS certificates...",
  "Analyzing domain reputation...",
  "Scanning for malicious patterns...",
  "Checking against threat databases...",
  "Finalizing security report..."
];

const CircularProgress = ({ score, status }: { score: number, status: string }) => {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;
  
  const getColor = () => {
    if (status === 'safe') return 'text-emerald-500';
    if (status === 'suspicious') return 'text-amber-500';
    return 'text-rose-500';
  };

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg className="transform -rotate-90 w-24 h-24">
        <circle
          className="text-slate-100"
          strokeWidth="8"
          stroke="currentColor"
          fill="transparent"
          r={radius}
          cx="48"
          cy="48"
        />
        <motion.circle
          className={getColor()}
          strokeWidth="8"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset }}
          transition={{ duration: 1.5, ease: "easeOut" }}
          strokeLinecap="round"
          stroke="currentColor"
          fill="transparent"
          r={radius}
          cx="48"
          cy="48"
        />
      </svg>
      <div className="absolute flex flex-col items-center justify-center text-slate-700">
        <span className="text-2xl font-bold">{score}</span>
        <span className="text-[10px] uppercase font-semibold tracking-wider text-slate-400">Risk</span>
      </div>
    </div>
  );
};

export default function PhishingChecker() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [result, setResult] = useState<AnalysisReport | null>(null);
  const [history, setHistory] = useState<AnalysisReport[]>([]);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem('phishguard_history');
    if (saved) {
      try {
        setHistory(JSON.parse(saved));
      } catch (e) {
        console.error('Failed to parse history');
      }
    }
  }, []);

  useEffect(() => {
    localStorage.setItem('phishguard_history', JSON.stringify(history));
  }, [history]);

  useEffect(() => {
    if (loading) {
      const interval = setInterval(() => {
        setScanStep((prev) => (prev < SCAN_STEPS.length - 1 ? prev + 1 : prev));
      }, 400);
      return () => clearInterval(interval);
    } else {
      setScanStep(0);
    }
  }, [loading]);

  const handleCheck = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setResult(null);
    setCopied(false);

    try {
      const response = await fetch('/api/analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.message || 'Analysis failed');
      }

      const report: AnalysisReport = data.data;
      setResult(report);
      setHistory(prev => [report, ...prev.filter(item => item.url !== report.url)].slice(0, 10));
    } catch (error: any) {
      alert(error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setUrl('');
    setResult(null);
    setCopied(false);
  };

  const handleCopy = () => {
    if (!result) return;
    const text = `PhishGuard Analysis Report\nURL: ${result.url}\nStatus: ${result.security.status.toUpperCase()}\nRisk Score: ${result.security.score}/100\n\nFindings:\n${result.security.reasons.map(r => `- ${r.text}`).join('\n')}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getStatusIcon = (status: string, className = "w-6 h-6") => {
    switch (status) {
      case 'safe': return <ShieldCheck className={`${className} text-emerald-600`} />;
      case 'suspicious': return <AlertTriangle className={`${className} text-amber-600`} />;
      case 'phishing': return <ShieldAlert className={`${className} text-rose-600`} />;
    }
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] text-slate-200 font-sans selection:bg-indigo-500/30 selection:text-indigo-200 flex flex-col">
      
      <nav className="sticky top-0 z-50 bg-[#0B0F19]/80 backdrop-blur-md border-b border-white/10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-gradient-to-br from-indigo-500 to-purple-600 p-2 rounded-xl shadow-lg shadow-indigo-500/50">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-400">
              PhishGuard
            </span>
          </div>
        </div>
      </nav>

      <main className="flex-grow">
        
        <section className="relative pt-20 pb-16 overflow-hidden">
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[1000px] h-[500px] opacity-20 pointer-events-none">
            <div className="absolute inset-0 bg-gradient-to-b from-indigo-500 to-purple-500 blur-[100px] rounded-full mix-blend-screen"></div>
          </div>

          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 text-center">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-white mb-6">
                Complete URL <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-purple-400">Intelligence.</span>
              </h1>
              <p className="mt-4 text-lg sm:text-xl text-slate-400 max-w-2xl mx-auto mb-10">
                Advanced Threat Intelligence URL analysis to protect you from malicious websites, scams, and credential theft.
              </p>
            </motion.div>

            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="max-w-3xl mx-auto"
            >
              <div className="bg-[#151A2D]/80 border border-white/10 rounded-2xl p-2 shadow-[0_0_40px_-10px_rgba(99,102,241,0.3)] backdrop-blur-xl relative group">
                <div className="absolute inset-0 bg-gradient-to-r from-indigo-500 to-purple-500 rounded-2xl opacity-0 group-hover:opacity-20 transition-opacity duration-500 blur-md -z-10"></div>
                <form onSubmit={handleCheck} className="flex flex-col sm:flex-row gap-2">
                  <div className="relative flex-grow">
                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                      <Globe className="h-5 w-5 text-indigo-400" />
                    </div>
                    <input
                      type="text"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder="Paste a suspicious link here (e.g., secure-login.com)"
                      className="block w-full pl-12 pr-12 py-4 bg-[#0B0F19]/50 border border-transparent rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-all text-base sm:text-lg shadow-inner"
                      disabled={loading}
                    />
                    {url && !loading && (
                      <button
                        type="button"
                        onClick={handleClear}
                        className="absolute inset-y-0 right-0 pr-4 flex items-center text-slate-500 hover:text-white transition-colors"
                      >
                        <XCircle className="h-5 w-5" />
                      </button>
                    )}
                  </div>
                  <button
                    type="submit"
                    disabled={!url.trim() || loading}
                    className="flex items-center justify-center gap-2 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white px-8 py-4 rounded-xl font-semibold transition-all shadow-[0_0_20px_-5px_rgba(99,102,241,0.5)] hover:shadow-[0_0_25px_-5px_rgba(99,102,241,0.7)] disabled:opacity-50 disabled:cursor-not-allowed sm:w-auto w-full"
                  >
                    {loading ? 'Analyzing...' : 'Scan URL'}
                    {!loading && <ArrowRight className="w-5 h-5" />}
                  </button>
                </form>
              </div>

              <AnimatePresence>
                {loading && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="mt-6 bg-[#151A2D] border border-white/10 rounded-2xl p-6 overflow-hidden relative"
                  >
                    <motion.div 
                      className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-indigo-500 to-transparent opacity-50"
                      animate={{ y: [0, 150, 0] }}
                      transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                    />
                    
                    <div className="flex items-center gap-4">
                      <div className="relative">
                        <div className="w-10 h-10 border-4 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin"></div>
                        <ShieldCheck className="w-4 h-4 text-indigo-400 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
                      </div>
                      <div className="text-left flex-1">
                        <h4 className="text-white font-medium">Deep Analysis in Progress</h4>
                        <p className="text-indigo-400 text-sm mt-1 h-5 overflow-hidden">
                          <AnimatePresence mode="wait">
                            <motion.span
                              key={scanStep}
                              initial={{ opacity: 0, y: 10 }}
                              animate={{ opacity: 1, y: 0 }}
                              exit={{ opacity: 0, y: -10 }}
                              className="block"
                            >
                              {SCAN_STEPS[scanStep]}
                            </motion.span>
                          </AnimatePresence>
                        </p>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

            </motion.div>
          </div>
        </section>

        <section className="max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8 pb-24">
          <div className="grid grid-cols-1 xl:grid-cols-4 gap-8">
            
            <div className="xl:col-span-3">
              <AnimatePresence mode="wait">
                {result ? (
                  <motion.div
                    key="result"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    className="space-y-8"
                  >
                    {/* Overall Security Score Card */}
                    <div className={`rounded-3xl border p-1 overflow-hidden ${
                      result.security.status === 'safe' ? 'bg-gradient-to-b from-emerald-500/20 to-transparent border-emerald-500/20' :
                      result.security.status === 'suspicious' ? 'bg-gradient-to-b from-amber-500/20 to-transparent border-amber-500/20' :
                      'bg-gradient-to-b from-rose-500/20 to-transparent border-rose-500/20'
                    }`}>
                      <div className="bg-[#0B0F19] rounded-[22px] p-6 sm:p-8 h-full">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6 mb-8 border-b border-white/5 pb-8">
                          <div className="flex items-center gap-5">
                            <CircularProgress score={result.security.score} status={result.security.status} />
                            <div>
                              <h3 className="text-3xl font-bold text-white capitalize mb-1 flex items-center gap-2">
                                {result.security.status}
                                {getStatusIcon(result.security.status, "w-6 h-6")}
                              </h3>
                              <p className="text-slate-400 text-sm">
                                Analysis completed at {new Date(result.timestamp).toLocaleTimeString()}
                              </p>
                            </div>
                          </div>
                          <button
                            onClick={handleCopy}
                            className="flex items-center justify-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl text-sm font-medium transition-colors w-full sm:w-auto"
                          >
                            {copied ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                            {copied ? 'Copied Report' : 'Copy Report'}
                          </button>
                        </div>

                        <div>
                          <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                            <Activity className="w-5 h-5 text-indigo-400" />
                            Security Findings
                          </h4>
                          <ul className="space-y-3">
                            {result.security.reasons.map((reason, idx) => (
                              <li key={idx} className="flex items-start gap-3 bg-[#151A2D] border border-white/5 p-4 rounded-xl">
                                <div className="mt-0.5 shrink-0">
                                  {reason.type === 'positive' && <CheckCircle2 className="w-5 h-5 text-emerald-500" />}
                                  {reason.type === 'negative' && <AlertTriangle className="w-5 h-5 text-rose-500" />}
                                  {reason.type === 'neutral' && <Info className="w-5 h-5 text-blue-500" />}
                                </div>
                                <span className="text-slate-300 leading-relaxed">{reason.text}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </div>

                    {/* Detailed Analysis Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 gap-6 mt-8">
                      <WebsiteCard data={result.website} />
                      <IPInfoCard data={result.ip} />
                      <WhoisCard data={result.whois} />
                      <DNSCard data={result.dns} />
                      <SSLCard data={result.ssl} />
                      <ContactCard emails={result.emails} phones={result.phones} />
                      <LinksCard data={result.links} />
                      <PortsCard data={result.ports} />
                      <SitemapCard data={result.sitemap} />
                      <RedirectsCard data={result.redirectChain} />
                      <HeadersCard data={result.headers} />
                      <CookiesCard data={result.cookies} />
                    </div>

                  </motion.div>
                ) : (
                  <motion.div 
                    key="empty"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="h-full min-h-[400px] flex flex-col items-center justify-center text-center p-8 border border-white/5 border-dashed rounded-3xl bg-[#151A2D]/10 backdrop-blur-sm relative overflow-hidden"
                  >
                    <div className="absolute inset-0 bg-gradient-to-b from-indigo-500/5 to-purple-500/5"></div>
                    <div className="w-20 h-20 bg-indigo-500/10 rounded-full flex items-center justify-center mb-6 shadow-[0_0_30px_rgba(99,102,241,0.2)]">
                      <Search className="w-10 h-10 text-indigo-400" />
                    </div>
                    <h3 className="text-2xl font-bold text-white mb-3">Awaiting URL</h3>
                    <p className="text-slate-400 max-w-md text-lg">
                      Enter a link above to begin the security analysis. We'll check for SSL certificates, domain reputation, and malicious patterns.
                    </p>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            <div className="xl:col-span-1">
              <div className="bg-[#151A2D] border border-white/5 rounded-3xl p-6 sticky top-24 shadow-xl">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="font-semibold text-white flex items-center gap-2">
                    <History className="w-5 h-5 text-indigo-400" />
                    Recent Scans
                  </h3>
                  {history.length > 0 && (
                    <button
                      onClick={() => setHistory([])}
                      className="text-slate-500 hover:text-rose-400 transition-colors p-2 rounded-lg hover:bg-white/5"
                      title="Clear History"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>

                {history.length === 0 ? (
                  <div className="text-center py-12 text-slate-500 text-sm">
                    Your scan history will appear here.
                  </div>
                ) : (
                  <div className="space-y-3 max-h-[600px] overflow-y-auto pr-2 custom-scrollbar">
                    {history.map((item) => (
                      <button
                        key={item.id}
                        onClick={() => {
                          setUrl(item.url);
                          setResult(item);
                          window.scrollTo({ top: 0, behavior: 'smooth' });
                        }}
                        className="w-full text-left p-4 rounded-xl bg-[#0B0F19] border border-white/5 hover:border-indigo-500/30 transition-all group relative overflow-hidden"
                      >
                        <div className={`absolute left-0 top-0 bottom-0 w-1 ${
                          item.security.status === 'safe' ? 'bg-emerald-500' :
                          item.security.status === 'suspicious' ? 'bg-amber-500' : 'bg-rose-500'
                        }`} />
                        
                        <div className="pl-2">
                          <p className="text-sm font-medium text-slate-200 truncate pr-6">
                            {item.url}
                          </p>
                          <div className="flex items-center justify-between mt-2">
                            <span className={`text-xs font-semibold uppercase tracking-wider ${
                              item.security.status === 'safe' ? 'text-emerald-400' :
                              item.security.status === 'suspicious' ? 'text-amber-400' : 'text-rose-400'
                            }`}>
                              {item.security.status}
                            </span>
                            <span className="text-xs text-slate-500">
                              {new Date(item.timestamp).toLocaleDateString()}
                            </span>
                          </div>
                        </div>
                        <ChevronRight className="w-4 h-4 text-slate-600 absolute right-3 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity group-hover:translate-x-1" />
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

          </div>
        </section>

      </main>

      <footer className="border-t border-white/5 bg-[#0B0F19] py-12 mt-auto">
        <div className="max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-indigo-500" />
            <span className="text-lg font-bold text-white">PhishGuard</span>
          </div>
          <p className="text-slate-500 text-sm text-center md:text-left">
            © {new Date().getFullYear()} PhishGuard Security. All rights reserved.
          </p>
          <div className="flex items-center gap-6 text-sm text-slate-500">
            <a href="#" className="hover:text-white transition-colors">Privacy Policy</a>
            <a href="#" className="hover:text-white transition-colors">Terms of Service</a>
            <a href="#" className="hover:text-white transition-colors flex items-center gap-1">
              API Docs <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>
      </footer>

      <style dangerouslySetInnerHTML={{__html: `
        .custom-scrollbar::-webkit-scrollbar {
          width: 6px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: transparent;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background-color: rgba(255, 255, 255, 0.1);
          border-radius: 20px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background-color: rgba(255, 255, 255, 0.2);
        }
      `}} />
    </div>
  );
}
