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

// --- Types ---
type Status = 'safe' | 'suspicious' | 'phishing';

interface CheckResult {
  id: string;
  url: string;
  parsedUrl: {
    protocol: string;
    hostname: string;
    pathname: string;
  } | null;
  status: Status;
  riskScore: number; // 0 to 100
  reasons: { text: string; type: 'positive' | 'negative' | 'neutral' }[];
  timestamp: number;
}

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'update', 'free', 'bank', 'secure', 'account', 
  'wallet', 'crypto', 'support', 'service', 'auth', 'confirm', 'paypal',
  'apple', 'microsoft', 'google', 'amazon', 'netflix', 'win', 'prize'
];

const SCAN_STEPS = [
  "Initializing secure connection...",
  "Resolving DNS records...",
  "Verifying SSL/TLS certificates...",
  "Analyzing domain reputation...",
  "Scanning for malicious patterns...",
  "Checking against threat databases...",
  "Finalizing security report..."
];

// --- Helper Components ---

const CircularProgress = ({ score, status }: { score: number, status: Status }) => {
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

// --- Main Page Component ---

export default function PhishingChecker() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [result, setResult] = useState<CheckResult | null>(null);
  const [history, setHistory] = useState<CheckResult[]>([]);
  const [copied, setCopied] = useState(false);

  // Load history on mount
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

  // Save history on change
  useEffect(() => {
    localStorage.setItem('phishguard_history', JSON.stringify(history));
  }, [history]);

  // Handle fake scanning steps progression
  useEffect(() => {
    if (loading) {
      const interval = setInterval(() => {
        setScanStep((prev) => (prev < SCAN_STEPS.length - 1 ? prev + 1 : prev));
      }, 400); // Change step every 400ms
      return () => clearInterval(interval);
    } else {
      setScanStep(0);
    }
  }, [loading]);

  const analyzeUrl = async (inputUrl: string): Promise<CheckResult> => {
    let riskScore = 0; // 0 to 100
    const reasons: { text: string; type: 'positive' | 'negative' | 'neutral' }[] = [];
    let parsedUrlObj = null;
    
    if (!inputUrl || inputUrl.trim() === '') {
      throw new Error('Please enter a valid URL');
    }

    let urlToParse = inputUrl.trim();
    if (!/^https?:\/\//i.test(urlToParse)) {
      urlToParse = 'http://' + urlToParse;
    }

    try {
      const urlObj = new URL(urlToParse);
      parsedUrlObj = {
        protocol: urlObj.protocol,
        hostname: urlObj.hostname,
        pathname: urlObj.pathname === '/' ? '' : urlObj.pathname
      };

      // 1. HTTPS Check
      if (urlObj.protocol !== 'https:') {
        riskScore += 25;
        reasons.push({ text: 'Connection is not encrypted (HTTP instead of HTTPS)', type: 'negative' });
      } else {
        reasons.push({ text: 'Uses secure HTTPS connection', type: 'positive' });
      }

      // 2. IP Address Check
      const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
      if (ipRegex.test(urlObj.hostname)) {
        riskScore += 40;
        reasons.push({ text: 'Uses a raw IP address instead of a domain name', type: 'negative' });
      }

      // 3. Length Check
      if (inputUrl.length > 75) {
        riskScore += 15;
        reasons.push({ text: 'URL is unusually long, often used to obscure the real destination', type: 'negative' });
      }

      // 4. Subdomain Check
      const domainParts = urlObj.hostname.split('.');
      if (domainParts.length > 3 && !ipRegex.test(urlObj.hostname)) {
        riskScore += 20;
        reasons.push({ text: 'Contains multiple subdomains, a common phishing tactic', type: 'negative' });
      }

      // 5. Keyword Check
      const urlLower = inputUrl.toLowerCase();
      const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => urlLower.includes(kw));
      if (foundKeywords.length > 0) {
        riskScore += foundKeywords.length * 15;
        reasons.push({ text: `Contains suspicious keywords: ${foundKeywords.join(', ')}`, type: 'negative' });
      }

      // 6. Simulate API Call (e.g., Google Safe Browsing)
      await new Promise(resolve => setTimeout(resolve, 2800)); // Simulate network latency to show off animation
      
      if (urlLower.includes('phishing') || urlLower.includes('malware') || urlLower.includes('hack')) {
        riskScore += 80;
        reasons.push({ text: 'Flagged by Threat Intelligence Database', type: 'negative' });
      }

    } catch (e) {
      riskScore = 100;
      reasons.push({ text: 'Invalid URL format or malformed structure', type: 'negative' });
    }

    // Cap score at 100
    riskScore = Math.min(riskScore, 100);

    let status: Status = 'safe';
    if (riskScore >= 60) {
      status = 'phishing';
    } else if (riskScore >= 25) {
      status = 'suspicious';
    }

    if (riskScore === 0) {
      reasons.push({ text: 'No suspicious indicators found. Domain appears clean.', type: 'positive' });
    }

    return {
      id: Math.random().toString(36).substring(2, 9),
      url: inputUrl,
      parsedUrl: parsedUrlObj,
      status,
      riskScore,
      reasons,
      timestamp: Date.now()
    };
  };

  const handleCheck = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setResult(null);
    setCopied(false);

    try {
      const res = await analyzeUrl(url);
      setResult(res);
      setHistory(prev => [res, ...prev.filter(item => item.url !== res.url)].slice(0, 10));
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
    const text = `PhishGuard Analysis Report\nURL: ${result.url}\nStatus: ${result.status.toUpperCase()}\nRisk Score: ${result.riskScore}/100\n\nFindings:\n${result.reasons.map(r => `- ${r.text}`).join('\n')}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getStatusColor = (status: Status) => {
    switch (status) {
      case 'safe': return 'bg-emerald-50 border-emerald-200 text-emerald-900';
      case 'suspicious': return 'bg-amber-50 border-amber-200 text-amber-900';
      case 'phishing': return 'bg-rose-50 border-rose-200 text-rose-900';
    }
  };

  const getStatusIcon = (status: Status, className = "w-6 h-6") => {
    switch (status) {
      case 'safe': return <ShieldCheck className={`${className} text-emerald-600`} />;
      case 'suspicious': return <AlertTriangle className={`${className} text-amber-600`} />;
      case 'phishing': return <ShieldAlert className={`${className} text-rose-600`} />;
    }
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] text-slate-200 font-sans selection:bg-indigo-500/30 selection:text-indigo-200 flex flex-col">
      
      {/* --- Navigation --- */}
      <nav className="sticky top-0 z-50 bg-[#0B0F19]/80 backdrop-blur-md border-b border-white/10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-gradient-to-br from-indigo-500 to-purple-600 p-2 rounded-xl shadow-lg shadow-indigo-500/20">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-400">
              PhishGuard
            </span>
          </div>
          <div className="flex items-center gap-4">
            <button className="bg-white text-slate-900 px-4 py-2 rounded-lg text-sm font-semibold hover:bg-indigo-50 transition-colors">
              Sign In
            </button>
          </div>
        </div>
      </nav>

      {/* --- Main Content --- */}
      <main className="flex-grow">
        
        {/* Hero Section */}
        <section className="relative pt-20 pb-32 overflow-hidden">
          {/* Background Glow */}
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[1000px] h-[500px] opacity-20 pointer-events-none">
            <div className="absolute inset-0 bg-gradient-to-b from-indigo-500 to-purple-500 blur-[100px] rounded-full mix-blend-screen"></div>
          </div>

          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 text-center">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-white mb-6">
                Detect Phishing in <br className="hidden sm:block" />
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-purple-400">
                  Real-Time.
                </span>
              </h1>
              <p className="mt-4 text-lg sm:text-xl text-slate-400 max-w-2xl mx-auto mb-10">
                Advanced AI-driven URL analysis to protect you from malicious websites, scams, and credential theft.
              </p>
            </motion.div>

            {/* The Checker Tool */}
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="max-w-3xl mx-auto"
            >
              <div className="bg-[#151A2D] border border-white/10 rounded-2xl p-2 shadow-2xl shadow-black/50 backdrop-blur-xl">
                <form onSubmit={handleCheck} className="flex flex-col sm:flex-row gap-2">
                  <div className="relative flex-grow">
                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                      <Globe className="h-5 w-5 text-slate-500" />
                    </div>
                    <input
                      type="text"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder="Paste a suspicious link here (e.g., secure-login.com)"
                      className="block w-full pl-12 pr-12 py-4 bg-[#0B0F19]/50 border border-transparent rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-[#0B0F19] transition-all text-base sm:text-lg"
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
                    className="flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white px-8 py-4 rounded-xl font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed sm:w-auto w-full"
                  >
                    {loading ? 'Analyzing...' : 'Scan URL'}
                    {!loading && <ArrowRight className="w-5 h-5" />}
                  </button>
                </form>
              </div>

              {/* Scanning Animation State */}
              <AnimatePresence>
                {loading && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="mt-6 bg-[#151A2D] border border-white/10 rounded-2xl p-6 overflow-hidden relative"
                  >
                    {/* Scanning line effect */}
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

        {/* Results & History Section */}
        <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-24">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            
            {/* Left Column: Result */}
            <div className="lg:col-span-2">
              <AnimatePresence mode="wait">
                {result ? (
                  <motion.div
                    key="result"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    className={`rounded-3xl border p-1 overflow-hidden ${
                      result.status === 'safe' ? 'bg-gradient-to-b from-emerald-500/20 to-transparent border-emerald-500/20' :
                      result.status === 'suspicious' ? 'bg-gradient-to-b from-amber-500/20 to-transparent border-amber-500/20' :
                      'bg-gradient-to-b from-rose-500/20 to-transparent border-rose-500/20'
                    }`}
                  >
                    <div className="bg-[#0B0F19] rounded-[22px] p-6 sm:p-8 h-full">
                      {/* Result Header */}
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6 mb-8 border-b border-white/5 pb-8">
                        <div className="flex items-center gap-5">
                          <CircularProgress score={result.riskScore} status={result.status} />
                          <div>
                            <h3 className="text-3xl font-bold text-white capitalize mb-1 flex items-center gap-2">
                              {result.status}
                              {getStatusIcon(result.status, "w-6 h-6")}
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

                      {/* URL Breakdown */}
                      {result.parsedUrl && (
                        <div className="mb-8 bg-[#151A2D] rounded-xl p-4 border border-white/5 font-mono text-sm overflow-x-auto">
                          <div className="flex items-center gap-2 text-slate-400 mb-2 text-xs uppercase tracking-wider font-sans font-semibold">
                            <Server className="w-3 h-3" /> Target Destination
                          </div>
                          <div className="flex items-center whitespace-nowrap">
                            <span className={result.parsedUrl.protocol === 'https:' ? 'text-emerald-400' : 'text-rose-400'}>
                              {result.parsedUrl.protocol}//
                            </span>
                            <span className="text-white font-bold">{result.parsedUrl.hostname}</span>
                            <span className="text-slate-500">{result.parsedUrl.pathname}</span>
                          </div>
                        </div>
                      )}

                      {/* Detailed Findings */}
                      <div>
                        <h4 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                          <Activity className="w-5 h-5 text-indigo-400" />
                          Security Findings
                        </h4>
                        <ul className="space-y-3">
                          {result.reasons.map((reason, idx) => (
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
                  </motion.div>
                ) : (
                  <motion.div 
                    key="empty"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="h-full min-h-[400px] flex flex-col items-center justify-center text-center p-8 border border-white/5 border-dashed rounded-3xl bg-[#151A2D]/30"
                  >
                    <div className="w-16 h-16 bg-indigo-500/10 rounded-full flex items-center justify-center mb-4">
                      <Search className="w-8 h-8 text-indigo-400" />
                    </div>
                    <h3 className="text-xl font-semibold text-white mb-2">Awaiting URL</h3>
                    <p className="text-slate-400 max-w-md">
                      Enter a link above to begin the security analysis. We'll check for SSL certificates, domain reputation, and malicious patterns.
                    </p>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Right Column: History */}
            <div className="lg:col-span-1">
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
                        {/* Status Indicator Line */}
                        <div className={`absolute left-0 top-0 bottom-0 w-1 ${
                          item.status === 'safe' ? 'bg-emerald-500' :
                          item.status === 'suspicious' ? 'bg-amber-500' : 'bg-rose-500'
                        }`} />
                        
                        <div className="pl-2">
                          <p className="text-sm font-medium text-slate-200 truncate pr-6">
                            {item.url}
                          </p>
                          <div className="flex items-center justify-between mt-2">
                            <span className={`text-xs font-semibold uppercase tracking-wider ${
                              item.status === 'safe' ? 'text-emerald-400' :
                              item.status === 'suspicious' ? 'text-amber-400' : 'text-rose-400'
                            }`}>
                              {item.status}
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

        {/* Features Section */}
        <section className="border-t border-white/5 bg-[#0B0F19] py-24">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center mb-16">
              <h2 className="text-3xl font-bold text-white mb-4">Enterprise-Grade Protection</h2>
              <p className="text-slate-400 max-w-2xl mx-auto">Our analysis engine performs multiple checks simultaneously to ensure you never fall victim to a phishing attack.</p>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              <div className="bg-[#151A2D] border border-white/5 p-8 rounded-2xl">
                <div className="w-12 h-12 bg-indigo-500/10 rounded-xl flex items-center justify-center mb-6">
                  <Lock className="w-6 h-6 text-indigo-400" />
                </div>
                <h3 className="text-xl font-semibold text-white mb-3">SSL/TLS Verification</h3>
                <p className="text-slate-400 text-sm leading-relaxed">We verify the cryptographic certificates of the destination to ensure your connection is private and secure.</p>
              </div>
              <div className="bg-[#151A2D] border border-white/5 p-8 rounded-2xl">
                <div className="w-12 h-12 bg-purple-500/10 rounded-xl flex items-center justify-center mb-6">
                  <Globe className="w-6 h-6 text-purple-400" />
                </div>
                <h3 className="text-xl font-semibold text-white mb-3">Domain Analysis</h3>
                <p className="text-slate-400 text-sm leading-relaxed">Detects homograph attacks, excessive subdomains, and raw IP addresses commonly used by threat actors.</p>
              </div>
              <div className="bg-[#151A2D] border border-white/5 p-8 rounded-2xl">
                <div className="w-12 h-12 bg-rose-500/10 rounded-xl flex items-center justify-center mb-6">
                  <ShieldAlert className="w-6 h-6 text-rose-400" />
                </div>
                <h3 className="text-xl font-semibold text-white mb-3">Heuristic Scanning</h3>
                <p className="text-slate-400 text-sm leading-relaxed">Scans for known malicious keywords, deceptive URL structures, and patterns matching active phishing campaigns.</p>
              </div>
            </div>
          </div>
        </section>

      </main>

      {/* --- Footer --- */}
      <footer className="border-t border-white/5 bg-[#0B0F19] py-12 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-6">
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

      {/* Custom Scrollbar Styles for History */}
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
