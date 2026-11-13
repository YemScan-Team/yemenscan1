import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { api } from '../services/api';
import {
  ScanStatusData,
  ScanSessionItem,
  LiveWebService,
  ApiEndpoint,
  VulnerabilityItem,
  ReportType,
  SeverityLevel,
} from '../types/yemenscan';

// ============================================================================
// Inline Crisp Cyber SVG Icons (Zero external bundle dependency)
// ============================================================================
const Icons = {
  Shield: () => (
    <svg className="w-6 h-6 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
  Search: () => (
    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  ),
  Play: () => (
    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="5 3 19 12 5 21 5 3" />
    </svg>
  ),
  Stop: () => (
    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="4" width="16" height="16" rx="2" />
    </svg>
  ),
  Globe: () => (
    <svg className="w-5 h-5 text-sky-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  ),
  Server: () => (
    <svg className="w-5 h-5 text-indigo-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
      <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
      <line x1="6" y1="6" x2="6.01" y2="6" /><line x1="6" y1="18" x2="6.01" y2="18" />
    </svg>
  ),
  Cpu: () => (
    <svg className="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="4" width="16" height="16" rx="2" />
      <rect x="9" y="9" width="6" height="6" />
      <line x1="9" y1="1" x2="9" y2="4" /><line x1="15" y1="1" x2="15" y2="4" />
      <line x1="9" y1="20" x2="9" y2="23" /><line x1="15" y1="20" x2="15" y2="23" />
      <line x1="20" y1="9" x2="23" y2="9" /><line x1="20" y1="14" x2="23" y2="14" />
      <line x1="1" y1="9" x2="4" y2="9" /><line x1="1" y1="14" x2="4" y2="14" />
    </svg>
  ),
  AlertTriangle: () => (
    <svg className="w-5 h-5 text-rose-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  Sparkles: () => (
    <svg className="w-5 h-5 text-purple-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3l1.912 5.813a2 2 0 001.275 1.275L21 12l-5.813 1.912a2 2 0 00-1.275 1.275L12 21l-1.912-5.813a2 2 0 00-1.275-1.275L3 12l5.813-1.912a2 2 0 001.275-1.275L12 3z" />
    </svg>
  ),
  Download: () => (
    <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  ),
  Printer: () => (
    <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="6 9 6 2 18 2 18 9" />
      <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2" />
      <rect x="6" y="14" width="12" height="8" />
    </svg>
  ),
  Copy: () => (
    <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  ),
  Check: () => (
    <svg className="w-3.5 h-3.5 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  ),
  Refresh: () => (
    <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="23 4 23 10 17 10" />
      <polyline points="1 20 1 14 7 14" />
      <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
    </svg>
  ),
  ExternalLink: () => (
    <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
      <polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" />
    </svg>
  )
};

// ============================================================================
// Specialized Markdown Renderer Component with LTR Code Isolation
// ============================================================================
interface SafeMarkdownProps {
  content: string;
}

const SafeMarkdownViewer: React.FC<SafeMarkdownProps> = ({ content }) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const copyCode = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  // Structured parser for high-fidelity markdown rendering with isolated LTR code blocks
  const renderFormattedMarkdown = (text: string) => {
    const lines = text.split('\n');
    const elements: React.ReactNode[] = [];
    let inCodeBlock = false;
    let codeLang = '';
    let codeLines: string[] = [];
    let blockIndex = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (trimmed.startsWith('```')) {
        if (!inCodeBlock) {
          inCodeBlock = true;
          codeLang = trimmed.replace('```', '').trim() || 'bash';
          codeLines = [];
        } else {
          inCodeBlock = false;
          const codeContent = codeLines.join('\n');
          const currentIdx = blockIndex++;
          elements.push(
            <div key={`code-block-${currentIdx}`} className="my-4 rounded-xl overflow-hidden border border-slate-700/60 bg-slate-950 shadow-xl break-inside-avoid">
              <div className="flex items-center justify-between px-4 py-2 bg-slate-900 border-b border-slate-800 text-xs font-mono text-slate-400">
                <span className="text-cyan-400 font-semibold uppercase">{codeLang}</span>
                <button
                  type="button"
                  onClick={() => copyCode(codeContent, currentIdx)}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                >
                  {copiedIndex === currentIdx ? (
                    <>
                      <Icons.Check />
                      <span className="text-emerald-400">تم النسخ</span>
                    </>
                  ) : (
                    <>
                      <Icons.Copy />
                      <span>نسخ الكود</span>
                    </>
                  )}
                </button>
              </div>
              <pre
                dir="ltr"
                className="p-4 text-left font-mono text-xs md:text-sm text-emerald-400 leading-relaxed overflow-x-auto whitespace-pre-wrap selection:bg-cyan-900 selection:text-white"
              >
                <code>{codeContent}</code>
              </pre>
            </div>
          );
        }
        continue;
      }

      if (inCodeBlock) {
        codeLines.push(line);
        continue;
      }

      if (trimmed.startsWith('# ')) {
        elements.push(
          <h1 key={`h1-${i}`} className="text-2xl md:text-3xl font-extrabold text-slate-100 mt-8 mb-4 pb-2 border-b border-cyan-500/30">
            {trimmed.replace('# ', '')}
          </h1>
        );
      } else if (trimmed.startsWith('## ')) {
        elements.push(
          <h2 key={`h2-${i}`} className="text-xl md:text-2xl font-bold text-cyan-400 mt-6 mb-3">
            {trimmed.replace('## ', '')}
          </h2>
        );
      } else if (trimmed.startsWith('### ')) {
        elements.push(
          <h3 key={`h3-${i}`} className="text-lg md:text-xl font-semibold text-slate-200 mt-5 mb-2">
            {trimmed.replace('### ', '')}
          </h3>
        );
      } else if (trimmed.startsWith('> ')) {
        elements.push(
          <blockquote key={`quote-${i}`} className="my-3 p-4 bg-slate-800/40 border-r-4 border-cyan-500 rounded-l-lg text-slate-300 italic text-sm">
            {trimmed.replace('> ', '')}
          </blockquote>
        );
      } else if (trimmed.startsWith('- ')) {
        elements.push(
          <li key={`li-${i}`} className="mr-6 my-1.5 list-disc text-slate-300 text-sm leading-relaxed">
            {renderInlineCode(trimmed.replace('- ', ''))}
          </li>
        );
      } else if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
        // Table line
        elements.push(
          <div key={`table-line-${i}`} className="text-xs font-mono text-slate-300 py-1 border-b border-slate-800/50">
            {trimmed}
          </div>
        );
      } else if (trimmed === '') {
        elements.push(<div key={`sp-${i}`} className="h-2" />);
      } else {
        elements.push(
          <p key={`p-${i}`} className="my-2.5 text-slate-300 text-sm md:text-base leading-relaxed">
            {renderInlineCode(trimmed)}
          </p>
        );
      }
    }

    return elements;
  };

  const renderInlineCode = (text: string) => {
    const parts = text.split(/(`[^`]+`)/g);
    return parts.map((part, index) => {
      if (part.startsWith('`') && part.endsWith('`')) {
        const codeText = part.slice(1, -1);
        return (
          <code
            key={`inline-code-${index}`}
            dir="ltr"
            className="inline-block px-1.5 py-0.5 mx-1 rounded bg-slate-800 text-cyan-300 font-mono text-xs border border-slate-700/60"
          >
            {codeText}
          </code>
        );
      }
      return part;
    });
  };

  return (
    <div className="report-markdown-content prose prose-invert max-w-none text-right">
      {renderFormattedMarkdown(content)}
    </div>
  );
};

// ============================================================================
// Main YemenScan Dashboard Component
// ============================================================================
export const Dashboard: React.FC = () => {
  // --- Target & Scan State ---
  const [domainInput, setDomainInput] = useState<string>('');
  const [activeScanId, setActiveScanId] = useState<string>('');
  const [scanStatus, setScanStatus] = useState<ScanStatusData | null>(null);
  const [isStartingScan, setIsStartingScan] = useState<boolean>(false);
  const [isStoppingScan, setIsStoppingScan] = useState<boolean>(false);
  const [allScans, setAllScans] = useState<ScanSessionItem[]>([]);
  const [activeTab, setActiveTab] = useState<'assets' | 'vulnerabilities' | 'ai-report'>('assets');

  // --- Detailed Results State ---
  const [subdomains, setSubdomains] = useState<string[]>([]);
  const [openPorts, setOpenPorts] = useState<string[]>([]);
  const [liveUrls, setLiveUrls] = useState<LiveWebService[]>([]);
  const [apiEndpoints, setApiEndpoints] = useState<ApiEndpoint[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityItem[]>([]);
  
  // --- AI Report State ---
  const [reportType, setReportType] = useState<ReportType>('executive');
  const [aiReportMarkdown, setAiReportMarkdown] = useState<string>('');
  const [aiReportModel, setAiReportModel] = useState<string>('');
  const [aiReportCached, setAiReportCached] = useState<boolean>(false);
  const [isLoadingAiReport, setIsLoadingAiReport] = useState<boolean>(false);

  // --- Filtering & UI Controls ---
  const [assetsFilter, setAssetsFilter] = useState<string>('');
  const [assetsTypeFilter, setAssetsTypeFilter] = useState<'all' | 'web' | 'api'>('all');
  const [vulnSeverityFilter, setVulnSeverityFilter] = useState<string>('ALL');
  const [vulnSearch, setVulnSearch] = useState<string>('');
  const [expandedVulnId, setExpandedVulnId] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const pollingTimerRef = useRef<NodeJS.Timeout | null>(null);

  // ==========================================================================
  // Load Historical Scans on Mount
  // ==========================================================================
  const loadHistoricalScans = useCallback(async () => {
    try {
      const response = await api.getScans();
      if (response.status === 'success') {
        setAllScans(response.scans);
        if (response.scans.length > 0 && !activeScanId) {
          setActiveScanId(response.scans[0].scan_id);
          setDomainInput(response.scans[0].target_domain);
        }
      }
    } catch (err) {
      console.warn('Could not load historical scans:', err);
    }
  }, [activeScanId]);

  useEffect(() => {
    loadHistoricalScans();
  }, [loadHistoricalScans]);

  // ==========================================================================
  // Load Scan Results (Discovery, Endpoints, Vulnerabilities)
  // ==========================================================================
  const loadScanResults = useCallback(async (scanId: string) => {
    if (!scanId) return;

    try {
      // 1. Fetch Discovery
      const discoveryRes = await api.getDiscovery(scanId);
      if (discoveryRes.status === 'success') {
        setSubdomains(discoveryRes.subdomains || []);
        setOpenPorts(discoveryRes.open_ports || []);
      }

      // 2. Fetch Endpoints & Live Services
      const endpointsRes = await api.getEndpoints(scanId);
      if (endpointsRes.status === 'success') {
        setLiveUrls(endpointsRes.live_web_services || []);
        setApiEndpoints(endpointsRes.api_endpoints || []);
      }

      // 3. Fetch Vulnerabilities
      const vulnsRes = await api.getVulnerabilities(scanId);
      if (vulnsRes.status === 'success') {
        setVulnerabilities(vulnsRes.vulnerabilities || vulnsRes.data || []);
      }
    } catch (err) {
      console.error('Failed to load scan details:', err);
    }
  }, []);

  // ==========================================================================
  // Load AI Security Report
  // ==========================================================================
  const loadAiReport = useCallback(async (scanId: string, type: ReportType, forceRefresh = false) => {
    if (!scanId) return;
    setIsLoadingAiReport(true);
    setErrorMessage(null);

    try {
      const res = await api.getAIReport(scanId, type, forceRefresh);
      if (res.status === 'success') {
        setAiReportMarkdown(res.ai_report_markdown);
        setAiReportModel(res.model_used);
        setAiReportCached(res.cached);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'تعذر توليد أو جلب التقرير الأمني.');
    } finally {
      setIsLoadingAiReport(false);
    }
  }, []);

  // Load results whenever activeScanId changes
  useEffect(() => {
    if (activeScanId) {
      loadScanResults(activeScanId);
      loadAiReport(activeScanId, reportType, false);
    }
  }, [activeScanId, loadScanResults, loadAiReport, reportType]);

  // ==========================================================================
  // Real-time Polling Mechanism for Active Scan
  // ==========================================================================
  const checkStatus = useCallback(async () => {
    if (!activeScanId) return;

    try {
      const res = await api.getScanStatus(activeScanId);
      if (res.status === 'success' && res.data) {
        setScanStatus(res.data);

        // If scan is still running, refresh intermediate results
        if (!res.data.is_completed && res.data.current_stage !== 'stopped' && res.data.current_stage !== 'failed') {
          loadScanResults(activeScanId);
        } else {
          // Scan finished
          if (pollingTimerRef.current) {
            clearInterval(pollingTimerRef.current);
            pollingTimerRef.current = null;
          }
          loadScanResults(activeScanId);
          loadAiReport(activeScanId, reportType, false);
          loadHistoricalScans();
        }
      }
    } catch (err) {
      console.warn('Status polling error:', err);
    }
  }, [activeScanId, loadScanResults, loadAiReport, loadHistoricalScans, reportType]);

  useEffect(() => {
    if (!activeScanId) return;

    // Immediately check status
    checkStatus();

    // Start interval
    pollingTimerRef.current = setInterval(checkStatus, 2000);

    return () => {
      if (pollingTimerRef.current) {
        clearInterval(pollingTimerRef.current);
        pollingTimerRef.current = null;
      }
    };
  }, [activeScanId, checkStatus]);

  // ==========================================================================
  // Actions: Start & Stop Scan
  // ==========================================================================
  const handleStartScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const clean = domainInput.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!clean || clean.length < 3 || !clean.includes('.')) {
      setErrorMessage('يرجى إدخال نطاق مستهدف صالح (مثال: example.com أو ust.edu.ye)');
      return;
    }

    setIsStartingScan(true);
    setErrorMessage(null);

    try {
      const res = await api.startScan(clean);
      if (res.status === 'success' && res.scan_id) {
        setActiveScanId(res.scan_id);
        setActiveTab('assets');
        loadHistoricalScans();
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'فشل إطلاق عملية الفحص.');
    } finally {
      setIsStartingScan(false);
    }
  };

  const handleStopScan = async () => {
    if (!activeScanId) return;
    setIsStoppingScan(true);
    try {
      await api.stopScan(activeScanId);
      checkStatus();
    } catch (err: any) {
      setErrorMessage(err.message || 'فشل إيقاف الفحص.');
    } finally {
      setIsStoppingScan(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  // ==========================================================================
  // Filtered Assets & Vulnerabilities Lists
  // ==========================================================================
  const filteredAssets = useMemo(() => {
    const q = assetsFilter.toLowerCase().trim();
    const list: Array<{ url: string; type: 'web' | 'api'; port?: string; code?: number; details: string }> = [];

    if (assetsTypeFilter === 'all' || assetsTypeFilter === 'web') {
      liveUrls.forEach(w => {
        if (!q || w.url.toLowerCase().includes(q) || (w.title && w.title.toLowerCase().includes(q))) {
          list.push({
            url: w.url,
            type: 'web',
            code: w.status_code,
            details: w.webserver ? `${w.webserver} ${w.tech ? '• ' + w.tech.join(', ') : ''}` : (w.tech ? w.tech.join(', ') : 'Standard Web Server')
          });
        }
      });
    }

    if (assetsTypeFilter === 'all' || assetsTypeFilter === 'api') {
      apiEndpoints.forEach(a => {
        if (!q || a.url.toLowerCase().includes(q) || a.path.toLowerCase().includes(q)) {
          const tags = [];
          if (a.is_auth_endpoint) tags.push('Authentication');
          if (a.is_swagger_or_doc) tags.push('Documentation');
          if (a.is_actuator) tags.push('Actuator');
          list.push({
            url: a.url,
            type: 'api',
            code: a.status_code,
            details: tags.length > 0 ? tags.join(' • ') : 'API Endpoint'
          });
        }
      });
    }

    return list;
  }, [liveUrls, apiEndpoints, assetsFilter, assetsTypeFilter]);

  const filteredVulnerabilities = useMemo(() => {
    const q = vulnSearch.toLowerCase().trim();
    return vulnerabilities.filter(v => {
      const matchSeverity = vulnSeverityFilter === 'ALL' || v.severity.toUpperCase() === vulnSeverityFilter;
      const matchQuery =
        !q ||
        v.title.toLowerCase().includes(q) ||
        v.url.toLowerCase().includes(q) ||
        (v.cve_id && v.cve_id.toLowerCase().includes(q)) ||
        (v.cwe_id && v.cwe_id.toLowerCase().includes(q)) ||
        (v.owasp_category && v.owasp_category.toLowerCase().includes(q));
      return matchSeverity && matchQuery;
    });
  }, [vulnerabilities, vulnSeverityFilter, vulnSearch]);

  const stats = scanStatus?.stats || {
    subdomains_count: subdomains.length,
    open_ports_count: openPorts.length,
    live_urls_count: liveUrls.length,
    api_endpoints_count: apiEndpoints.length,
    vulnerabilities_count: vulnerabilities.length,
    vuln_by_severity: {
      critical: vulnerabilities.filter(v => v.severity.toUpperCase() === 'CRITICAL').length,
      high: vulnerabilities.filter(v => v.severity.toUpperCase() === 'HIGH').length,
      medium: vulnerabilities.filter(v => v.severity.toUpperCase() === 'MEDIUM').length,
      low: vulnerabilities.filter(v => v.severity.toUpperCase() === 'LOW').length,
      info: vulnerabilities.filter(v => v.severity.toUpperCase() === 'INFO').length,
    }
  };

  const isScanningActive = scanStatus ? (!scanStatus.is_completed && scanStatus.current_stage !== 'stopped' && scanStatus.current_stage !== 'failed') : false;
  const exportUrls = activeScanId ? api.getExportUrls(activeScanId, reportType) : null;

  return (
    <div dir="rtl" className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500 selection:text-slate-950 pb-16">
      
      {/* ==================================================================== */}
      {/* Top Navbar & Header */}
      {/* ==================================================================== */}
      <header className="sticky top-0 z-50 bg-slate-900/80 backdrop-blur-md border-b border-slate-800 shadow-lg no-print">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-tr from-cyan-600 to-emerald-500 shadow-md shadow-cyan-500/20">
              <Icons.Shield />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl font-black tracking-wider text-white">YEMEN<span className="text-cyan-400">SCAN</span></span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800/60 font-mono font-bold">v2.0 PRO</span>
              </div>
              <p className="text-xs text-slate-400 font-medium">منظومة فحص سطح الهجوم السيبراني وتتبع الثغرات</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {allScans.length > 0 && (
              <div className="hidden sm:flex items-center gap-2 bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700 text-xs">
                <span className="text-slate-400 font-bold">الجلسة الحالية:</span>
                <select
                  aria-label="اختر جلسة الفحص الأمني"
                  value={activeScanId}
                  onChange={(e) => setActiveScanId(e.target.value)}
                  className="bg-transparent text-cyan-300 font-mono focus:outline-none cursor-pointer"
                >
                  {allScans.map(s => (
                    <option key={s.scan_id} value={s.scan_id} className="bg-slate-900 text-white">
                      {s.target_domain} ({s.scan_id.slice(-6)})
                    </option>
                  ))}
                </select>
              </div>
            )}
            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-bold transition-all shadow-sm"
              title="طباعة التقرير الفوري"
            >
              <Icons.Printer />
              <span>طباعة PDF</span>
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-6 space-y-6">

        {/* ==================================================================== */}
        {/* Target Domain Input Card */}
        {/* ==================================================================== */}
        <section className="bg-slate-900/60 rounded-2xl border border-slate-800 p-5 md:p-6 shadow-xl backdrop-blur-sm no-print">
          <form onSubmit={handleStartScan} className="flex flex-col md:flex-row items-stretch md:items-center gap-3">
            <div className="relative flex-1">
              <div className="absolute inset-y-0 right-0 pr-3.5 flex items-center pointer-events-none text-slate-400">
                <Icons.Search />
              </div>
              <input
                type="text"
                dir="ltr"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                placeholder="أدخل النطاق المستهدف، مثل: example.com أو ust.edu.ye"
                disabled={isStartingScan}
                className="w-full pr-11 pl-4 py-3 bg-slate-950/80 border border-slate-700/80 rounded-xl text-white placeholder-slate-500 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition-all"
              />
            </div>

            <div className="flex items-center gap-2">
              <button
                type="submit"
                disabled={isStartingScan || isScanningActive}
                className="flex-1 md:flex-initial flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-extrabold text-sm shadow-lg shadow-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all cursor-pointer"
              >
                {isStartingScan ? (
                  <span className="inline-block animate-spin">⏳</span>
                ) : (
                  <Icons.Play />
                )}
                <span>{isStartingScan ? 'جاري الإطلاق...' : 'بدء الفحص الشامل'}</span>
              </button>

              {isScanningActive && (
                <button
                  type="button"
                  onClick={handleStopScan}
                  disabled={isStoppingScan}
                  className="flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-rose-600/90 hover:bg-rose-500 text-white font-bold text-sm shadow-lg shadow-rose-600/20 transition-all cursor-pointer"
                >
                  <Icons.Stop />
                  <span>{isStoppingScan ? 'جاري الإيقاف...' : 'إيقاف الفحص'}</span>
                </button>
              )}
            </div>
          </form>

          {/* Quick Preset Badges */}
          <div className="mt-3 flex items-center gap-2 flex-wrap text-xs text-slate-400">
            <span className="font-semibold text-slate-500">نطاقات سريعة للتجربة:</span>
            {['ust.edu.ye', 'dvwa.co.uk', 'example.com'].map(p => (
              <button
                key={p}
                type="button"
                onClick={() => setDomainInput(p)}
                className="px-2.5 py-1 rounded-md bg-slate-800/80 hover:bg-slate-700 text-cyan-300 font-mono border border-slate-700/50 transition-colors"
              >
                {p}
              </button>
            ))}
          </div>

          {errorMessage && (
            <div className="mt-4 p-3 rounded-xl bg-rose-950/50 border border-rose-800 text-rose-300 text-xs font-medium flex items-center gap-2">
              <Icons.AlertTriangle />
              <span>{errorMessage}</span>
            </div>
          )}
        </section>

        {/* ==================================================================== */}
        {/* Real-time Progress Bar & Stage Stepper */}
        {/* ==================================================================== */}
        {scanStatus && (
          <section className="bg-slate-900/60 rounded-2xl border border-slate-800 p-5 shadow-xl no-print">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
              <div className="flex items-center gap-3">
                <span className={`inline-block w-3 h-3 rounded-full ${isScanningActive ? 'bg-cyan-400 animate-ping' : scanStatus.is_completed ? 'bg-emerald-400' : 'bg-amber-400'}`} />
                <span className="font-bold text-sm text-slate-200">
                  {scanStatus.is_completed ? 'اكتمل الفحص الأمني بنجاح' : scanStatus.current_stage === 'stopped' ? 'تم إيقاف الفحص' : 'الفحص الأمني قيد التشغيل المباشر...'}
                </span>
                <span dir="ltr" className="text-xs px-2.5 py-0.5 rounded-full bg-slate-800 border border-slate-700 font-mono text-cyan-400">
                  {scanStatus.current_tool || 'YemenScan Engine'}
                </span>
              </div>
              <div className="text-left font-mono font-black text-cyan-400 text-base">
                {scanStatus.progress_percentage || 0}%
              </div>
            </div>

            {/* Glowing progress bar */}
            <div className="w-full h-3 rounded-full bg-slate-950 overflow-hidden border border-slate-800 p-0.5">
              <div
                className="h-full rounded-full bg-gradient-to-r from-blue-600 via-cyan-400 to-emerald-400 transition-all duration-500 shadow-sm shadow-cyan-400"
                style={{ width: `${Math.min(100, Math.max(0, scanStatus.progress_percentage || 0))}%` }}
              />
            </div>

            {/* Stepper indicators */}
            <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
              <div className={`p-2.5 rounded-xl border flex items-center gap-2.5 ${scanStatus.current_stage.includes('phase1') ? 'bg-cyan-950/40 border-cyan-500/50 text-cyan-300' : 'bg-slate-950/40 border-slate-800/80 text-slate-400'}`}>
                <span className="w-5 h-5 rounded-full flex items-center justify-center bg-slate-800 font-mono text-[10px] font-bold">1</span>
                <div>
                  <div className="font-bold">المرحلة الأولى: الاستكشاف</div>
                  <div className="text-[11px] text-slate-500 font-mono">Subfinder + Naabu</div>
                </div>
              </div>
              <div className={`p-2.5 rounded-xl border flex items-center gap-2.5 ${scanStatus.current_stage.includes('phase2') ? 'bg-cyan-950/40 border-cyan-500/50 text-cyan-300' : 'bg-slate-950/40 border-slate-800/80 text-slate-400'}`}>
                <span className="w-5 h-5 rounded-full flex items-center justify-center bg-slate-800 font-mono text-[10px] font-bold">2</span>
                <div>
                  <div className="font-bold">المرحلة الثانية: الخوادم والـ APIs</div>
                  <div className="text-[11px] text-slate-500 font-mono">HTTPX + Kiterunner</div>
                </div>
              </div>
              <div className={`p-2.5 rounded-xl border flex items-center gap-2.5 ${scanStatus.current_stage.includes('phase3') ? 'bg-cyan-950/40 border-cyan-500/50 text-cyan-300' : 'bg-slate-950/40 border-slate-800/80 text-slate-400'}`}>
                <span className="w-5 h-5 rounded-full flex items-center justify-center bg-slate-800 font-mono text-[10px] font-bold">3</span>
                <div>
                  <div className="font-bold">المرحلة الثالثة: فحص الثغرات</div>
                  <div className="text-[11px] text-slate-500 font-mono">Nuclei (CVEs) + Wapiti</div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* ==================================================================== */}
        {/* Metrics & Statistical Cards */}
        {/* ==================================================================== */}
        <section className="grid grid-cols-2 lg:grid-cols-5 gap-3 md:gap-4">
          <div className="p-4 rounded-2xl bg-slate-900/50 border border-slate-800 hover:border-slate-700 transition-all shadow-md">
            <div className="flex items-center justify-between text-slate-400 text-xs font-bold mb-2">
              <span>النطاقات الفرعية</span>
              <Icons.Globe />
            </div>
            <div className="text-2xl md:text-3xl font-black text-sky-400 font-mono">{stats.subdomains_count}</div>
            <div className="text-[11px] text-slate-500 mt-1">المكتشفة عبر Subfinder</div>
          </div>

          <div className="p-4 rounded-2xl bg-slate-900/50 border border-slate-800 hover:border-slate-700 transition-all shadow-md">
            <div className="flex items-center justify-between text-slate-400 text-xs font-bold mb-2">
              <span>المنافذ المفتوحة</span>
              <Icons.Server />
            </div>
            <div className="text-2xl md:text-3xl font-black text-indigo-400 font-mono">{stats.open_ports_count}</div>
            <div className="text-[11px] text-slate-500 mt-1">مرصودة بواسطة Naabu</div>
          </div>

          <div className="p-4 rounded-2xl bg-slate-900/50 border border-slate-800 hover:border-slate-700 transition-all shadow-md">
            <div className="flex items-center justify-between text-slate-400 text-xs font-bold mb-2">
              <span>الخدمات النشطة</span>
              <Icons.Globe />
            </div>
            <div className="text-2xl md:text-3xl font-black text-emerald-400 font-mono">{stats.live_urls_count}</div>
            <div className="text-[11px] text-slate-500 mt-1">خوادم ويب حية (HTTPX)</div>
          </div>

          <div className="p-4 rounded-2xl bg-slate-900/50 border border-slate-800 hover:border-slate-700 transition-all shadow-md">
            <div className="flex items-center justify-between text-slate-400 text-xs font-bold mb-2">
              <span>مسارات الـ APIs</span>
              <Icons.Cpu />
            </div>
            <div className="text-2xl md:text-3xl font-black text-amber-400 font-mono">{stats.api_endpoints_count}</div>
            <div className="text-[11px] text-slate-500 mt-1">موجهات Kiterunner</div>
          </div>

          <div className="col-span-2 lg:col-span-1 p-4 rounded-2xl bg-slate-900/50 border border-rose-900/30 hover:border-rose-700/50 transition-all shadow-md">
            <div className="flex items-center justify-between text-slate-400 text-xs font-bold mb-2">
              <span>الثغرات الأمنية</span>
              <Icons.AlertTriangle />
            </div>
            <div className="text-2xl md:text-3xl font-black text-rose-400 font-mono">{stats.vulnerabilities_count}</div>
            <div className="flex items-center gap-1.5 mt-2 flex-wrap text-[10px] font-mono">
              <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 font-bold border border-rose-800">
                C: {stats.vuln_by_severity?.critical || 0}
              </span>
              <span className="px-1.5 py-0.5 rounded bg-orange-950 text-orange-300 font-bold border border-orange-800">
                H: {stats.vuln_by_severity?.high || 0}
              </span>
              <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 font-bold border border-amber-800">
                M: {stats.vuln_by_severity?.medium || 0}
              </span>
            </div>
          </div>
        </section>

        {/* ==================================================================== */}
        {/* Navigation Tabs */}
        {/* ==================================================================== */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2 no-print">
          <button
            type="button"
            onClick={() => setActiveTab('assets')}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold text-sm transition-all cursor-pointer ${activeTab === 'assets' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-md' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'}`}
          >
            <Icons.Globe />
            <span>الأصول والمسارات المكتشفة ({filteredAssets.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('vulnerabilities')}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold text-sm transition-all cursor-pointer ${activeTab === 'vulnerabilities' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30 shadow-md' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'}`}
          >
            <Icons.AlertTriangle />
            <span>سجل الثغرات الأمنية ({filteredVulnerabilities.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('ai-report')}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold text-sm transition-all cursor-pointer ${activeTab === 'ai-report' ? 'bg-purple-500/10 text-purple-400 border border-purple-500/30 shadow-md' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'}`}
          >
            <Icons.Sparkles />
            <span>استشارات الذكاء الاصطناعي (AI Advisory)</span>
          </button>
        </div>

        {/* ==================================================================== */}
        {/* Tab 1: Assets & Endpoints */}
        {/* ==================================================================== */}
        {activeTab === 'assets' && (
          <section className="bg-slate-900/60 rounded-2xl border border-slate-800 p-5 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 no-print">
              <div className="relative flex-1 max-w-md">
                <input
                  type="text"
                  dir="ltr"
                  value={assetsFilter}
                  onChange={(e) => setAssetsFilter(e.target.value)}
                  placeholder="بحث في الروابط أو العناوين..."
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-700 text-sm font-mono text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs font-bold">
                {(['all', 'web', 'api'] as const).map(t => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setAssetsTypeFilter(t)}
                    className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${assetsTypeFilter === t ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-white'}`}
                  >
                    {t === 'all' ? 'الكل' : t === 'web' ? 'خوادم الويب' : 'واجهات APIs'}
                  </button>
                ))}
              </div>
            </div>

            <div className="overflow-x-auto rounded-xl border border-slate-800">
              <table className="w-full text-right text-sm">
                <thead className="bg-slate-950/80 text-xs font-bold text-slate-400 uppercase border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">النوع</th>
                    <th className="px-4 py-3">الرابط / المسار المستكشف</th>
                    <th className="px-4 py-3">كود الحالة</th>
                    <th className="px-4 py-3">التفاصيل والتقنيات</th>
                    <th className="px-4 py-3 text-left">إجراء</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
                  {filteredAssets.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="text-center py-8 text-slate-500 font-sans">
                        لا توجد أصول مطابقة لمعايير البحث الحالية.
                      </td>
                    </tr>
                  ) : (
                    filteredAssets.map((asset, idx) => (
                      <tr key={idx} className="hover:bg-slate-850/50 transition-colors">
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${asset.type === 'web' ? 'bg-sky-950 text-sky-400 border border-sky-800' : 'bg-amber-950 text-amber-400 border border-amber-800'}`}>
                            {asset.type === 'web' ? 'WEB' : 'API'}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-semibold text-slate-200">
                          <span dir="ltr" className="select-all">{asset.url}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded font-bold ${asset.code === 200 ? 'text-emerald-400 bg-emerald-950/60' : asset.code === 401 || asset.code === 403 ? 'text-amber-400 bg-amber-950/60' : 'text-slate-400 bg-slate-800'}`}>
                            {asset.code || 200}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-slate-400 font-sans">
                          {asset.details}
                        </td>
                        <td className="px-4 py-3 text-left">
                          <a
                            href={asset.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-sans text-xs hover:underline"
                          >
                            <span>فتح</span>
                            <Icons.ExternalLink />
                          </a>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* ==================================================================== */}
        {/* Tab 2: Vulnerabilities */}
        {/* ==================================================================== */}
        {activeTab === 'vulnerabilities' && (
          <section className="bg-slate-900/60 rounded-2xl border border-slate-800 p-5 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 no-print">
              <div className="relative flex-1 max-w-md">
                <input
                  type="text"
                  dir="ltr"
                  value={vulnSearch}
                  onChange={(e) => setVulnSearch(e.target.value)}
                  placeholder="بحث في اسم الثغرة، CVE، CWE، الرابط..."
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-700 text-sm font-mono text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-rose-500"
                />
              </div>

              {/* Severity Pill Filters */}
              <div className="flex items-center gap-1.5 flex-wrap text-xs font-bold">
                {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map(sev => (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => setVulnSeverityFilter(sev)}
                    className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${vulnSeverityFilter === sev ? (sev === 'CRITICAL' ? 'bg-rose-600 text-white' : sev === 'HIGH' ? 'bg-orange-600 text-white' : sev === 'MEDIUM' ? 'bg-amber-600 text-slate-950' : 'bg-cyan-500 text-slate-950') : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'}`}
                  >
                    {sev === 'ALL' ? 'الكل' : sev}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-3">
              {filteredVulnerabilities.length === 0 ? (
                <div className="text-center py-12 bg-slate-950/40 rounded-xl border border-slate-800/80">
                  <div className="inline-block p-3 rounded-full bg-emerald-950/50 text-emerald-400 mb-2">
                    <Icons.Check />
                  </div>
                  <h4 className="text-base font-bold text-slate-200">لا توجد ثغرات مكشوفة مطابقة</h4>
                  <p className="text-xs text-slate-500 mt-1">تم اجتياز اختبارات الأمان أو لا توجد نتائج لمعيار التصفية الحالي.</p>
                </div>
              ) : (
                filteredVulnerabilities.map((vuln, idx) => {
                  const sev = vuln.severity.toUpperCase() as SeverityLevel;
                  const isExpanded = expandedVulnId === (vuln.id || String(idx));
                  const sevColor =
                    sev === 'CRITICAL' ? 'border-rose-500/50 bg-rose-950/10' :
                    sev === 'HIGH' ? 'border-orange-500/50 bg-orange-950/10' :
                    sev === 'MEDIUM' ? 'border-amber-500/50 bg-amber-950/10' :
                    'border-cyan-500/50 bg-cyan-950/10';

                  const cvssVal = vuln.cvss_score != null ? Number(vuln.cvss_score) : null;
                  const cvssBadgeClass =
                    cvssVal === null ? 'bg-slate-800/80 text-slate-400 border-slate-700' :
                    cvssVal >= 9.0 ? 'bg-rose-950/80 text-rose-300 border-rose-700 font-black' :
                    cvssVal >= 7.0 ? 'bg-orange-950/80 text-orange-300 border-orange-700 font-bold' :
                    cvssVal >= 4.0 ? 'bg-amber-950/80 text-amber-300 border-amber-700 font-semibold' :
                    cvssVal > 0 ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700 font-medium' :
                    'bg-slate-800/80 text-slate-400 border-slate-700';

                  return (
                    <div
                      key={vuln.id || idx}
                      className={`rounded-xl border transition-all p-4 break-inside-avoid ${sevColor}`}
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2.5 flex-wrap">
                          <span className={`px-2.5 py-0.5 rounded-full text-xs font-black font-mono tracking-wide ${sev === 'CRITICAL' ? 'bg-rose-900/80 text-rose-200 border border-rose-700' : sev === 'HIGH' ? 'bg-orange-900/80 text-orange-200 border border-orange-700' : sev === 'MEDIUM' ? 'bg-amber-900/80 text-amber-200 border border-amber-700' : 'bg-slate-800 text-slate-300'}`}>
                            {sev}
                          </span>
                          <h4 className="font-bold text-sm md:text-base text-white">{vuln.title}</h4>
                          {vuln.cve_id && (
                            <span dir="ltr" className="px-2 py-0.5 rounded bg-slate-800 font-mono text-xs text-cyan-400 border border-slate-700">
                              {vuln.cve_id}
                            </span>
                          )}
                          {cvssVal !== null ? (
                            <span
                              dir="ltr"
                              title={vuln.cvss_vector ? `${vuln.cvss_vector} (درجة ${cvssVal.toFixed(1)})` : `CVSS Base: ${cvssVal.toFixed(1)}`}
                              className={`px-2 py-0.5 rounded font-mono text-xs border flex items-center gap-1 ${cvssBadgeClass}`}
                            >
                              <span>⚡</span>
                              <span>CVSS {cvssVal.toFixed(1)}</span>
                            </span>
                          ) : (
                            <span dir="ltr" title="درجة CVSS غير محددة" className="px-2 py-0.5 rounded bg-slate-800/60 font-mono text-xs text-slate-500 border border-slate-800">
                              CVSS N/A
                            </span>
                          )}
                          {vuln.cwe_id && (
                            <span dir="ltr" className="px-2 py-0.5 rounded bg-purple-950/60 font-mono text-xs text-purple-300 border border-purple-800/50">
                              {vuln.cwe_id}
                            </span>
                          )}
                        </div>

                        <button
                          type="button"
                          onClick={() => setExpandedVulnId(isExpanded ? null : (vuln.id || String(idx)))}
                          className="text-xs font-bold text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-1 self-end sm:self-auto cursor-pointer no-print"
                        >
                          <span>{isExpanded ? 'إخفاء التفاصيل' : 'عرض التفاصيل والمعالجة'}</span>
                        </button>
                      </div>

                      {/* Summary URL */}
                      <div className="mt-2 text-xs text-slate-400 font-mono">
                        <span className="font-sans text-slate-500 font-bold">الرابط المتأثر: </span>
                        <span dir="ltr" className="text-cyan-300 select-all">{vuln.url}</span>
                      </div>

                      {/* Expandable Technical Details */}
                      {isExpanded && (
                        <div className="mt-4 pt-4 border-t border-slate-800/80 space-y-3 text-xs md:text-sm">
                          {vuln.description && (
                            <div>
                              <span className="font-bold text-slate-300 block mb-1">وصف الثغرة:</span>
                              <p className="text-slate-400 leading-relaxed">{vuln.description}</p>
                            </div>
                          )}

                          {(cvssVal !== null || vuln.cvss_vector || vuln.owasp_category) && (
                            <div className="flex items-center gap-2 flex-wrap text-xs">
                              {cvssVal !== null && (
                                <div className="flex items-center gap-1.5">
                                  <span className="font-bold text-slate-300">مقياس CVSS v3.1:</span>
                                  <span className={`px-2 py-0.5 rounded font-mono font-bold border ${cvssBadgeClass}`}>
                                    درجة {cvssVal.toFixed(1)}
                                  </span>
                                </div>
                              )}
                              {vuln.cvss_vector && (
                                <code dir="ltr" className="px-2 py-0.5 rounded bg-slate-950 text-cyan-300 font-mono text-xs border border-slate-800 select-all" title="CVSS v3.1 Vector String">
                                  {vuln.cvss_vector}
                                </code>
                              )}
                              {vuln.owasp_category && (
                                <div className="flex items-center gap-1.5 mr-auto">
                                  <span className="font-bold text-slate-300">تصنيف OWASP:</span>
                                  <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-xs border border-slate-700">
                                    {vuln.owasp_category}
                                  </span>
                                </div>
                              )}
                            </div>
                          )}

                          {vuln.evidence && (
                            <div>
                              <span className="font-bold text-slate-300 block mb-1">دليل الاستغلال (Evidence):</span>
                              <pre dir="ltr" className="p-3 rounded-lg bg-slate-950 font-mono text-xs text-rose-300 border border-slate-800 overflow-x-auto text-left whitespace-pre-wrap">
                                <code>{vuln.evidence}</code>
                              </pre>
                            </div>
                          )}

                          {vuln.remediation && (
                            <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-800/50">
                              <span className="font-bold text-emerald-400 block mb-1">خطوات المعالجة المقترحة (Remediation):</span>
                              <p className="text-slate-300 leading-relaxed font-sans">{vuln.remediation}</p>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </section>
        )}

        {/* ==================================================================== */}
        {/* Tab 3: AI Advisory Reports */}
        {/* ==================================================================== */}
        {activeTab === 'ai-report' && (
          <section className="bg-slate-900/60 rounded-2xl border border-slate-800 p-5 md:p-6 shadow-xl space-y-6">
            
            {/* Report Type Switcher & Action Bar */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5 no-print">
              <div className="flex items-center gap-2 bg-slate-950 p-1 rounded-xl border border-slate-800">
                <button
                  type="button"
                  onClick={() => {
                    setReportType('executive');
                    loadAiReport(activeScanId, 'executive');
                  }}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg font-bold text-xs md:text-sm transition-all cursor-pointer ${reportType === 'executive' ? 'bg-cyan-500 text-slate-950 shadow-md' : 'text-slate-400 hover:text-white'}`}
                >
                  <Icons.Shield />
                  <span>التقرير التنفيذي للإدارة العليا (CISO)</span>
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setReportType('technical');
                    loadAiReport(activeScanId, 'technical');
                  }}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg font-bold text-xs md:text-sm transition-all cursor-pointer ${reportType === 'technical' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-400 hover:text-white'}`}
                >
                  <Icons.Cpu />
                  <span>التقرير التقني المفصل (SysAdmins)</span>
                </button>
              </div>

              {/* Status Badges & Export Buttons */}
              <div className="flex items-center gap-2 flex-wrap">
                {aiReportModel && (
                  <span className="text-[11px] px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 font-mono border border-slate-700">
                    {aiReportModel} {aiReportCached ? '• مخزن في DB' : ''}
                  </span>
                )}

                <button
                  type="button"
                  onClick={() => loadAiReport(activeScanId, reportType, true)}
                  disabled={isLoadingAiReport}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-bold transition-all cursor-pointer"
                  title="إعادة توليد التقرير الأمني عبر Gemini"
                >
                  <Icons.Refresh />
                  <span>{isLoadingAiReport ? 'جاري التوليد...' : 'تحديث التقرير'}</span>
                </button>

                {exportUrls && (
                  <>
                    <a
                      href={exportUrls.markdown}
                      download
                      className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 text-xs font-bold transition-all"
                    >
                      <Icons.Download />
                      <span>Markdown (.md)</span>
                    </a>
                    <a
                      href={exportUrls.html}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-emerald-400 border border-slate-700 text-xs font-bold transition-all"
                    >
                      <Icons.ExternalLink />
                      <span>تقرير HTML</span>
                    </a>
                  </>
                )}
              </div>
            </div>

            {/* Print Header Visible ONLY When Printing */}
            <div className="hidden print:block mb-6 border-b-2 border-slate-900 pb-4">
              <h1 className="text-2xl font-black text-slate-900">
                منصة YemenScan للتقييم الأمني وفحص الثغرات
              </h1>
              <p className="text-xs text-slate-600 font-mono mt-1">
                النطاق: {domainInput || 'المستهدف'} | معرف الجلسة: {activeScanId} | نوع التقرير: {reportType === 'executive' ? 'تنفيذي' : 'تقني'}
              </p>
            </div>

            {/* AI Report Body */}
            {isLoadingAiReport ? (
              <div className="py-20 text-center space-y-4">
                <div className="inline-block animate-spin text-3xl">✨</div>
                <h4 className="text-lg font-bold text-slate-200">يقوم محرك الذكاء الاصطناعي (Gemini) بصياغة التقرير الآن...</h4>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  يتم تحليل نتائج الفحص، مواءمة معايير OWASP، وعزل الأكواد البرمجية وفق الموجهات الأمنية الصارمة.
                </p>
              </div>
            ) : aiReportMarkdown ? (
              <div className="bg-slate-950/70 p-6 md:p-8 rounded-2xl border border-slate-800/80 shadow-inner">
                <SafeMarkdownViewer content={aiReportMarkdown} />
              </div>
            ) : (
              <div className="py-16 text-center text-slate-500">
                لا يوجد تقرير مولد لهذه الجلسة بعد. اضغط على زر "تحديث التقرير" لإنشائه.
              </div>
            )}
          </section>
        )}

      </main>

      {/* ==================================================================== */}
      {/* Global Embedded Print Styling preventing Page-Break inside code */}
      {/* ==================================================================== */}
      <style>{`
        @media print {
          body {
            background-color: #ffffff !important;
            color: #0f172a !important;
          }
          .no-print {
            display: none !important;
          }
          .break-inside-avoid, pre, code, tr {
            break-inside: avoid !important;
            page-break-inside: avoid !important;
          }
          pre {
            background-color: #0f172a !important;
            color: #38bdf8 !important;
            border: 1px solid #cbd5e1 !important;
          }
          h1, h2, h3, h4 {
            color: #0f172a !important;
          }
          p, li {
            color: #334155 !important;
          }
        }
      `}</style>
    </div>
  );
};

export default Dashboard;
