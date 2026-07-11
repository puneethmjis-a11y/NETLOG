import { useState } from 'react';
import { Eye, EyeOff, Search, Info, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { RawLogLine } from '../types/netlog';

interface LogsConsoleProps {
  logs: RawLogLine[];
  timestamp: string;
}

export default function LogsConsole({ logs, timestamp }: LogsConsoleProps) {
  const [maskPii, setMaskPii] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<number | 'all'>('all');

  // Filter logs
  const filteredLogs = logs.filter(log => {
    const matchesSearch = 
      log.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.mnemonic.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.host.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesSeverity = severityFilter === 'all' || log.severity === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  // Severity style helper
  const getSeverityBadge = (sev: number) => {
    switch (sev) {
      case 0:
      case 1:
      case 2:
      case 3:
        return 'bg-rose-500/20 text-rose-300 border border-rose-500/30';
      case 4:
      case 5:
        return 'bg-amber-500/20 text-amber-300 border border-amber-500/30';
      case 6:
        return 'bg-blue-500/20 text-blue-300 border border-blue-500/30';
      case 7:
      default:
        return 'bg-slate-500/20 text-slate-300 border border-slate-500/30';
    }
  };

  const getSeverityName = (sev: number) => {
    const names = ['EMERG', 'ALERT', 'CRIT', 'ERROR', 'WARN', 'NOTICE', 'INFO', 'DEBUG'];
    return `${sev} - ${names[sev] || 'INFO'}`;
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5 flex flex-col h-full space-y-4 shadow-sm">
      {/* Header Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200 pb-4">
        <div>
          <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
            <span className="w-2.5 h-2.5 bg-emerald-500 rounded-full animate-pulse" />
            <span>Interactive Real-time Syslog Console</span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Ingested <strong className="text-slate-800 font-bold">{filteredLogs.length}</strong> logs for window {timestamp}
          </p>
        </div>

        {/* PII Toggle */}
        <button
          onClick={() => setMaskPii(!maskPii)}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold border flex items-center space-x-1.5 transition-all cursor-pointer ${
            maskPii 
              ? 'bg-violet-50 text-violet-700 border-violet-200 hover:bg-violet-100/50'
              : 'bg-amber-50 text-amber-700 border-amber-200 hover:bg-amber-100/50'
          }`}
        >
          {maskPii ? (
            <>
              <EyeOff className="w-3.5 h-3.5 animate-pulse" />
              <span>PII Masking Active</span>
            </>
          ) : (
            <>
              <Eye className="w-3.5 h-3.5" />
              <span className="font-semibold text-rose-600">WARNING: PII Raw IPs Exposed</span>
            </>
          )}
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3">
        {/* Search */}
        <div className="relative flex-grow">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by message, host, or mnemonic (e.g. UPDOWN)..."
            className="w-full bg-slate-50 border border-slate-200 rounded-lg py-1.5 pl-9 pr-4 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:border-blue-500 font-mono transition-all"
          />
        </div>

        {/* Severity dropdown */}
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value === 'all' ? 'all' : Number(e.target.value))}
          className="bg-slate-50 border border-slate-200 rounded-lg py-1.5 px-3 text-xs text-slate-700 font-mono focus:outline-none focus:border-blue-500 cursor-pointer"
        >
          <option value="all">Severity: All Levels</option>
          {[0, 1, 2, 3, 4, 5, 6, 7].map(lvl => (
            <option key={lvl} value={lvl}>{getSeverityName(lvl)}</option>
          ))}
        </select>
      </div>

      {/* GDPR Safe Banner */}
      <div className="bg-slate-50 rounded-lg p-2.5 border border-slate-200 flex items-start space-x-2 text-[10px] font-mono leading-relaxed">
        {maskPii ? (
          <>
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
            <span className="text-slate-600">
              <strong className="text-emerald-700">GDPR Compliance Verified:</strong> Raw IP addresses and operator usernames are stripped and masked with <code className="text-violet-600 bg-violet-50 border border-violet-100 px-1 py-0.5 rounded">SHA-256 (Salted)</code> keys at the edge. Downstream Isolation Forest algorithm operates only on un-identifiable tokens.
            </span>
          </>
        ) : (
          <>
            <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
            <span className="text-rose-600">
              <strong className="text-rose-700 font-bold">Audit Mode Active:</strong> Displaying RAW syslog lines containing cleartext IP addresses. Do not export this log stream to public logging platforms.
            </span>
          </>
        )}
      </div>

      {/* Scrolling Log stream */}
      <div className="bg-slate-950 border border-slate-900 rounded-lg p-3 overflow-y-auto max-h-[350px] font-mono text-[11px] leading-relaxed flex-grow min-h-[220px]">
        {filteredLogs.length === 0 ? (
          <div className="text-center py-12 text-slate-500 italic flex flex-col items-center justify-center space-y-2">
            <Info className="w-5 h-5 text-slate-600" />
            <span>No log entries match the search/severity criteria.</span>
          </div>
        ) : (
          <div className="space-y-2">
            {filteredLogs.map((log) => {
              const displayLine = maskPii ? log.maskedLine : log.rawLine;
              
              // We want to highlight the IPs / Usernames beautifully in our console
              const highlightPii = (text: string) => {
                if (maskPii) {
                  // Find masked tokens e.g. "abcdef12.ip" or "abcdef12.usr" and highlight them in violet
                  const parts = text.split(/([a-f0-9]{8}\.ip|[a-f0-9]{8}\.usr)/);
                  return parts.map((part, i) => {
                    const isMaskedIp = part.endsWith('.ip');
                    const isMaskedUsr = part.endsWith('.usr');
                    if (isMaskedIp || isMaskedUsr) {
                      return (
                        <span key={i} className="px-1 py-0.5 rounded bg-violet-950 text-violet-300 font-bold border border-violet-800/30" title="Salted Hash PII Mask">
                          {part}
                        </span>
                      );
                    }
                    return part;
                  });
                } else {
                  // Highlight raw IPs or Usernames in amber if exposed
                  const parts = text.split(/(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|for\s+user\s+([a-zA-Z0-9_\-\.]+)|by\s+user\s+([a-zA-Z0-9_\-\.]+))/i);
                  return parts.map((part, i) => {
                    const isIp = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/.test(part);
                    const isUser = /user/i.test(part);
                    if (isIp || isUser) {
                      return (
                        <span key={i} className="px-1 py-0.5 rounded bg-amber-950 text-amber-300 font-bold border border-amber-800/30" title="Unmasked Sensitive Data">
                          {part}
                        </span>
                      );
                    }
                    return part;
                  });
                }
              };

              return (
                <div key={log.id} className="flex items-start py-1 border-b border-slate-900 hover:bg-slate-900/30 px-1.5 rounded transition-all">
                  {/* Severity Badge */}
                  <span className={`w-18 text-center px-1.5 py-0.5 rounded text-[9px] font-bold uppercase shrink-0 mr-3 mt-0.5 ${getSeverityBadge(log.severity)}`}>
                    {getSeverityName(log.severity).substring(4)}
                  </span>
                  
                  {/* Log timestamp and line */}
                  <div className="flex-grow min-w-0">
                    <span className="text-slate-500 mr-2 shrink-0 select-none">
                      {new Date(log.timestamp).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: false })}
                    </span>
                    <span className="text-slate-300 break-words whitespace-pre-wrap leading-relaxed">
                      {highlightPii(displayLine)}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
