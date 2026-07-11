import { Shield, AlertTriangle, Cpu, Globe, Database } from 'lucide-react';
import { ScoredWindow } from '../types/netlog';

interface DashboardOverviewProps {
  windows: ScoredWindow[];
  summary: {
    totalLogs: number;
    totalWindows: number;
    anomalyCount: number;
    preset: string;
    windowMinutes: number;
    contamination: number;
  } | null;
  selectedWindow: ScoredWindow | null;
}

export default function DashboardOverview({ windows, summary, selectedWindow }: DashboardOverviewProps) {
  if (!summary) return null;

  // Compute unique source IPs across all windows
  const uniqueIps = new Set<string>();
  windows.forEach(w => {
    w.rawLogs.forEach(l => {
      if (l.metadata.srcIp) uniqueIps.add(l.metadata.srcIp);
    });
  });

  const anomalyPercentage = windows.length > 0
    ? ((summary.anomalyCount / windows.length) * 100).toFixed(1)
    : '0.0';

  const presetsMap: Record<string, string> = {
    clean: 'Baseline (Clean Operations)',
    brute_force: 'Active SSH Brute-Force',
    port_scan: 'Reconnaissance Port Scan',
    interface_flap: 'Interface Hardware Flapping',
    config_tamper: 'Unauthorized Config Mod',
    all_mixed: 'Multi-Vector Combined Attack'
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
      {/* KPI 1: Status */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 flex items-center space-x-4 relative overflow-hidden shadow-sm">
        <div className="absolute right-0 top-0 w-24 h-24 bg-emerald-500/5 rounded-full blur-2xl" />
        <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-100 text-emerald-600">
          <Shield className="w-6 h-6" />
        </div>
        <div>
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider">Engine Status</p>
          <p className="text-base font-bold text-slate-900 flex items-center space-x-2 mt-0.5">
            <span className="w-2.5 h-2.5 bg-emerald-500 rounded-full animate-ping mr-1" />
            <span>Active Sentinel</span>
          </p>
          <p className="text-xs text-slate-500 font-mono mt-0.5 truncate max-w-[150px]">
            {presetsMap[summary.preset] || summary.preset}
          </p>
        </div>
      </div>

      {/* KPI 2: Total Logs Ingested */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 flex items-center space-x-4 relative overflow-hidden shadow-sm">
        <div className="absolute right-0 top-0 w-24 h-24 bg-blue-500/5 rounded-full blur-2xl" />
        <div className="p-3 rounded-lg bg-blue-50 border border-blue-100 text-blue-600">
          <Database className="w-6 h-6" />
        </div>
        <div>
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider">Syslogs Scanned</p>
          <p className="text-2xl font-bold font-mono text-slate-900 mt-0.5">
            {summary.totalLogs.toLocaleString()}
          </p>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            across {summary.totalWindows} windows
          </p>
        </div>
      </div>

      {/* KPI 3: Anomalies Detected */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 flex items-center space-x-4 relative overflow-hidden shadow-sm">
        <div className="absolute right-0 top-0 w-24 h-24 bg-rose-500/5 rounded-full blur-2xl" />
        <div className="p-3 rounded-lg bg-rose-50 border border-rose-100 text-rose-600">
          <AlertTriangle className="w-6 h-6" />
        </div>
        <div>
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider">ML Anomaly Flags</p>
          <p className="text-2xl font-bold font-mono text-rose-600 mt-0.5">
            {summary.anomalyCount}
          </p>
          <p className="text-xs text-rose-600 font-medium mt-0.5">
            {anomalyPercentage}% anomaly rate
          </p>
        </div>
      </div>

      {/* KPI 4: Unique Connecting IPs */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 flex items-center space-x-4 relative overflow-hidden shadow-sm">
        <div className="absolute right-0 top-0 w-24 h-24 bg-indigo-500/5 rounded-full blur-2xl" />
        <div className="p-3 rounded-lg bg-indigo-50 border border-indigo-100 text-indigo-600">
          <Globe className="w-6 h-6" />
        </div>
        <div>
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider">Monitored IPs</p>
          <p className="text-2xl font-bold font-mono text-slate-900 mt-0.5">
            {uniqueIps.size}
          </p>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            GDPR hashed by default
          </p>
        </div>
      </div>

      {/* KPI 5: Model Config */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 flex items-center space-x-4 relative overflow-hidden shadow-sm">
        <div className="absolute right-0 top-0 w-24 h-24 bg-amber-500/5 rounded-full blur-2xl" />
        <div className="p-3 rounded-lg bg-amber-50 border border-amber-100 text-amber-600">
          <Cpu className="w-6 h-6" />
        </div>
        <div>
          <p className="text-xs text-slate-500 font-bold uppercase tracking-wider">Isolation Forest</p>
          <p className="text-base font-bold text-slate-900 font-mono mt-0.5">
            Contam: {summary.contamination * 100}%
          </p>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            {summary.windowMinutes}m interval slice
          </p>
        </div>
      </div>
    </div>
  );
}
