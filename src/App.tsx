import { useState, useEffect } from 'react';
import { Shield, Sparkles, Activity, AlertTriangle, Play, RefreshCw, Cpu, Server, HelpCircle } from 'lucide-react';
import { ScoredWindow } from './types/netlog';
import DashboardOverview from './components/DashboardOverview';
import AnomalyTimeline from './components/AnomalyTimeline';
import WindowDetailsPanel from './components/WindowDetailsPanel';
import LogsConsole from './components/LogsConsole';
import PipelineController from './components/PipelineController';

export default function App() {
  const [windows, setWindows] = useState<ScoredWindow[]>([]);
  const [summary, setSummary] = useState<any | null>(null);
  const [selectedWindow, setSelectedWindow] = useState<ScoredWindow | null>(null);
  const [selectedWindowLogs, setSelectedWindowLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [logsLoading, setLogsLoading] = useState<boolean>(false);
  const [serverStatus, setServerStatus] = useState<any>(null);

  // Fetch server status on mount
  useEffect(() => {
    fetch('/api/status')
      .then(res => res.json())
      .then(data => setServerStatus(data))
      .catch(err => console.error('Error fetching server status:', err));
  }, []);

  // Run pipeline at least once with standard mix on launch to populate the UI beautifully!
  useEffect(() => {
    handleRunPipeline({ preset: 'all_mixed', windowMinutes: 5, contamination: 0.05 });
  }, []);

  // Fetch logs when selected window changes
  useEffect(() => {
    if (!selectedWindow) {
      setSelectedWindowLogs([]);
      return;
    }

    setLogsLoading(true);
    fetch(`/api/window/${selectedWindow.windowId}/logs`)
      .then(res => {
        if (!res.ok) throw new Error();
        return res.json();
      })
      .then(data => {
        setSelectedWindowLogs(data.logs || []);
      })
      .catch(err => {
        console.error('Error fetching logs for window:', err);
        // Fallback: use window's nested rawLogs if available (uncompressed)
        setSelectedWindowLogs(selectedWindow.rawLogs || []);
      })
      .finally(() => {
        setLogsLoading(false);
      });
  }, [selectedWindow?.windowId]);

  const handleRunPipeline = async (params: { preset: string; windowMinutes: number; contamination: number }) => {
    setLoading(true);
    try {
      const res = await fetch('/api/pipeline/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params)
      });
      const data = await res.json();
      if (data.success) {
        setWindows(data.windows);
        setSummary(data.summary);
        
        // Auto-select the most extreme anomaly window if any exists, otherwise select the first window
        const anomalies = data.windows.filter((w: ScoredWindow) => w.isAnomaly);
        if (anomalies.length > 0) {
          const sortedAnomalies = [...anomalies].sort((a, b) => b.anomalyScore - a.anomalyScore);
          setSelectedWindow(sortedAnomalies[0]);
        } else if (data.windows.length > 0) {
          setSelectedWindow(data.windows[Math.floor(data.windows.length / 2)]); // pick mid node
        }
      }
    } catch (error) {
      console.error('Pipeline call failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleUploadLogs = async (params: { rawLogsText: string; windowMinutes: number; contamination: number }) => {
    setLoading(true);
    try {
      const res = await fetch('/api/pipeline/upload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params)
      });
      const data = await res.json();
      if (data.success) {
        setWindows(data.windows);
        setSummary(data.summary);
        
        // Auto-select the most extreme anomaly window if any exists, otherwise select first
        const anomalies = data.windows.filter((w: ScoredWindow) => w.isAnomaly);
        if (anomalies.length > 0) {
          const sortedAnomalies = [...anomalies].sort((a, b) => b.anomalyScore - a.anomalyScore);
          setSelectedWindow(sortedAnomalies[0]);
        } else if (data.windows.length > 0) {
          setSelectedWindow(data.windows[0]);
        }
      } else {
        alert(`Analysis failed: ${data.error}`);
      }
    } catch (error: any) {
      console.error('Upload call failed:', error);
      alert(`Connection failed: ${error.message || error}`);
    } finally {
      setLoading(false);
    }
  };

  // Callback to update local state if Gemini generates a report for a specific window
  const handleUpdateWindow = (updatedWin: ScoredWindow) => {
    setWindows(prev => prev.map(w => w.windowId === updatedWin.windowId ? updatedWin : w));
    setSelectedWindow(updatedWin);
  };

  return (
    <div className="min-h-screen bg-[#F8FAFC] text-slate-900 flex flex-col font-sans">
      {/* Header */}
      <header className="border-b border-slate-200 bg-white px-6 py-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 sticky top-0 z-50 shadow-sm">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-blue-50 border border-blue-200 rounded-xl text-blue-600 shadow-sm">
            <Shield className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-black tracking-wider text-slate-900 font-sans uppercase">
                NetLog <span className="text-blue-600">Sentinel</span>
              </h1>
              <span className="bg-blue-50 text-blue-700 text-[9px] px-1.5 py-0.5 rounded font-mono font-bold uppercase tracking-wider border border-blue-100">
                v2.4 ML-Platform
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Unsupervised anomaly detection & AI threat hunter for enterprise router syslogs.
            </p>
          </div>
        </div>

        {/* Server & API Status */}
        <div className="flex items-center space-x-3 self-start sm:self-center">
          {serverStatus && (
            <div className="flex items-center space-x-2 bg-slate-50 border border-slate-200 px-3 py-1.5 rounded-lg text-xs font-mono">
              <div className="flex items-center space-x-1.5">
                <span className={`w-2 h-2 rounded-full ${serverStatus.hasGeminiKey ? 'bg-emerald-500' : 'bg-amber-500'}`} />
                <span className="text-slate-500">Gemini API:</span>
                <span className={serverStatus.hasGeminiKey ? 'text-emerald-700 font-bold' : 'text-amber-600 font-bold'}>
                  {serverStatus.hasGeminiKey ? 'CONNECTED' : 'OFFLINE (FALLBACK)'}
                </span>
              </div>
            </div>
          )}
          <div className="flex items-center space-x-1 bg-blue-50 border border-blue-100 px-2 py-1 rounded text-[10px] text-blue-700 font-mono">
            <Activity className="w-3.5 h-3.5 animate-pulse" />
            <span>3000 // LIVE</span>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-grow p-4 md:p-6 max-w-7xl mx-auto w-full space-y-6">
        
        {/* Intro banner */}
        <div className="bg-[#F1F5F9] border border-slate-200 rounded-xl p-5 relative overflow-hidden flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="absolute top-0 right-0 w-80 h-80 bg-blue-500/5 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute bottom-0 left-1/3 w-80 h-80 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none" />
          <div className="space-y-1 relative z-10">
            <h2 className="text-sm font-semibold text-slate-900">Autonomous Security Operations Control Deck</h2>
            <p className="text-xs text-slate-600 max-w-2xl leading-relaxed">
              Designed for R&D divisions of Mercedes-Benz and BMW. Sentinel analyzes incoming syslog lines, automatically clusters raw traffic into contiguous window frames, performs high-performance density and partitioning anomaly detection, and engages a server-side Gemini intelligence analyst to write localized threat defense manuals.
            </p>
          </div>
          <div className="flex items-center space-x-2 font-mono text-[10px] text-slate-500 relative z-10">
            <Server className="w-3.5 h-3.5 text-blue-600" />
            <span>Target Platform: Cisco IOS Syslog</span>
          </div>
        </div>

        {/* Dashboard Cards & Control Panel Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <PipelineController
              onRunPipeline={handleRunPipeline}
              onUploadLogs={handleUploadLogs}
              loading={loading}
            />
          </div>
          <div>
            <div className="bg-white border border-slate-200 rounded-xl p-5 h-full flex flex-col justify-between shadow-sm">
              <div>
                <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Engine Architecture</h3>
                <p className="text-xs text-slate-600 leading-relaxed">
                  NetLog Sentinel uses an ensemble of <strong className="text-slate-900 font-bold">Isolation Forest</strong> (for partitioning distance anomaly detection) and <strong className="text-slate-900 font-bold">Local Outlier Factor (LOF)</strong> (for density checking).
                </p>
                <div className="mt-4 space-y-2 text-xs font-mono">
                  <div className="flex justify-between border-b border-slate-100 pb-1">
                    <span className="text-slate-500">Unsupervised Forest Trees:</span>
                    <span className="text-blue-600 font-semibold">100 Trees</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-100 pb-1">
                    <span className="text-slate-500">Subsample Leaf Depth:</span>
                    <span className="text-blue-600 font-semibold">8 Nodes max</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-100 pb-1">
                    <span className="text-slate-500">Feature Dimensions Analyzed:</span>
                    <span className="text-blue-600 font-semibold">12 Dimensions</span>
                  </div>
                </div>
              </div>
              <div className="mt-4 p-2.5 bg-slate-50 rounded border border-slate-200 text-[10px] text-slate-500 font-mono">
                💡 Tip: Click on any outlier on the chart below to inspect how the ML scores are generated and explain them.
              </div>
            </div>
          </div>
        </div>

        {/* Dynamic Telemetry Metrics Overview */}
        <DashboardOverview
          windows={windows}
          summary={summary}
          selectedWindow={selectedWindow}
        />

        {/* Telemetry Timeline Area Chart */}
        <AnomalyTimeline
          windows={windows}
          selectedWindow={selectedWindow}
          onSelectWindow={setSelectedWindow}
        />

        {/* Workspace: Columns for Window Detail & Raw Scrolling Logs */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-[500px]">
          {/* Detail Metric Attribution Panel */}
          <div>
            <WindowDetailsPanel
              window={selectedWindow}
              onUpdateWindow={handleUpdateWindow}
            />
          </div>

          {/* Interactive Logs Console */}
          <div>
            <LogsConsole
              logs={selectedWindowLogs}
              timestamp={selectedWindow ? selectedWindow.timestamp : 'None Selected'}
            />
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white py-6 px-6 mt-12 text-center text-xs text-slate-500 font-mono space-y-2 shadow-sm">
        <p>
          🛰️ NETLOG SENTINEL — UNSUPERVISED NETWORK DEVIATION TELEMETRY AUDITOR
        </p>
        <p className="text-[10px] text-slate-400">
          Built with React 19 · Vite 6 · Tailwind CSS · Node Express · Google Gemini AI Platform. Fully GDPR safe.
        </p>
      </footer>
    </div>
  );
}
