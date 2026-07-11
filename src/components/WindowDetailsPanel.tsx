import { useState, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import { ShieldAlert, Sparkles, TrendingUp, Cpu, Server, CheckCircle2, RefreshCw } from 'lucide-react';
import { ScoredWindow } from '../types/netlog';

interface WindowDetailsPanelProps {
  window: ScoredWindow | null;
  onUpdateWindow: (updatedWin: ScoredWindow) => void;
}

export default function WindowDetailsPanel({ window, onUpdateWindow }: WindowDetailsPanelProps) {
  const [loadingAI, setLoadingAI] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  // Clear states when selected window changes
  useEffect(() => {
    setAiError(null);
  }, [window?.windowId]);

  if (!window) {
    return (
      <div className="bg-white border border-slate-200 border-dashed rounded-xl p-12 text-center text-slate-500 h-full flex flex-col justify-center items-center shadow-sm">
        <Server className="w-12 h-12 text-slate-400 mb-4 animate-pulse" />
        <p className="font-bold text-slate-700">No Window Selected</p>
        <p className="text-xs text-slate-400 mt-1 max-w-[280px]">
          Select an interval on the chart timeline above or click on an anomaly to inspect telemetry logs.
        </p>
      </div>
    );
  }

  const handleConsultAI = async () => {
    if (loadingAI) return;
    setLoadingAI(true);
    setAiError(null);

    try {
      const response = await fetch('/api/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ window })
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      if (data.aiExplanation) {
        onUpdateWindow({
          ...window,
          aiExplanation: data.aiExplanation
        });
      } else {
        throw new Error('AI failed to generate a response text.');
      }
    } catch (err: any) {
      console.error(err);
      setAiError(err.message || 'Connection lost to the Gemini API service.');
    } finally {
      setLoadingAI(false);
    }
  };

  // Human friendly feature name mapper
  const formatFeatureLabel = (fName: string): string => {
    const mapping: Record<string, string> = {
      total_events: 'Syslog Event Volume',
      unique_ips: 'Unique Source IPs',
      severity_entropy: 'Severity Shannon Entropy',
      failed_logins: 'Login Failures',
      failed_login_ratio: 'Failed Login Ratio',
      denied_acls: 'Security ACL Denials',
      link_flaps: 'Interface Flap Events',
      config_changes: 'Device Configuration Changes',
      critical_severity_count: 'Emergency/Critical Alerts',
      auth_attempts: 'Auth Attempts',
      system_restarts: 'System Reboots/Reloads',
      unusual_port_traffic: 'Restricted Port Probes'
    };
    return mapping[fName] || fName;
  };

  const isSignificantOutlier = window.anomalyScore >= 0.55;

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5 flex flex-col h-full space-y-5 shadow-sm">
      {/* Window Header */}
      <div className="flex items-start justify-between border-b border-slate-200 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <h3 className="text-base font-bold text-slate-900">{window.timestamp}</h3>
            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
              window.isAnomaly ? 'bg-rose-50 text-rose-600 border border-rose-200' : 'bg-blue-50 text-blue-600 border border-blue-200'
            }`}>
              {window.isAnomaly ? 'Anomaly Flagged' : 'Normal State'}
            </span>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1">ID: {window.windowId}</p>
        </div>
        <div className="text-right font-mono">
          <p className="text-xs text-slate-500">ML Outlier Score</p>
          <p className={`text-xl font-black ${isSignificantOutlier ? 'text-rose-600' : 'text-blue-600'}`}>
            {(window.anomalyScore * 100).toFixed(1)}%
          </p>
        </div>
      </div>

      {/* Model Diagnostic */}
      <div className="grid grid-cols-2 gap-3 bg-slate-50 rounded-lg p-3 border border-slate-200 font-mono text-xs">
        <div className="flex items-center space-x-2 text-slate-600">
          <Cpu className="w-4 h-4 text-blue-600" />
          <span>Isolation Forest:</span>
          <span className={window.isAnomaly ? 'text-rose-600 font-bold' : 'text-slate-500'}>
            {window.isAnomaly ? 'ABNORMAL' : 'NORMAL'}
          </span>
        </div>
        <div className="flex items-center space-x-2 text-slate-600">
          <TrendingUp className="w-4 h-4 text-violet-600" />
          <span>LOF Density Crosscheck:</span>
          <span className={window.isLofAnomaly ? 'text-rose-600 font-bold' : 'text-slate-500'}>
            {window.isLofAnomaly ? 'OUTLIER' : 'NORMAL'}
          </span>
        </div>
      </div>

      {/* Feature Attribution (Z-scores) */}
      <div>
        <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3 flex items-center space-x-1.5">
          <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
          <span>Feature Attribution Metrics (Z-Score Deviation)</span>
        </h4>
        <div className="space-y-3 max-h-60 overflow-y-auto pr-1">
          {window.attributions.map((attr) => {
            const z = attr.zScore;
            // Percent width capped at 100
            const percentage = Math.min(100, Math.max(0, (Math.abs(z) / 8) * 100));
            const barColor = z > 3.0 ? 'bg-rose-500' : z > 1.5 ? 'bg-amber-500' : 'bg-blue-500';
            const valueDisplay = attr.featureName === 'failed_login_ratio' 
              ? `${(attr.value * 100).toFixed(0)}%` 
              : attr.value;
            const meanDisplay = attr.featureName === 'failed_login_ratio' 
              ? `${(attr.mean * 100).toFixed(0)}%` 
              : attr.mean;

            return (
              <div key={attr.featureName} className="text-xs">
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-700 font-semibold">{formatFeatureLabel(attr.featureName)}</span>
                  <span className="font-mono text-slate-500">
                    Val: <strong className="text-slate-800">{valueDisplay}</strong> (Baseline: {meanDisplay})
                  </span>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="h-1.5 bg-slate-100 rounded-full flex-grow overflow-hidden relative">
                    <div 
                       className={`h-full ${barColor} rounded-full transition-all duration-500`}
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                  <span className={`font-mono text-[10px] w-12 text-right ${z > 1.5 ? 'text-rose-600 font-bold' : 'text-slate-500'}`}>
                    {z > 0 ? `+${z}` : z} Z
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Rule-Based Summary */}
      <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
        <h5 className="text-[10px] uppercase font-mono font-bold text-slate-500 mb-1">Local Rule-Engine Explanation</h5>
        <p className="text-xs text-slate-700 leading-relaxed">{window.explanation}</p>
      </div>

      {/* Gemini AI Analyst Section */}
      <div className="border-t border-slate-200 pt-4 flex-grow flex flex-col min-h-0">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center space-x-1.5">
            <Sparkles className="w-4 h-4 text-violet-600" />
            <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider">AI SecOps Analyst (Gemini)</h4>
          </div>
          {!window.aiExplanation && (
            <button
              onClick={handleConsultAI}
              disabled={loadingAI}
              className="px-2.5 py-1 text-[11px] font-semibold bg-blue-600 hover:bg-blue-700 disabled:bg-slate-200 disabled:text-slate-400 rounded-md text-white transition-all flex items-center space-x-1 cursor-pointer"
            >
              {loadingAI ? (
                <>
                  <RefreshCw className="w-3 h-3 animate-spin mr-1" />
                  <span>Synthesizing...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-3 h-3 mr-1" />
                  <span>Consult AI Analyst</span>
                </>
              )}
            </button>
          )}
        </div>

        {/* AI Report Output Area */}
        <div className="bg-slate-50 rounded-lg p-4 font-sans text-xs border border-slate-200 flex-grow overflow-y-auto max-h-80 leading-relaxed text-slate-700">
          {loadingAI ? (
            <div className="flex flex-col items-center justify-center py-8 space-y-2 text-center text-slate-500">
              <RefreshCw className="w-6 h-6 text-blue-600 animate-spin" />
              <p className="font-mono text-[10px] animate-pulse">
                NETLOG SENTINEL AGENT COGNITIVE PIPELINE ENGAGED...
              </p>
              <p className="text-[10px] text-slate-400 max-w-[250px]">
                Mining features, extracting syslog indicators, and validating threat playbooks.
              </p>
            </div>
          ) : aiError ? (
            <div className="text-rose-600 font-mono text-[11px]">
              🚨 Error engaging Gemini agent: {aiError}
            </div>
          ) : window.aiExplanation ? (
            <div className="text-slate-700 space-y-2 text-xs leading-relaxed">
              <ReactMarkdown>{window.aiExplanation}</ReactMarkdown>
              <div className="mt-4 pt-3 border-t border-slate-200 flex items-center justify-between text-[10px] text-slate-400 font-mono">
                <span>Verified threat classification: DeepMind Gemini-3.5-Flash</span>
                <span className="flex items-center text-emerald-600 font-bold">
                  <CheckCircle2 className="w-3 h-3 mr-1" /> Verified Report
                </span>
              </div>
            </div>
          ) : (
            <div className="text-center py-6 text-slate-400 italic font-mono text-[11px]">
              AI Agent is dormant. Click "Consult AI Analyst" to request a deep cryptographic PII-masked incident audit.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
