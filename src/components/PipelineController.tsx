import { useState } from 'react';
import { Play, Upload, Settings, RefreshCw, AlertTriangle, ShieldCheck, HelpCircle } from 'lucide-react';
import { AnomalyPreset } from '../types/netlog';

interface PipelineControllerProps {
  onRunPipeline: (params: { preset: AnomalyPreset; windowMinutes: number; contamination: number }) => Promise<void>;
  onUploadLogs: (params: { rawLogsText: string; windowMinutes: number; contamination: number }) => Promise<void>;
  loading: boolean;
}

export default function PipelineController({ onRunPipeline, onUploadLogs, loading }: PipelineControllerProps) {
  const [activeTab, setActiveTab] = useState<'generate' | 'upload'>('generate');
  const [selectedPreset, setSelectedPreset] = useState<AnomalyPreset>('all_mixed');
  const [windowMinutes, setWindowMinutes] = useState<number>(5);
  const [contamination, setContamination] = useState<number>(0.05);

  // Custom log text state with realistic pre-populated samples
  const [customLogsText, setCustomLogsText] = useState<string>(
`2026-07-11T12:01:00Z RTR-EDGE-01 : %SEC-6-LOGIN_SUCCESS : Login success on vty0 for user admin from 10.0.10.15
2026-07-11T12:01:45Z RTR-EDGE-01 : %OSPF-5-ADJCHG : Process 1, Nbr 10.0.1.2 on GigabitEthernet0/2 from FULL to FULL
2026-07-11T12:02:10Z RTR-EDGE-01 : %SYS-5-CONFIG_I : Configured from console by console admin on vty0 (10.0.10.15)
2026-07-11T12:03:00Z RTR-EDGE-01 : %SEC-6-LOGIN_FAILED : Login failed on vty0 for user support from 198.51.100.5
2026-07-11T12:03:05Z RTR-EDGE-01 : %SEC-6-LOGIN_FAILED : Login failed on vty0 for user support from 198.51.100.5
2026-07-11T12:03:10Z RTR-EDGE-01 : %SEC-6-LOGIN_FAILED : Login failed on vty0 for user admin from 198.51.100.5
2026-07-11T12:03:15Z RTR-EDGE-01 : %SEC-6-LOGIN_FAILED : Login failed on vty0 for user root from 198.51.100.5
2026-07-11T12:03:20Z RTR-EDGE-01 : %SEC-6-LOGIN_FAILED : Login failed on vty0 for user support from 198.51.100.5
2026-07-11T12:03:25Z RTR-EDGE-01 : %SEC-6-LOGIN_FAILED : Login failed on vty0 for user network_ops from 198.51.100.5
2026-07-11T12:03:30Z RTR-EDGE-01 : %SEC-6-LOGIN_FAILED : Login failed on vty0 for user support from 198.51.100.5
2026-07-11T12:04:10Z RTR-EDGE-01 : %LINK-3-UPDOWN : Interface GigabitEthernet0/1, changed state to down
2026-07-11T12:04:12Z RTR-EDGE-01 : %LINEPROTO-5-UPDOWN : Line protocol on Interface GigabitEthernet0/1, changed state to down
2026-07-11T12:04:30Z RTR-EDGE-01 : %LINK-3-UPDOWN : Interface GigabitEthernet0/1, changed state to up
2026-07-11T12:04:32Z RTR-EDGE-01 : %LINEPROTO-5-UPDOWN : Line protocol on Interface GigabitEthernet0/1, changed state to up
2026-07-11T12:05:00Z RTR-EDGE-01 : %SEC-6-IPACCESSLOGDP : list border-acl denied tcp 203.0.113.88(44123) -> 10.0.10.5(22), 1 packet
2026-07-11T12:05:05Z RTR-EDGE-01 : %SEC-6-IPACCESSLOGDP : list border-acl denied tcp 203.0.113.88(44124) -> 10.0.10.5(23), 1 packet
2026-07-11T12:05:10Z RTR-EDGE-01 : %SEC-6-IPACCESSLOGDP : list border-acl denied tcp 203.0.113.88(44125) -> 10.0.10.5(80), 1 packet
2026-07-11T12:05:15Z RTR-EDGE-01 : %SEC-6-IPACCESSLOGDP : list border-acl denied tcp 203.0.113.88(44126) -> 10.0.10.5(443), 1 packet
2026-07-11T12:05:20Z RTR-EDGE-01 : %SEC-6-IPACCESSLOGDP : list border-acl denied tcp 203.0.113.88(44127) -> 10.0.10.5(3389), 1 packet`
  );

  const presets = [
    { id: 'all_mixed', name: 'Multi-Vector Combined Attack', desc: 'Injects brute-force, ACL sweeps, flapping interface, and unauthorized config tampering at staggered intervals.', icon: AlertTriangle, color: 'text-rose-600 border-rose-200 bg-rose-50' },
    { id: 'brute_force', name: 'SSH Brute-Force Attempt', desc: 'Fires high volume of rapid login failures from external threat vector 198.51.100.222.', icon: AlertTriangle, color: 'text-amber-600 border-amber-200 bg-amber-50' },
    { id: 'port_scan', name: 'Reconnaissance Sweep (Port Scan)', desc: 'Generates consecutive security access-list denial logs targeting multiple internal ports.', icon: AlertTriangle, color: 'text-orange-600 border-orange-200 bg-orange-50' },
    { id: 'interface_flap', name: 'Interface Link-Flap Cycle', desc: 'Triggers hardware interface down/up sequences simulating physical port cable failure.', icon: RefreshCw, color: 'text-blue-600 border-blue-200 bg-blue-50' },
    { id: 'config_tamper', name: 'Privileged Configuration Tamper', desc: 'Executes terminal config commands from unverified IP, exceeding limit buffers.', icon: AlertTriangle, color: 'text-violet-600 border-violet-200 bg-violet-50' },
    { id: 'clean', name: 'Nominal Operations Baseline', desc: 'Background normal traffic ONLY. High entropy syslog volume with no active intrusions.', icon: ShieldCheck, color: 'text-emerald-600 border-emerald-200 bg-emerald-50' }
  ];

  const handleGenerateRun = () => {
    onRunPipeline({ preset: selectedPreset, windowMinutes, contamination });
  };

  const handleUploadRun = () => {
    onUploadLogs({ rawLogsText: customLogsText, windowMinutes, contamination });
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
      {/* Tabs */}
      <div className="flex border-b border-slate-200 pb-3 mb-4">
        <button
          onClick={() => setActiveTab('generate')}
          className={`px-4 py-1.5 rounded-lg text-xs font-semibold mr-2 transition-all flex items-center space-x-2 cursor-pointer ${
            activeTab === 'generate'
              ? 'bg-blue-50 text-blue-600 border border-blue-200 shadow-sm'
              : 'text-slate-500 hover:text-slate-800'
          }`}
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>Synthetic Scenario Generator</span>
        </button>
        <button
          onClick={() => setActiveTab('upload')}
          className={`px-4 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center space-x-2 cursor-pointer ${
            activeTab === 'upload'
              ? 'bg-blue-50 text-blue-600 border border-blue-200 shadow-sm'
              : 'text-slate-500 hover:text-slate-800'
          }`}
        >
          <Upload className="w-3.5 h-3.5" />
          <span>Upload Custom Syslogs</span>
        </button>
      </div>

      {activeTab === 'generate' ? (
        <div className="space-y-4">
          {/* Preset Select Grid */}
          <div>
            <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2 block">
              Choose Telemetry Scenario Template
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {presets.map((p) => {
                const Icon = p.icon;
                const isSelected = selectedPreset === p.id;
                return (
                  <button
                    key={p.id}
                    onClick={() => setSelectedPreset(p.id as AnomalyPreset)}
                    className={`p-3 text-left border rounded-xl transition-all flex items-start space-x-3 cursor-pointer ${
                      isSelected
                        ? 'border-blue-500 bg-blue-50/30 shadow-[0_0_12px_rgba(37,99,235,0.06)]'
                        : 'border-slate-200 bg-slate-50 hover:border-slate-300 hover:bg-slate-100/50'
                    }`}
                  >
                    <div className={`p-2 rounded-lg border mt-0.5 ${p.color}`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <div className="flex-grow min-w-0">
                      <p className={`text-xs font-bold ${isSelected ? 'text-blue-600' : 'text-slate-800'}`}>
                        {p.name}
                      </p>
                      <p className="text-[11px] text-slate-500 leading-normal mt-0.5 line-clamp-2">
                        {p.desc}
                      </p>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <div>
            <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1 block">
              Paste Enterprise Syslog Buffer (Cisco IOS Format)
            </label>
            <p className="text-[11px] text-slate-400 mb-2">
              Ensure lines feature timestamp, host/router identifier, facility mnemonic, and payload message.
            </p>
            <textarea
              value={customLogsText}
              onChange={(e) => setCustomLogsText(e.target.value)}
              className="w-full bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs text-slate-800 font-mono h-48 focus:outline-none focus:border-blue-500 placeholder-slate-400 focus:ring-1 focus:ring-blue-500"
              placeholder="Paste raw IOS syslog dump..."
            />
          </div>
        </div>
      )}

      {/* Hyperparameter Settings */}
      <div className="border-t border-slate-200 mt-4 pt-4">
        <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3 flex items-center space-x-1">
          <Settings className="w-3.5 h-3.5 text-blue-600" />
          <span>Sentinel Pipeline Hyperparameters</span>
        </h4>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Time Window Slice */}
          <div className="bg-slate-50 border border-slate-200 p-3 rounded-lg">
            <div className="flex justify-between items-center mb-1.5">
              <span className="text-[11px] font-bold text-slate-600 flex items-center">
                Aggregation Window Duration
                <span title="Time size to group raw logs and compute features." className="cursor-help">
                  <HelpCircle className="w-3 h-3 text-slate-400 ml-1" />
                </span>
              </span>
              <span className="text-xs font-mono font-bold text-blue-600">{windowMinutes} Minutes</span>
            </div>
            <input
              type="range"
              min="1"
              max="30"
              value={windowMinutes}
              onChange={(e) => setWindowMinutes(Number(e.target.value))}
              className="w-full accent-blue-600 h-1.5 bg-slate-200 rounded-full appearance-none cursor-pointer"
            />
            <div className="flex justify-between text-[9px] text-slate-400 font-mono mt-1">
              <span>1m (High resolution)</span>
              <span>15m</span>
              <span>30m (Bulk trend)</span>
            </div>
          </div>

          {/* Isolation Forest Target Contamination */}
          <div className="bg-slate-50 border border-slate-200 p-3 rounded-lg">
            <div className="flex justify-between items-center mb-1.5">
              <span className="text-[11px] font-bold text-slate-600 flex items-center">
                Target Contamination Rate ($\alpha$)
                <span title="Percentage of windows expected to represent anomalous events." className="cursor-help">
                  <HelpCircle className="w-3 h-3 text-slate-400 ml-1" />
                </span>
              </span>
              <span className="text-xs font-mono font-bold text-blue-600">{(contamination * 100).toFixed(0)}%</span>
            </div>
            <input
              type="range"
              min="0.01"
              max="0.20"
              step="0.01"
              value={contamination}
              onChange={(e) => setContamination(Number(e.target.value))}
              className="w-full accent-blue-600 h-1.5 bg-slate-200 rounded-full appearance-none cursor-pointer"
            />
            <div className="flex justify-between text-[9px] text-slate-400 font-mono mt-1">
              <span>1% (Strict outliers)</span>
              <span>10%</span>
              <span>20% (High sensitivity)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Execute Pipeline Button */}
      <div className="mt-5 border-t border-slate-200 pt-4 flex justify-end">
        <button
          onClick={activeTab === 'generate' ? handleGenerateRun : handleUploadRun}
          disabled={loading}
          className={`px-5 py-2 rounded-xl text-xs font-bold transition-all flex items-center space-x-2 shadow-sm cursor-pointer ${
            loading
              ? 'bg-slate-100 text-slate-400 shadow-none'
              : 'bg-blue-600 hover:bg-blue-700 text-white hover:shadow-blue-600/10 hover:shadow-md'
          }`}
        >
          {loading ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin" />
              <span>INGESTING & ENGINE EVALUATION...</span>
            </>
          ) : activeTab === 'generate' ? (
            <>
              <Play className="w-4 h-4 fill-white text-white" />
              <span>SPAWN TELEMETRY & INITIATE SCORING</span>
            </>
          ) : (
            <>
              <Upload className="w-4 h-4" />
              <span>ANALYZE CUSTOM SYSLOG STREAM</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
}
