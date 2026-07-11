export interface RawLogLine {
  id: string;
  timestamp: string; // ISO format or parsed date
  host: string;
  facility: string;
  severity: number; // 0-7 (Cisco standard: Emergency=0, Debug=7)
  mnemonic: string; // e.g. UPDOWN, CONFIG_I, IPACCESSLOGP
  message: string;
  rawLine: string;
  maskedLine: string;
  metadata: {
    srcIp?: string;
    maskedIp?: string;
    username?: string;
    maskedUsername?: string;
    interface?: string;
    port?: number;
  };
}

export interface WindowFeatures {
  windowId: string; // e.g., '2026-07-11T11:00:00'
  timestamp: string; // display string
  features: {
    total_events: number;
    unique_ips: number;
    severity_entropy: number;
    failed_logins: number;
    failed_login_ratio: number;
    denied_acls: number;
    link_flaps: number;
    config_changes: number;
    critical_severity_count: number;
    auth_attempts: number;
    system_restarts: number;
    unusual_port_traffic: number;
  };
  rawLogs: RawLogLine[]; // logs falling into this window
}

export interface ScoredWindow extends WindowFeatures {
  anomalyScore: number; // 0 to 1, higher is more anomalous
  isAnomaly: boolean;
  isLofAnomaly: boolean;
  attributions: {
    featureName: string;
    zScore: number;
    value: number;
    mean: number;
    importance: number; // contribution weight
  }[];
  explanation: string;
  aiExplanation?: string;
}

export type AnomalyPreset = 'clean' | 'brute_force' | 'port_scan' | 'interface_flap' | 'config_tamper' | 'all_mixed';
