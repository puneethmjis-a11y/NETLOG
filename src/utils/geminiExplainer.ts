import { GoogleGenAI } from '@google/genai';
import { ScoredWindow } from '../types/netlog';

let aiClient: GoogleGenAI | null = null;

function getGeminiClient(): GoogleGenAI {
  if (!aiClient) {
    const key = process.env.GEMINI_API_KEY;
    if (!key) {
      throw new Error('GEMINI_API_KEY environment variable is not defined.');
    }
    aiClient = new GoogleGenAI({
      apiKey: key,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return aiClient;
}

export async function explainAnomalyWithAI(window: ScoredWindow): Promise<string> {
  const key = process.env.GEMINI_API_KEY;
  if (!key) {
    return window.explanation + ' (AI explanation is offline because GEMINI_API_KEY is not set)';
  }

  try {
    const client = getGeminiClient();

    // Prepare a concise summary of the window's anomalous features
    const topDrivers = window.attributions.slice(0, 3).map(a => 
      `- **${a.featureName}**: value=${a.value} (Normal mean=${a.mean}, Z-Score=${a.zScore})`
    ).join('\n');

    // Get a few sample raw logs to help the LLM contextualize
    const sampleLogs = window.rawLogs.slice(0, 10).map(l => 
      `[${l.timestamp}] %${l.facility}-${l.severity}-${l.mnemonic}: ${l.message}`
    ).join('\n');

    const prompt = `
You are a senior enterprise Network Security Engineer and threat hunter at NetLog Sentinel.
An unsupervised Machine Learning algorithm (Isolation Forest + LOF) has flagged a 5-minute log window as anomalous.
Analyze the following features, metrics, and raw logs to explain exactly WHAT happened, why it is dangerous, and WHAT immediate remediation steps the operator should take.

WINDOW TIMESTAMP: ${window.timestamp}
ANOMALY SCORE: ${(window.anomalyScore * 100).toFixed(1)}% (Threshold exceeded)

TOP ABNORMAL FEATURES (Z-SCORE ACCORDING TO NORMAL BASELINE):
${topDrivers}

ALL FEATURES IN THIS WINDOW:
${JSON.stringify(winFeaturesToMap(window.features), null, 2)}

REPRESENTATIVE SYSLOG SAMPLES (FIRST 10 LINES):
${sampleLogs || 'No syslog samples are available in this window.'}

INSTRUCTIONS:
1. Write a professional, concise, and highly realistic summary of the event (e.g. "SSH Brute-Force Attempt", "Network Reconnaissance/Scan", "Interface Hardware Flapping").
2. Explain how the abnormal metrics relate directly to the raw logs.
3. Keep the tone calm, expert, and actionable. Do not use generic explanations. Maximize specificity based on the actual Cisco syslog lines provided.
4. Output your analysis in Markdown, with the following sections:
   - **Incident Severity & Vector**
   - **Technical Breakdown**
   - **Risk Assessment**
   - **Recommended Playbook Actions**
`;

    const response = await client.models.generateContent({
      model: 'gemini-3.5-flash',
      contents: prompt,
      config: {
        temperature: 0.2,
      },
    });

    if (response.text) {
      return response.text.trim();
    }
    return 'Failed to generate explanation. No content returned.';
  } catch (error: any) {
    console.error('Gemini explanation failed:', error);
    return `AI analyst is temporarily offline. Error: ${error?.message || error}. Falling back to rule engine description: \n\n${window.explanation}`;
  }
}

function winFeaturesToMap(f: ScoredWindow['features']) {
  return {
    'Total Syslog Volume': f.total_events,
    'Unique Connecting Hosts': f.unique_ips,
    'Severity Entropy': f.severity_entropy,
    'Failed Auth Count': f.failed_logins,
    'Failed Auth Ratio': `${(f.failed_login_ratio * 100).toFixed(1)}%`,
    'Blocked Firewall ACLs': f.denied_acls,
    'Physical Interface Flaps': f.link_flaps,
    'Config Changes Detected': f.config_changes,
    'Emergency & Critical Logs': f.critical_severity_count,
    'Total Auth Attempts': f.auth_attempts,
    'System Reloads': f.system_restarts,
    'Unusual Restricted Ports Scanned': f.unusual_port_traffic
  };
}
