import crypto from 'crypto';
import { RawLogLine, WindowFeatures, AnomalyPreset } from '../types/netlog';

// Helper to hash PII (IPs and usernames) securely with SHA-256 (first 16 characters for readability)
export function hashPII(value: string, salt: string = 'sentinel-salt-99'): string {
  if (!value) return '';
  return crypto.createHash('sha256').update(value + salt).digest('hex').substring(0, 16);
}

// Regex list for log parsing
const CISCO_SYSLOG_REGEX = /^(?:(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z|\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?))?\s*([a-zA-Z0-9_\-\.]+)?\s*:\s*%([A-Z0-9_\-\.]+)-(\d)-([A-Z0-9_\-\.]+)\s*:\s*(.*)$/;

export function parseLogLine(rawLine: string, lineId: string): RawLogLine {
  const match = rawLine.match(CISCO_SYSLOG_REGEX);
  let timestamp = new Date().toISOString();
  let host = 'CORE-RTR-01';
  let facility = 'SYS';
  let severity = 5;
  let mnemonic = 'INFO';
  let message = rawLine;

  if (match) {
    const rawTime = match[1];
    host = match[2] || 'CORE-RTR-01';
    facility = match[3];
    severity = parseInt(match[4], 10);
    mnemonic = match[5];
    message = match[6];

    if (rawTime) {
      try {
        timestamp = new Date(rawTime).toISOString();
      } catch (e) {
        timestamp = new Date().toISOString(); // fallback
      }
    }
  }

  // Extract IPs and Usernames for PII masking
  const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
  const usernameRegex = /for\s+user\s+([a-zA-Z0-9_\-\.]+)|by\s+user\s+([a-zA-Z0-9_\-\.]+)|user\s+([a-zA-Z0-9_\-\.]+)\s+failed/i;

  const ipsFound = message.match(ipRegex) || [];
  let maskedMessage = message;

  let srcIp: string | undefined = undefined;
  let maskedIp: string | undefined = undefined;
  let username: string | undefined = undefined;
  let maskedUsername: string | undefined = undefined;
  let port: number | undefined = undefined;
  let ethInterface: string | undefined = undefined;

  if (ipsFound.length > 0) {
    srcIp = ipsFound[0];
    maskedIp = `${hashPII(srcIp)}.ip`;
    // Replace all instances of the IP with hashed IP
    ipsFound.forEach(ip => {
      maskedMessage = maskedMessage.replace(ip, `${hashPII(ip).substring(0, 8)}.ip`);
    });
  }

  const userMatch = message.match(usernameRegex);
  if (userMatch) {
    username = userMatch[1] || userMatch[2] || userMatch[3];
    if (username) {
      maskedUsername = `${hashPII(username).substring(0, 8)}.usr`;
      maskedMessage = maskedMessage.replace(username, maskedUsername);
    }
  }

  // Extract interface names e.g. GigabitEthernet0/1 or FastEthernet1/2
  const interfaceRegex = /(GigabitEthernet|FastEthernet|Vlan|Loopback|Serial)[0-9\/]+/i;
  const intMatch = message.match(interfaceRegex);
  if (intMatch) {
    ethInterface = intMatch[0];
  }

  // Extract ports if standard like (53), (22), etc
  const portRegex = /(?:\(|port\s+)([0-9]{2,5})\)?/i;
  const portMatch = message.match(portRegex);
  if (portMatch) {
    port = parseInt(portMatch[1], 10);
  }

  const maskedLine = match
    ? `${match[1] || ''} ${host} : %${facility}-${severity}-${mnemonic} : ${maskedMessage}`
    : maskedMessage;

  return {
    id: lineId,
    timestamp,
    host,
    facility,
    severity,
    mnemonic,
    message,
    rawLine,
    maskedLine,
    metadata: {
      srcIp,
      maskedIp,
      username,
      maskedUsername,
      interface: ethInterface,
      port
    }
  };
}

// Generate full set of logs spanning e.g. 24 hours with custom anomaly injection
export function generateSyntheticLogs(preset: AnomalyPreset, durationHours: number = 12): string[] {
  const logs: string[] = [];
  const startTime = Date.now() - durationHours * 60 * 60 * 1000;
  const hosts = ['RTR-EDGE-01', 'SW-CORE-02', 'FW-DMZ-01', 'RTR-WAN-01'];

  // Base log frequencies (events per minute under normal load)
  // We write logs every few seconds
  let currentTimer = startTime;
  const endTime = Date.now();

  // Helper to make Cisco timestamp format: "2026-07-11T11:00:00.123Z"
  const getCiscoTimestamp = (ms: number) => new Date(ms).toISOString();

  // Generate normal traffic background logs
  while (currentTimer < endTime) {
    const elapsedMinutes = (currentTimer - startTime) / (60 * 1000);
    const windowIndex = Math.floor(elapsedMinutes / 5); // 5-min intervals

    // Standard background normal events
    // 1. ACL Permit logs (common traffic)
    if (Math.random() < 0.3) {
      const src = `10.0.10.${Math.floor(Math.random() * 200 + 10)}`;
      const dest = `192.168.100.${Math.floor(Math.random() * 50 + 10)}`;
      const portVal = [80, 443, 8080, 53, 123][Math.floor(Math.random() * 5)];
      logs.push(`${getCiscoTimestamp(currentTimer)} ${hosts[0]}: %SEC-6-IPACCESSLOGRP: list trust permit tcp ${src}(${Math.floor(Math.random() * 50000 + 1024)}) -> ${dest}(${portVal}), 1 packet`);
    }

    // 2. Normal login checks
    if (Math.random() < 0.05) {
      const user = ['admin', 'operator', 'puneeth', 'network_ops'][Math.floor(Math.random() * 4)];
      const src = `10.0.10.${Math.floor(Math.random() * 10 + 5)}`;
      logs.push(`${getCiscoTimestamp(currentTimer)} ${hosts[1]}: %SEC-6-LOGIN_SUCCESS: Login success on vty0 for user ${user} from ${src}`);
    }

    // 3. NTP updates or OSPF keepalives
    if (Math.random() < 0.08) {
      logs.push(`${getCiscoTimestamp(currentTimer)} ${hosts[3]}: %OSPF-5-ADJCHG: Process 1, Nbr 10.0.1.2 on GigabitEthernet0/2 from FULL to FULL, Neighbor Signalled Restart`);
    }

    // 4. Minor errors or warnings
    if (Math.random() < 0.02) {
      logs.push(`${getCiscoTimestamp(currentTimer)} ${hosts[2]}: %SYS-5-CONFIG_I: Configured from console by console admin on vty0 (10.0.5.2)`);
    }

    // Now inject specific anomalies based on elapsed minutes (e.g. at 25%, 50%, 75% of duration)
    const quarter1 = Math.floor(durationHours * 60 * 0.25);
    const quarter2 = Math.floor(durationHours * 60 * 0.50);
    const quarter3 = Math.floor(durationHours * 60 * 0.75);

    // ----------------------------------------------------
    // Scenario 1: SSH Brute Force (Vulnerability)
    // ----------------------------------------------------
    if ((preset === 'brute_force' || preset === 'all_mixed') &&
        Math.floor(elapsedMinutes) >= quarter1 && Math.floor(elapsedMinutes) <= quarter1 + 3) {
      // 40 login failures in 3 minutes from an external IP
      const hackerIp = '198.51.100.222';
      const fakeUsers = ['root', 'admin', 'cisco', 'guest', 'user', 'test', 'support', 'oracle', 'ubnt', 'agent'];
      for (let j = 0; j < 15; j++) {
        const timestampOffset = currentTimer + Math.random() * 60000;
        const fakeUser = fakeUsers[Math.floor(Math.random() * fakeUsers.length)];
        logs.push(`${getCiscoTimestamp(timestampOffset)} ${hosts[0]}: %SEC-6-LOGIN_FAILED: Login failed on vty0 for user ${fakeUser} from ${hackerIp}`);
      }
    }

    // ----------------------------------------------------
    // Scenario 2: Network Port Scan (Reconnaissance)
    // ----------------------------------------------------
    if ((preset === 'port_scan' || preset === 'all_mixed') &&
        Math.floor(elapsedMinutes) >= quarter2 && Math.floor(elapsedMinutes) <= quarter2 + 4) {
      // High volume of ACL Denied logs across 20+ distinct ports
      const scannerIp = '203.0.113.88';
      const targetIps = ['10.0.10.5', '10.0.10.12', '10.0.10.33'];
      const scanPorts = [21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080];
      for (let j = 0; j < 25; j++) {
        const timestampOffset = currentTimer + Math.random() * 60000;
        const target = targetIps[Math.floor(Math.random() * targetIps.length)];
        const targetPort = scanPorts[Math.floor(Math.random() * scanPorts.length)];
        logs.push(`${getCiscoTimestamp(timestampOffset)} ${hosts[2]}: %SEC-6-IPACCESSLOGDP: list border-acl denied tcp ${scannerIp}(${Math.floor(Math.random() * 60000 + 1024)}) -> ${target}(${targetPort}), 1 packet`);
      }
    }

    // ----------------------------------------------------
    // Scenario 3: Interface Flapping (Hardware failure)
    // ----------------------------------------------------
    if ((preset === 'interface_flap' || preset === 'all_mixed') &&
        Math.floor(elapsedMinutes) >= quarter3 && Math.floor(elapsedMinutes) <= quarter3 + 3) {
      // GigabitEthernet0/1 flaps continuously (Up/Down logs)
      const targetInt = 'GigabitEthernet0/1';
      for (let j = 0; j < 8; j++) {
        const timestampOffset = currentTimer + Math.random() * 60000;
        logs.push(`${getCiscoTimestamp(timestampOffset)} ${hosts[1]}: %LINK-3-UPDOWN: Interface ${targetInt}, changed state to down`);
        logs.push(`${getCiscoTimestamp(timestampOffset + 2000)} ${hosts[1]}: %LINEPROTO-5-UPDOWN: Line protocol on Interface ${targetInt}, changed state to down`);
        logs.push(`${getCiscoTimestamp(timestampOffset + 15000)} ${hosts[1]}: %LINK-3-UPDOWN: Interface ${targetInt}, changed state to up`);
        logs.push(`${getCiscoTimestamp(timestampOffset + 17000)} ${hosts[1]}: %LINEPROTO-5-UPDOWN: Line protocol on Interface ${targetInt}, changed state to up`);
      }
    }

    // ----------------------------------------------------
    // Scenario 4: Configuration Tampering / Unauthorized Admin Access
    // ----------------------------------------------------
    if ((preset === 'config_tamper' || preset === 'all_mixed') &&
        Math.floor(elapsedMinutes) >= Math.floor(durationHours * 60 * 0.90) &&
        Math.floor(elapsedMinutes) <= Math.floor(durationHours * 60 * 0.90) + 2) {
      // Configuration commands executed from a highly unusual IP, with multiple system warning states
      const shadyIp = '198.51.100.99';
      logs.push(`${getCiscoTimestamp(currentTimer)} ${hosts[0]}: %SYS-5-CONFIG_I: Configured from console by mal_operator on vty1 (${shadyIp})`);
      logs.push(`${getCiscoTimestamp(currentTimer + 2000)} ${hosts[0]}: %SEC-6-IPACCESSLOGP: list trust denied tcp 10.0.10.99(80) -> ${shadyIp}(1234), 1 packet`);
      logs.push(`${getCiscoTimestamp(currentTimer + 4000)} ${hosts[0]}: %SYS-5-CONFIG_I: Configured from console by mal_operator on vty1 (${shadyIp})`);
      logs.push(`${getCiscoTimestamp(currentTimer + 10000)} ${hosts[0]}: %SYS-3-IPACCESSLOG_LIMIT: Access list log buffer limits exceeded (3500 pkts/sec)`);
    }

    // Increment time by an average of 45 seconds (some randomness)
    currentTimer += (10000 + Math.random() * 70000);
  }

  // Sort logs by chronological order
  return logs.sort((a, b) => {
    const timeA = a.substring(0, 24);
    const timeB = b.substring(0, 24);
    return timeA.localeCompare(timeB);
  });
}

// Roll up raw log lines into discrete aggregated time windows
export function aggregateLogsToWindows(parsedLogs: RawLogLine[], windowMinutes: number = 5): WindowFeatures[] {
  if (parsedLogs.length === 0) return [];

  // Group by window
  const windowsMap = new Map<string, RawLogLine[]>();
  const windowMs = windowMinutes * 60 * 1000;

  // Find min/max boundaries
  let minTime = Infinity;
  let maxTime = -Infinity;

  parsedLogs.forEach(log => {
    const t = new Date(log.timestamp).getTime();
    if (t < minTime) minTime = t;
    if (t > maxTime) maxTime = t;
  });

  // Create empty buckets for all intervals between min and max to prevent gaps
  const startBucket = Math.floor(minTime / windowMs) * windowMs;
  const endBucket = Math.floor(maxTime / windowMs) * windowMs;

  for (let t = startBucket; t <= endBucket; t += windowMs) {
    const winKey = new Date(t).toISOString();
    windowsMap.set(winKey, []);
  }

  // Populate buckets
  parsedLogs.forEach(log => {
    const t = new Date(log.timestamp).getTime();
    const bucketTime = Math.floor(t / windowMs) * windowMs;
    const winKey = new Date(bucketTime).toISOString();
    if (windowsMap.has(winKey)) {
      windowsMap.get(winKey)!.push(log);
    } else {
      windowsMap.set(winKey, [log]);
    }
  });

  const windowFeaturesList: WindowFeatures[] = [];

  windowsMap.forEach((logsInWindow, winKey) => {
    // 1. total events
    const total_events = logsInWindow.length;

    // 2. unique ips
    const ips = new Set<string>();
    logsInWindow.forEach(l => {
      if (l.metadata.srcIp) ips.add(l.metadata.srcIp);
    });
    const unique_ips = ips.size;

    // 3. severity entropy
    const severityCounts = [0, 0, 0, 0, 0, 0, 0, 0]; // 0-7
    logsInWindow.forEach(l => {
      if (l.severity >= 0 && l.severity <= 7) {
        severityCounts[l.severity]++;
      }
    });
    let severity_entropy = 0;
    if (total_events > 0) {
      severityCounts.forEach(count => {
        if (count > 0) {
          const p = count / total_events;
          severity_entropy -= p * Math.log2(p);
        }
      });
    }

    // 4. failed logining
    let failed_logins = 0;
    let auth_attempts = 0;
    logsInWindow.forEach(l => {
      if (l.mnemonic.includes('LOGIN_FAILED')) failed_logins++;
      if (l.mnemonic.includes('LOGIN_SUCCESS') || l.mnemonic.includes('LOGIN_FAILED')) auth_attempts++;
    });

    // 5. failed login ratio
    const failed_login_ratio = auth_attempts > 0 ? failed_logins / auth_attempts : 0;

    // 6. denied ACLs
    let denied_acls = 0;
    logsInWindow.forEach(l => {
      if (l.mnemonic.includes('IPACCESSLOGDP') || l.mnemonic.includes('IPACCESSLOGP') && l.message.toLowerCase().includes('denied')) {
        denied_acls++;
      }
    });

    // 7. link flaps
    let link_flaps = 0;
    logsInWindow.forEach(l => {
      if (l.mnemonic === 'UPDOWN' || l.mnemonic === 'LINK' || l.mnemonic.includes('PORT-') || l.mnemonic.includes('UPDOWN')) {
        link_flaps++;
      }
    });

    // 8. config changes
    let config_changes = 0;
    logsInWindow.forEach(l => {
      if (l.mnemonic === 'CONFIG_I' || l.mnemonic.includes('SYS-5-CONFIG')) {
        config_changes++;
      }
    });

    // 9. critical severity count (severity <= 3)
    let critical_severity_count = 0;
    logsInWindow.forEach(l => {
      if (l.severity <= 3) critical_severity_count++;
    });

    // 10. system restarts
    let system_restarts = 0;
    logsInWindow.forEach(l => {
      if (l.mnemonic === 'RESTART' || l.mnemonic === 'REBOOT' || l.message.toLowerCase().includes('restarted') || l.message.toLowerCase().includes('reboot')) {
        system_restarts++;
      }
    });

    // 11. unusual port traffic (e.g. port scan indications)
    let unusual_port_traffic = 0;
    logsInWindow.forEach(l => {
      if (l.metadata.port) {
        const suspiciousPorts = [21, 23, 22, 135, 139, 445, 3389, 2323];
        if (suspiciousPorts.includes(l.metadata.port)) {
          unusual_port_traffic++;
        }
      }
    });

    const displayTime = new Date(winKey).toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true
    }) + ' ' + new Date(winKey).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

    windowFeaturesList.push({
      windowId: winKey,
      timestamp: displayTime,
      features: {
        total_events,
        unique_ips,
        severity_entropy: parseFloat(severity_entropy.toFixed(4)),
        failed_logins,
        failed_login_ratio: parseFloat(failed_login_ratio.toFixed(4)),
        denied_acls,
        link_flaps,
        config_changes,
        critical_severity_count,
        auth_attempts,
        system_restarts,
        unusual_port_traffic
      },
      rawLogs: logsInWindow
    });
  });

  // Sort windows chronologically
  return windowFeaturesList.sort((a, b) => a.windowId.localeCompare(b.windowId));
}
