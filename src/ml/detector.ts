import { WindowFeatures, ScoredWindow } from '../types/netlog';
import { IsolationForest } from './isolationForest';

// Calculate standard deviation of an array
function getStdDev(arr: number[], mean: number): number {
  if (arr.length <= 1) return 0;
  const sumSq = arr.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0);
  return Math.sqrt(sumSq / (arr.length - 1));
}

// Calculate Euclidean distance between two feature vectors
function euclideanDistance(v1: number[], v2: number[]): number {
  let sum = 0;
  for (let i = 0; i < v1.length; i++) {
    sum += Math.pow(v1[i] - v2[i], 2);
  }
  return Math.sqrt(sum);
}

// Simplified Local Outlier Factor (LOF) calculation using k-nearest neighbors distance
function calculateLOFScores(data: number[][], k: number = 3): number[] {
  if (data.length <= k) return data.map(() => 0);

  // 1. Calculate distance matrix
  const distMatrix: number[][] = [];
  for (let i = 0; i < data.length; i++) {
    distMatrix[i] = [];
    for (let j = 0; j < data.length; j++) {
      distMatrix[i][j] = i === j ? Infinity : euclideanDistance(data[i], data[j]);
    }
  }

  // 2. Find k-nearest neighbors and reachability distances
  const kDistances: number[] = [];
  const kNeighborsList: number[][] = [];
  for (let i = 0; i < data.length; i++) {
    const sortedDists = distMatrix[i]
      .map((dist, idx) => ({ dist, idx }))
      .sort((a, b) => a.dist - b.dist);
    
    kDistances[i] = sortedDists[k - 1].dist;
    kNeighborsList[i] = sortedDists.slice(0, k).map(item => item.idx);
  }

  // 3. Local reachability density (lrd)
  const lrd: number[] = [];
  for (let i = 0; i < data.length; i++) {
    let sumReachDist = 0;
    const neighbors = kNeighborsList[i];
    for (const nb of neighbors) {
      // reach_dist(i, nb) = max(k-distance(nb), dist(i, nb))
      sumReachDist += Math.max(kDistances[nb], distMatrix[i][nb]);
    }
    lrd[i] = neighbors.length / (sumReachDist || 0.001);
  }

  // 4. Calculate LOF scores
  const lofScores: number[] = [];
  for (let i = 0; i < data.length; i++) {
    let sumLrdRatio = 0;
    const neighbors = kNeighborsList[i];
    for (const nb of neighbors) {
      sumLrdRatio += lrd[nb] / (lrd[i] || 0.001);
    }
    const score = sumLrdRatio / neighbors.length;
    lofScores[i] = score;
  }

  return lofScores;
}

export function runAnomalyDetection(windows: WindowFeatures[], contamination: number = 0.05): ScoredWindow[] {
  if (windows.length === 0) return [];

  const featureKeys: (keyof WindowFeatures['features'])[] = [
    'total_events',
    'unique_ips',
    'severity_entropy',
    'failed_logins',
    'failed_login_ratio',
    'denied_acls',
    'link_flaps',
    'config_changes',
    'critical_severity_count',
    'auth_attempts',
    'system_restarts',
    'unusual_port_traffic'
  ];

  // Map each window's features to an array of numbers
  const rawFeaturesMatrix = windows.map(win => 
    featureKeys.map(k => win.features[k])
  );

  // Normalize columns (Z-score scaling) so Isolation Forest and LOF aren't biased by feature magnitude
  const numFeatures = featureKeys.length;
  const numSamples = rawFeaturesMatrix.length;

  const means = Array(numFeatures).fill(0);
  const stds = Array(numFeatures).fill(0);

  for (let f = 0; f < numFeatures; f++) {
    const values = rawFeaturesMatrix.map(row => row[f]);
    means[f] = values.reduce((sum, v) => sum + v, 0) / numSamples;
    stds[f] = getStdDev(values, means[f]) || 1.0;
  }

  const normalizedMatrix = rawFeaturesMatrix.map(row =>
    row.map((v, f) => (v - means[f]) / stds[f])
  );

  // Fit Isolation Forest
  const forest = new IsolationForest(100, 256, 42);
  forest.fit(normalizedMatrix);

  // Compute Isolation Forest anomaly scores (0 to 1)
  const iForestScores = normalizedMatrix.map(row => forest.predictScore(row));

  // Compute LOF scores
  const lofScores = calculateLOFScores(normalizedMatrix, Math.min(5, Math.floor(numSamples / 3) || 1));

  // Sort scores to establish a dynamic percentile threshold based on target contamination rate
  const sortedIForestScores = [...iForestScores].sort((a, b) => b - a);
  const cutoffIndex = Math.max(0, Math.min(numSamples - 1, Math.floor(contamination * numSamples)));
  const dynamicThreshold = sortedIForestScores[cutoffIndex] || 0.60;

  // Let's ensure normal stats are computed on truly normal-looking windows to prevent contamination of references
  const normalIndices: number[] = [];
  iForestScores.forEach((sc, idx) => {
    if (sc < 0.53) {
      normalIndices.push(idx);
    }
  });

  // If we don't have enough reference normal windows, use the bottom 80%
  if (normalIndices.length < 5) {
    const threshold80 = sortedIForestScores[Math.floor(numSamples * 0.8)] || 0.5;
    iForestScores.forEach((sc, idx) => {
      if (sc <= threshold80) normalIndices.push(idx);
    });
  }

  // Calculate means and standard deviations for feature attributions based on normal windows
  const normalMeans = Array(numFeatures).fill(0);
  const normalStds = Array(numFeatures).fill(0);

  for (let f = 0; f < numFeatures; f++) {
    const normalVals = normalIndices.map(idx => rawFeaturesMatrix[idx][f]);
    const avg = normalVals.reduce((sum, v) => sum + v, 0) / normalVals.length;
    normalMeans[f] = avg;
    normalStds[f] = getStdDev(normalVals, avg) || 0.001; // Guard zero
  }

  // Build the final ScoredWindow objects
  const scoredWindows: ScoredWindow[] = windows.map((win, idx) => {
    const rawFeatures = rawFeaturesMatrix[idx];
    const score = iForestScores[idx];
    const lofScore = lofScores[idx];

    // An anomaly is flagged if it exceeds either the dynamic contamination threshold (strictly for the target rate)
    // or if the LOF score and IF score are both moderately elevated. Let's make it robust!
    const isAnomaly = score >= dynamicThreshold || (score > 0.58 && lofScore > 1.3);
    const isLofAnomaly = lofScore > 1.5;

    // Feature attribution (Z-scores compared to normal baseline)
    const attributions = featureKeys.map((k, fIdx) => {
      const val = rawFeatures[fIdx];
      const normMean = normalMeans[fIdx];
      const normStd = normalStds[fIdx];

      let zScore = 0;
      if (val > normMean) {
        zScore = (val - normMean) / normStd;
      } else if (val < normMean) {
        zScore = (val - normMean) / normStd;
      }

      return {
        featureName: k,
        zScore: parseFloat(zScore.toFixed(2)),
        value: val,
        mean: parseFloat(normMean.toFixed(2)),
        importance: 0 // Will assign below
      };
    });

    // Compute importance weighting (relative contribution of positive abnormal z-scores)
    const positiveZScores = attributions.map(attr => Math.max(0, attr.zScore));
    const zSum = positiveZScores.reduce((sum, v) => sum + v, 0);

    attributions.forEach((attr, fIdx) => {
      attr.importance = zSum > 0 ? parseFloat((positiveZScores[fIdx] / zSum).toFixed(3)) : 0;
    });

    // Sort attributions by absolute z-score descending so highest drivers are first
    attributions.sort((a, b) => Math.abs(b.zScore) - Math.abs(a.zScore));

    // Construct a concise offline rule-based explanation
    const ruleExplanation = buildRuleExplanation(win, attributions);

    return {
      ...win,
      anomalyScore: parseFloat(score.toFixed(4)),
      isAnomaly,
      isLofAnomaly,
      attributions,
      explanation: ruleExplanation
    };
  });

  return scoredWindows;
}

// Generate an accurate rule-based description based on the highest-attributed features
function buildRuleExplanation(win: WindowFeatures, attributions: ScoredWindow['attributions']): string {
  const topDrivers = attributions.filter(attr => attr.zScore > 1.5).slice(0, 3);
  if (topDrivers.length === 0) {
    return "This window resembles standard, normal background network operations with baseline traffic levels.";
  }

  const descriptors = topDrivers.map(drv => {
    const fName = drv.featureName;
    const val = drv.value;
    const z = drv.zScore;

    switch (fName) {
      case 'failed_logins':
        return `a sharp spike in failed login attempts (${val} errors, z=${z})`;
      case 'failed_login_ratio':
        return `an unusually high fraction of failed credentials (${(val * 100).toFixed(0)}% fail rate)`;
      case 'denied_acls':
        return `heavy traffic blocked by security ACLs (${val} denials, z=${z})`;
      case 'link_flaps':
        return `intermittent physical link state changes / flapping (${val} flaps, z=${z})`;
      case 'config_changes':
        return `unexpected device configuration operations (${val} edits)`;
      case 'critical_severity_count':
        return `elevated emergency or critical error alerts (${val} events)`;
      case 'unique_ips':
        return `traffic coming from an unusual variety of hosts (${val} source IPs)`;
      case 'unusual_port_traffic':
        return `probing directed at restricted services/ports (${val} scans, z=${z})`;
      case 'total_events':
        return `an intense surge in syslog traffic volume (${val} events, z=${z})`;
      case 'severity_entropy':
        return `highly erratic severity distributions (entropy=${val})`;
      case 'system_restarts':
        return `unexpected system reboot or interface reload`;
      default:
        return `deviation in ${fName} (value=${val}, z=${z})`;
    }
  });

  return `Flagged anomalous behavior: Driven primarily by ` + descriptors.join(', ') + '.';
}
