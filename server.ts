import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { generateSyntheticLogs, parseLogLine, aggregateLogsToWindows } from './src/utils/logParser';
import { runAnomalyDetection } from './src/ml/detector';
import { explainAnomalyWithAI } from './src/utils/geminiExplainer';
import { AnomalyPreset, RawLogLine } from './src/types/netlog';

const app = express();
const PORT = 3000;

// Body parser
app.use(express.json({ limit: '10mb' }));

// Keep an in-memory cache of the last pipeline run to allow granular queries
let lastRunResults: {
  logs: RawLogLine[];
  windows: any[];
  preset: AnomalyPreset;
  timestamp: string;
} | null = null;

// API Routes
app.get('/api/status', (req, res) => {
  res.json({
    status: 'online',
    hasGeminiKey: !!process.env.GEMINI_API_KEY,
    timestamp: new Date().toISOString()
  });
});

// Run full pipeline
app.post('/api/pipeline/run', (req, res) => {
  try {
    const { preset = 'all_mixed', windowMinutes = 5, contamination = 0.05 } = req.body;

    console.log(`Running pipeline: Preset=${preset}, window=${windowMinutes}m, contamination=${contamination}`);

    // 1. Generate logs
    const rawLines = generateSyntheticLogs(preset as AnomalyPreset, 12); // 12 hours of data
    
    // 2. Parse logs & mask PII
    const parsedLogs = rawLines.map((line, idx) => parseLogLine(line, `log-${idx}`));

    // 3. Roll up into windows
    const windows = aggregateLogsToWindows(parsedLogs, Number(windowMinutes));

    // 4. Run Isolation Forest + LOF Anomaly detection
    const scoredWindows = runAnomalyDetection(windows, Number(contamination));

    // Cache results
    lastRunResults = {
      logs: parsedLogs,
      windows: scoredWindows,
      preset: preset as AnomalyPreset,
      timestamp: new Date().toISOString()
    };

    res.json({
      success: true,
      summary: {
        totalLogs: parsedLogs.length,
        totalWindows: scoredWindows.length,
        anomalyCount: scoredWindows.filter(w => w.isAnomaly).length,
        preset,
        windowMinutes,
        contamination
      },
      windows: scoredWindows
    });
  } catch (error: any) {
    console.error('Pipeline execution error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Custom Log Upload Analyzer
app.post('/api/pipeline/upload', (req, res) => {
  try {
    const { rawLogsText, windowMinutes = 5, contamination = 0.05 } = req.body;

    if (!rawLogsText || typeof rawLogsText !== 'string') {
      return res.status(400).json({ success: false, error: 'rawLogsText is required as a string.' });
    }

    // Split raw lines
    const rawLines = rawLogsText
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0);

    if (rawLines.length === 0) {
      return res.status(400).json({ success: false, error: 'No valid log lines found.' });
    }

    // Parse logs & mask PII
    const parsedLogs = rawLines.map((line, idx) => parseLogLine(line, `upload-log-${idx}`));

    // Roll up into windows
    const windows = aggregateLogsToWindows(parsedLogs, Number(windowMinutes));

    // Run ML Anomaly detection
    const scoredWindows = runAnomalyDetection(windows, Number(contamination));

    // Cache results
    lastRunResults = {
      logs: parsedLogs,
      windows: scoredWindows,
      preset: 'clean', // custom uploads treated as custom clean-base
      timestamp: new Date().toISOString()
    };

    res.json({
      success: true,
      summary: {
        totalLogs: parsedLogs.length,
        totalWindows: scoredWindows.length,
        anomalyCount: scoredWindows.filter(w => w.isAnomaly).length,
        windowMinutes,
        contamination
      },
      windows: scoredWindows
    });
  } catch (error: any) {
    console.error('Upload processing error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Explain anomalous window with Gemini AI
app.post('/api/explain', async (req, res) => {
  try {
    const { window } = req.body;
    if (!window || !window.windowId) {
      return res.status(400).json({ error: 'Valid ScoredWindow is required in request body.' });
    }

    console.log(`Explaining window ${window.windowId} with AI...`);
    const aiExplanation = await explainAnomalyWithAI(window);

    res.json({
      windowId: window.windowId,
      aiExplanation
    });
  } catch (error: any) {
    console.error('AI explanation route error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get logs in a specific window
app.get('/api/window/:windowId/logs', (req, res) => {
  const { windowId } = req.params;
  if (!lastRunResults) {
    return res.status(400).json({ error: 'No pipeline data available. Run the pipeline first.' });
  }

  const foundWindow = lastRunResults.windows.find(w => w.windowId === windowId);
  if (!foundWindow) {
    return res.status(404).json({ error: 'Window not found.' });
  }

  res.json({
    windowId,
    timestamp: foundWindow.timestamp,
    logs: foundWindow.rawLogs
  });
});

// Configure Vite or Serve static assets
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer();
