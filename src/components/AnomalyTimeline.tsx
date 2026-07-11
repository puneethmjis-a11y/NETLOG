import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, ReferenceLine, CartesianGrid } from 'recharts';
import { ScoredWindow } from '../types/netlog';

interface AnomalyTimelineProps {
  windows: ScoredWindow[];
  selectedWindow: ScoredWindow | null;
  onSelectWindow: (win: ScoredWindow) => void;
}

export default function AnomalyTimeline({ windows, selectedWindow, onSelectWindow }: AnomalyTimelineProps) {
  if (windows.length === 0) {
    return (
      <div className="bg-white border border-slate-200 rounded-xl p-8 text-center text-slate-400">
        No pipeline data loaded. Start the generator to see telemetry.
      </div>
    );
  }

  // Format data for Recharts
  const chartData = windows.map((win, idx) => ({
    id: win.windowId,
    index: idx,
    time: win.timestamp.split(' ')[0], // just the HH:MM
    fullTime: win.timestamp,
    score: win.anomalyScore,
    volume: win.features.total_events,
    isAnomaly: win.isAnomaly,
    original: win
  }));

  // Find max score or volume for custom references
  const threshold = 0.55; // visual guide

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5 mb-6 relative shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-bold text-slate-900 tracking-tight">Timeline Analytics Telemetry</h3>
          <p className="text-xs text-slate-500 mt-0.5">Click any node on the timeline to inspect features, raw syslog dumps, and AI analysis.</p>
        </div>
        <div className="flex items-center space-x-4 mt-2 sm:mt-0 font-mono text-xs">
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 bg-rose-500 rounded-full" />
            <span className="text-rose-600 font-semibold">ML Anomaly (Score &gt; Threshold)</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 bg-blue-500 rounded-full" />
            <span className="text-blue-600 font-semibold">Normal operations</span>
          </div>
        </div>
      </div>

      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={chartData}
            margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
            onClick={(state: any) => {
              if (state && state.activePayload && state.activePayload.length > 0) {
                const clickedNode = state.activePayload[0].payload.original;
                onSelectWindow(clickedNode);
              }
            }}
          >
            <defs>
              <linearGradient id="scoreColor" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2}/>
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.01}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
            <XAxis
              dataKey="time"
              stroke="#94a3b8"
              fontSize={10}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              stroke="#94a3b8"
              fontSize={10}
              domain={[0, 1]}
              tickLine={false}
              axisLine={false}
              tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
            />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const data = payload[0].payload;
                  const isSelected = selectedWindow?.windowId === data.id;
                  return (
                    <div className="bg-white border border-slate-200 p-3 rounded-lg shadow-xl font-mono text-xs space-y-1">
                      <p className="text-slate-800 font-bold">{data.fullTime}</p>
                      <p className="flex justify-between space-x-4">
                        <span className="text-slate-500">ML Outlier Score:</span>
                        <span className={`font-bold ${data.isAnomaly ? 'text-rose-600' : 'text-blue-600'}`}>
                          {(data.score * 100).toFixed(1)}%
                        </span>
                      </p>
                      <p className="flex justify-between space-x-4">
                        <span className="text-slate-500">Log Count:</span>
                        <span className="text-slate-800 font-bold">{data.volume} lines</span>
                      </p>
                      {data.isAnomaly && (
                        <p className="text-rose-600 text-[10px] font-semibold uppercase tracking-wider mt-1">
                          ⚠️ Anomalous Activity
                        </p>
                      )}
                      <p className="text-[10px] text-slate-400 mt-1 italic">
                        {isSelected ? '✓ Currently Selected' : 'Click to inspect window'}
                      </p>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Area
              type="monotone"
              dataKey="score"
              stroke="#3b82f6"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#scoreColor)"
              dot={(props: any) => {
                const { cx, cy, payload } = props;
                const isSelected = selectedWindow?.windowId === payload.id;
                const r = isSelected ? 6 : payload.isAnomaly ? 4 : 2;
                const stroke = isSelected ? '#3b82f6' : 'none';
                const strokeWidth = isSelected ? 2 : 0;
                const fill = payload.isAnomaly ? '#f43f5e' : '#3b82f6';
                return (
                  <circle
                    key={`dot-${payload.id}`}
                    cx={cx}
                    cy={cy}
                    r={r}
                    fill={fill}
                    stroke={stroke}
                    strokeWidth={strokeWidth}
                    className="cursor-pointer transition-all duration-150"
                    onClick={() => onSelectWindow(payload.original)}
                  />
                );
              }}
              activeDot={{ r: 7, stroke: '#3b82f6', strokeWidth: 2 }}
            />
            <ReferenceLine
              y={threshold}
              stroke="#f43f5e"
              strokeDasharray="4 4"
              strokeOpacity={0.6}
              label={{
                value: 'Anomaly Cutoff',
                position: 'insideBottomRight',
                fill: '#f43f5e',
                fontSize: 9,
                fontFamily: 'JetBrains Mono',
                dy: -4
              }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
