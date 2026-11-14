"use client";

import React from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { TimeSeriesPoint } from "@/lib/api";

interface TrafficThreatsChartProps {
  data: TimeSeriesPoint[];
  range: string;
  onRangeChange: (r: string) => void;
  loading: boolean;
}

export function TrafficThreatsChart({
  data,
  range,
  onRangeChange,
  loading,
}: TrafficThreatsChartProps) {
  const formattedData = data.map((d) => ({
    ...d,
    time: d.timestamp.slice(11, 16),
  }));

  return (
    <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800/80 gap-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-200">
            Traffic vs Threats
          </h3>
          <p className="text-xs text-slate-400">
            Total request volume compared against detected threats
          </p>
        </div>
        <div className="flex items-center gap-1.5 bg-slate-950/60 p-1 rounded-lg border border-slate-800 self-start sm:self-auto">
          {["1h", "24h", "7d"].map((r) => (
            <button
              key={r}
              onClick={() => onRangeChange(r)}
              className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                range === r
                  ? "bg-sky-500 text-white shadow-sm"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {r.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="h-72 mt-4 w-full">
        {loading ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-500 animate-pulse">
            Loading telemetry time series...
          </div>
        ) : formattedData.length === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-500">
            No telemetry recorded in this range.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={formattedData}>
              <defs>
                <linearGradient id="totalGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#0f172a",
                  borderColor: "#334155",
                  borderRadius: "8px",
                  color: "#f8fafc",
                  fontSize: "12px",
                }}
              />
              <Area
                type="monotone"
                dataKey="total"
                name="Total Requests"
                stroke="#38bdf8"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#totalGrad)"
              />
              <Area
                type="monotone"
                dataKey="threats"
                name="Threats (Blocked/Flagged)"
                stroke="#f43f5e"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#threatGrad)"
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
