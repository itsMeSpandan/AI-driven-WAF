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
import { TRAFFIC_COLOR, THREAT_COLOR } from "@/lib/chart-colors";

interface TrafficThreatsChartProps {
  data: TimeSeriesPoint[];
  range: string;
  onRangeChange: (r: string) => void;
  loading: boolean;
}

function parseLocalTime(isoString: string): string {
  try {
    const utcIso =
      isoString.includes("Z") || isoString.includes("+")
        ? isoString
        : isoString.replace(" ", "T") + "Z";
    const date = new Date(utcIso);
    if (isNaN(date.getTime())) return isoString.slice(11, 16);
    return date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  } catch {
    return isoString.slice(11, 16);
  }
}

export function TrafficThreatsChart({
  data,
  range,
  onRangeChange,
  loading,
}: TrafficThreatsChartProps) {
  const formattedData = data.map((d) => ({
    ...d,
    time: parseLocalTime(d.timestamp),
  }));

  return (
    <div className="bg-panel border border-ink">
      {/* Header Strip */}
      <div className="px-4 py-2.5 border-b border-ink flex items-center justify-between font-mono text-[11px] uppercase tracking-[0.06em]">
        <span className="font-semibold text-ink">
          TRAFFIC VS THREATS &middot; {range.toUpperCase()}
        </span>
        <div className="flex items-center gap-3">
          {["1h", "24h", "7d"].map((r) => (
            <button
              key={r}
              onClick={() => onRangeChange(r)}
              className={`transition-colors font-mono text-[11px] uppercase ${
                range === r
                  ? "text-ink font-bold underline underline-offset-4 decoration-2"
                  : "text-muted hover:text-ink"
              }`}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      <div className="p-4 h-72 w-full">
        {loading ? (
          <div className="h-full flex items-center justify-center font-mono text-xs text-muted">
            LOADING TELEMETRY TIME SERIES...
          </div>
        ) : formattedData.length === 0 ? (
          <div className="h-full flex items-center justify-center font-mono text-xs text-muted">
            NO TELEMETRY RECORDED IN THIS RANGE.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={formattedData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid vertical={false} horizontal={true} stroke="#e1e1de" />
              <XAxis
                dataKey="time"
                stroke="#555555"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: "#111111" }}
                fontFamily="var(--font-ibm-mono)"
              />
              <YAxis
                stroke="#555555"
                fontSize={11}
                tickLine={false}
                axisLine={false}
                fontFamily="var(--font-ibm-mono)"
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#ffffff",
                  borderColor: "#111111",
                  borderRadius: "0px",
                  color: "#111111",
                  fontSize: "11px",
                  fontFamily: "var(--font-ibm-mono)",
                  boxShadow: "none",
                  padding: "8px 12px",
                }}
                itemStyle={{
                  fontFamily: "var(--font-ibm-mono)",
                  fontSize: "11px",
                  padding: "2px 0",
                }}
                labelStyle={{
                  fontFamily: "var(--font-ibm-mono)",
                  fontWeight: 600,
                  marginBottom: "4px",
                  borderBottom: "1px solid #d6d6d2",
                  paddingBottom: "2px",
                }}
                labelFormatter={(label, payload) => {
                  if (payload && payload.length > 0 && payload[0].payload?.timestamp) {
                    const iso = payload[0].payload.timestamp;
                    try {
                      const utcIso =
                        iso.includes("Z") || iso.includes("+")
                          ? iso
                          : iso.replace(" ", "T") + "Z";
                      const date = new Date(utcIso);
                      if (!isNaN(date.getTime())) {
                        return date.toLocaleString([], {
                          month: "short",
                          day: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                          hour12: false,
                        });
                      }
                    } catch {}
                  }
                  return label;
                }}
              />
              <Area
                type="monotone"
                dataKey="total"
                name="Total Requests"
                stroke={TRAFFIC_COLOR}
                strokeWidth={2}
                fill={TRAFFIC_COLOR}
                fillOpacity={0.16}
                isAnimationActive={false}
              />
              <Area
                type="monotone"
                dataKey="threats"
                name="Threats"
                stroke={THREAT_COLOR}
                strokeWidth={2}
                fill={THREAT_COLOR}
                fillOpacity={0.16}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
