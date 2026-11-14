"use client";

import React from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { AttackTypeItem } from "@/lib/api";

const COLORS = ["#f43f5e", "#fbbf24", "#38bdf8", "#a855f7", "#ec4899"];

interface AttackTypeDonutProps {
  data: AttackTypeItem[];
  loading: boolean;
}

export function AttackTypeDonut({ data, loading }: AttackTypeDonutProps) {
  const chartData = data.map((d) => ({
    name: d.attack_type.toUpperCase(),
    value: d.count,
    percentage: d.percentage,
  }));

  const total = chartData.reduce((acc, cur) => acc + cur.value, 0);

  return (
    <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg flex flex-col justify-between">
      <div className="pb-3 border-b border-slate-800/80">
        <h3 className="text-sm font-semibold text-slate-200">
          Attack Breakdown
        </h3>
        <p className="text-xs text-slate-400">Threat distribution by payload class</p>
      </div>

      <div className="h-56 mt-2 relative">
        {loading ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-500 animate-pulse">
            Loading attack metrics...
          </div>
        ) : chartData.length === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-500">
            No attacks recorded yet
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                innerRadius={55}
                outerRadius={80}
                paddingAngle={4}
                dataKey="value"
              >
                {chartData.map((_, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={COLORS[index % COLORS.length]}
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "#0f172a",
                  borderColor: "#334155",
                  borderRadius: "8px",
                  color: "#f8fafc",
                  fontSize: "12px",
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="grid grid-cols-2 gap-2 pt-3 border-t border-slate-800/80">
        {chartData.map((item, idx) => (
          <div key={idx} className="flex items-center gap-2 text-xs">
            <span
              className="w-2.5 h-2.5 rounded-full shrink-0"
              style={{ backgroundColor: COLORS[idx % COLORS.length] }}
            />
            <span className="text-slate-400 truncate">{item.name}</span>
            <span className="text-slate-200 font-semibold ml-auto">
              {item.percentage}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
