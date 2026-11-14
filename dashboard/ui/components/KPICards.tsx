"use client";

import React from "react";
import { Activity, ShieldAlert, ShieldCheck, Clock, Percent } from "lucide-react";
import { SummaryStats } from "@/lib/api";

interface KPICardsProps {
  stats: SummaryStats | null;
  loading: boolean;
}

export function KPICards({ stats, loading }: KPICardsProps) {
  if (loading || !stats) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {[...Array(5)].map((_, i) => (
          <div
            key={i}
            className="h-28 rounded-xl bg-slate-900/60 border border-slate-800/80 animate-pulse p-4"
          />
        ))}
      </div>
    );
  }

  const cards = [
    {
      title: "Total Requests",
      value: stats.total_requests.toLocaleString(),
      sub: `${stats.total_allowed.toLocaleString()} allowed`,
      icon: Activity,
      color: "text-sky-400",
      bg: "bg-sky-500/10",
      border: "border-sky-500/20",
    },
    {
      title: "Blocked Threats",
      value: stats.total_blocked.toLocaleString(),
      sub: "Active blocks (403)",
      icon: ShieldAlert,
      color: "text-rose-400",
      bg: "bg-rose-500/10",
      border: "border-rose-500/20",
    },
    {
      title: "Flagged Requests",
      value: stats.total_flagged.toLocaleString(),
      sub: "Monitor mode tags",
      icon: ShieldCheck,
      color: "text-amber-400",
      bg: "bg-amber-500/10",
      border: "border-amber-500/20",
    },
    {
      title: "Block Rate",
      value: `${stats.block_rate}%`,
      sub: "Threat ratio",
      icon: Percent,
      color: "text-emerald-400",
      bg: "bg-emerald-500/10",
      border: "border-emerald-500/20",
    },
    {
      title: "Avg Latency",
      value: `${stats.avg_latency_ms} ms`,
      sub: "Target: p95 < 25ms",
      icon: Clock,
      color: "text-indigo-400",
      bg: "bg-indigo-500/10",
      border: "border-indigo-500/20",
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      {cards.map((c, idx) => {
        const Icon = c.icon;
        return (
          <div
            key={idx}
            className="relative overflow-hidden rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg backdrop-blur-sm transition-all hover:border-slate-700"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
                {c.title}
              </span>
              <div className={`p-2 rounded-lg ${c.bg} ${c.border} border`}>
                <Icon className={`w-4 h-4 ${c.color}`} />
              </div>
            </div>
            <div className="mt-3">
              <div className="text-2xl font-bold tracking-tight text-white">
                {c.value}
              </div>
              <div className="mt-1 text-xs text-slate-400">{c.sub}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
