"use client";

import React from "react";
import { SummaryStats } from "@/lib/api";
import { Tile } from "@/components/monolith/ui";

interface KPICardsProps {
  stats: SummaryStats | null;
  loading: boolean;
}

export function KPICards({ stats, loading }: KPICardsProps) {
  if (loading || !stats) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {[...Array(5)].map((_, i) => (
          <div
            key={i}
            className="h-[120px] bg-panel border border-ink p-4 flex flex-col justify-between"
          >
            <div className="h-3 w-20 bg-hair" />
            <div className="h-8 w-28 bg-hair my-2" />
            <div className="h-3 w-24 bg-hair" />
          </div>
        ))}
      </div>
    );
  }

  const items = [
    {
      label: "TOTAL REQUESTS",
      value: stats.total_requests.toLocaleString(),
      sublabel: `${stats.total_allowed.toLocaleString()} ALLOWED`,
      inverted: false,
    },
    {
      label: "BLOCKED",
      value: stats.total_blocked.toLocaleString(),
      sublabel: "ACTIVE BLOCKS (403)",
      inverted: true,
    },
    {
      label: "FLAGGED",
      value: stats.total_flagged.toLocaleString(),
      sublabel: "MONITOR-MODE TAGS",
      inverted: false,
    },
    {
      label: "BLOCK RATE",
      value: `${stats.block_rate}%`,
      sublabel: "THREAT RATIO",
      inverted: false,
    },
    {
      label: "AVG LATENCY",
      value: `${stats.avg_latency_ms} ms`,
      sublabel: "TARGET P95 UNDER 25 MS",
      inverted: false,
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
      {items.map((item, idx) => (
        <Tile
          key={idx}
          label={item.label}
          value={item.value}
          sublabel={item.sublabel}
          inverted={item.inverted}
        />
      ))}
    </div>
  );
}
