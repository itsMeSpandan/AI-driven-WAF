"use client";

import React from "react";
import { Network, ShieldAlert } from "lucide-react";
import { TopIPItem } from "@/lib/api";

interface TopIPsTableProps {
  data: TopIPItem[];
  loading?: boolean;
}

export function TopIPsTable({ data, loading }: TopIPsTableProps) {
  if (loading) {
    return (
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg animate-pulse h-64">
        <div className="h-4 bg-slate-800 rounded w-1/3 mb-4" />
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-8 bg-slate-800/50 rounded" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              Top Noisy / Threat Source IPs
            </h3>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">
            {data.length} active sources
          </span>
        </div>

        <div className="mt-3 divide-y divide-slate-800/60 font-mono text-xs">
          {data.length === 0 ? (
            <div className="text-center py-6 text-slate-500 text-xs font-sans">
              No IP activity recorded in selected time window.
            </div>
          ) : (
            data.map((item, idx) => {
              const blockRatio =
                item.total_requests > 0
                  ? Math.round((item.blocked_requests / item.total_requests) * 100)
                  : 0;

              return (
                <div
                  key={idx}
                  className="py-2.5 flex items-center justify-between hover:bg-slate-800/30 px-1 rounded transition-colors"
                >
                  <div className="flex items-center gap-2 truncate">
                    <span className="text-slate-500 text-[10px] w-4">
                      #{idx + 1}
                    </span>
                    <span className="text-slate-200 truncate font-semibold">
                      {item.ip}
                    </span>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="text-right">
                      <span className="text-slate-400 text-[11px]">
                        {item.total_requests} reqs
                      </span>
                    </div>
                    {item.blocked_requests > 0 && (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-rose-500/10 text-rose-400 border border-rose-500/30 font-bold">
                        <ShieldAlert className="w-3 h-3" />
                        {item.blocked_requests} ({blockRatio}%)
                      </span>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
