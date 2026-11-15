"use client";

import React from "react";
import { TopEndpointItem } from "@/lib/api";

interface TopEndpointsTableProps {
  data: TopEndpointItem[];
  loading: boolean;
}

export function TopEndpointsTable({ data, loading }: TopEndpointsTableProps) {
  return (
    <div className="bg-panel border border-ink">
      {/* Header Strip */}
      <div className="px-4 py-2.5 border-b border-ink font-mono text-[11px] uppercase tracking-[0.06em] font-semibold text-ink">
        TOP ATTACKED ENDPOINTS
      </div>

      <div className="overflow-x-auto">
        {loading ? (
          <div className="h-44 flex items-center justify-center font-mono text-xs text-muted">
            LOADING ENDPOINTS...
          </div>
        ) : data.length === 0 ? (
          <div className="h-44 flex items-center justify-center font-mono text-xs text-muted">
            NO TARGETED ROUTES DETECTED.
          </div>
        ) : (
          <table className="w-full text-left font-mono text-[12px] border-collapse">
            <thead>
              <tr className="bg-ink text-white text-[11px] uppercase tracking-[0.06em]">
                <th className="px-3.5 py-2 font-medium">Endpoint</th>
                <th className="px-3.5 py-2 font-medium text-right">Attacks</th>
                <th className="px-3.5 py-2 font-medium text-right">Total Requests</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hair">
              {data.map((item, idx) => (
                <tr
                  key={idx}
                  className="even:bg-panel odd:bg-zebra hover:bg-hover transition-colors"
                >
                  <td
                    className="px-3.5 py-2 text-ink truncate max-w-[260px]"
                    title={item.path}
                  >
                    {item.path}
                  </td>
                  <td className="px-3.5 py-2 text-right font-semibold text-ink">
                    {item.attack_count}
                  </td>
                  <td className="px-3.5 py-2 text-right text-muted">
                    {item.total_count}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
