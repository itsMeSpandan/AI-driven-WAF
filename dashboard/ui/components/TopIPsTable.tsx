"use client";

import React from "react";
import { TopIPItem } from "@/lib/api";

interface TopIPsTableProps {
  data: TopIPItem[];
  loading?: boolean;
}

export function TopIPsTable({ data, loading }: TopIPsTableProps) {
  return (
    <div className="bg-panel border border-ink">
      {/* Header Strip */}
      <div className="px-4 py-2.5 border-b border-ink font-mono text-[11px] uppercase tracking-[0.06em] font-semibold text-ink flex items-center justify-between">
        <span>TOP NOISY / THREAT SOURCE IPS</span>
        <span className="text-muted">{data.length} SOURCES</span>
      </div>

      <div className="overflow-x-auto">
        {loading ? (
          <div className="h-44 flex items-center justify-center font-mono text-xs text-muted">
            LOADING IP SOURCES...
          </div>
        ) : data.length === 0 ? (
          <div className="h-44 flex items-center justify-center font-mono text-xs text-muted">
            NO IP ACTIVITY RECORDED IN SELECTED TIME WINDOW.
          </div>
        ) : (
          <table className="w-full text-left font-mono text-[12px] border-collapse">
            <thead>
              <tr className="bg-ink text-white text-[11px] uppercase tracking-[0.06em]">
                <th className="px-3.5 py-2 font-medium">Source IP</th>
                <th className="px-3.5 py-2 font-medium text-right">Requests</th>
                <th className="px-3.5 py-2 font-medium text-right">Blocks</th>
                <th className="px-3.5 py-2 font-medium text-right">Block %</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hair">
              {data.map((item, idx) => {
                const blockRatio =
                  item.total_requests > 0
                    ? Math.round((item.blocked_requests / item.total_requests) * 100)
                    : 0;

                return (
                  <tr
                    key={idx}
                    className="even:bg-panel odd:bg-zebra hover:bg-hover transition-colors"
                  >
                    <td className="px-3.5 py-2 text-ink font-semibold">
                      {item.ip}
                    </td>
                    <td className="px-3.5 py-2 text-right text-muted">
                      {item.total_requests}
                    </td>
                    <td className="px-3.5 py-2 text-right text-ink font-medium">
                      {item.blocked_requests}
                    </td>
                    <td className="px-3.5 py-2 text-right text-muted">
                      {blockRatio}%
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
