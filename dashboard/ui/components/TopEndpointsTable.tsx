"use client";

import React from "react";
import { TopEndpointItem } from "@/lib/api";

interface TopEndpointsTableProps {
  data: TopEndpointItem[];
  loading: boolean;
}

export function TopEndpointsTable({ data, loading }: TopEndpointsTableProps) {
  return (
    <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg">
      <div className="pb-3 border-b border-slate-800/80">
        <h3 className="text-sm font-semibold text-slate-200">
          Top Attacked Endpoints
        </h3>
        <p className="text-xs text-slate-400">Targeted application routes</p>
      </div>

      <div className="mt-4 overflow-x-auto">
        {loading ? (
          <div className="h-44 flex items-center justify-center text-xs text-slate-500 animate-pulse">
            Loading endpoints...
          </div>
        ) : data.length === 0 ? (
          <div className="h-44 flex items-center justify-center text-xs text-slate-500">
            No targeted routes detected.
          </div>
        ) : (
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="pb-2 font-medium">Endpoint</th>
                <th className="pb-2 font-medium text-right">Attacks</th>
                <th className="pb-2 font-medium text-right">Total Requests</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {data.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-800/30">
                  <td className="py-2.5 text-slate-200 truncate max-w-[200px]" title={item.path}>
                    {item.path}
                  </td>
                  <td className="py-2.5 text-right font-semibold text-rose-400">
                    {item.attack_count}
                  </td>
                  <td className="py-2.5 text-right text-slate-400">
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
