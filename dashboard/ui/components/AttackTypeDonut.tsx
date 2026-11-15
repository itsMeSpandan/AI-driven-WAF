"use client";

import React from "react";
import { AttackTypeItem } from "@/lib/api";
import { getAttackColor, getAttackLabel } from "@/lib/chart-colors";

interface AttackTypeDonutProps {
  data: AttackTypeItem[];
  loading: boolean;
}

export function AttackTypeDonut({ data, loading }: AttackTypeDonutProps) {
  const total = data.reduce((acc, cur) => acc + cur.count, 0);

  return (
    <div className="bg-panel border border-ink flex flex-col justify-between h-full">
      {/* Header Strip */}
      <div className="px-4 py-2.5 border-b border-ink font-mono text-[11px] uppercase tracking-[0.06em] font-semibold text-ink">
        ATTACK BREAKDOWN
      </div>

      <div className="p-4 flex-1 flex flex-col justify-start">
        {loading ? (
          <div className="h-48 flex items-center justify-center font-mono text-xs text-muted">
            LOADING ATTACK METRICS...
          </div>
        ) : data.length === 0 ? (
          <div className="h-48 flex items-center justify-center font-mono text-xs text-muted">
            NO ATTACKS RECORDED YET.
          </div>
        ) : (
          <>
            {/* 100% Horizontal Stacked Bar (34px high) */}
            <div className="h-[34px] w-full flex border border-ink bg-zebra overflow-hidden">
              {data.map((item, idx) => {
                const color = getAttackColor(item.attack_type);
                const pct = total > 0 ? (item.count / total) * 100 : item.percentage;
                if (pct <= 0) return null;
                return (
                  <div
                    key={idx}
                    style={{
                      width: `${pct}%`,
                      backgroundColor: color,
                    }}
                    title={`${getAttackLabel(item.attack_type)}: ${item.count} (${item.percentage}%)`}
                    className="h-full border-r border-ink last:border-r-0"
                  />
                );
              })}
            </div>

            {/* List of Breakdown Rows */}
            <div className="mt-3 divide-y divide-hair">
              {data.map((item, idx) => {
                const color = getAttackColor(item.attack_type);
                return (
                  <div
                    key={idx}
                    className="flex items-center justify-between py-2 font-mono text-[12px]"
                  >
                    <div className="flex items-center gap-2">
                      <span
                        className="w-2.5 h-2.5 shrink-0 inline-block border border-ink"
                        style={{ backgroundColor: color }}
                      />
                      <span className="text-ink">{getAttackLabel(item.attack_type)}</span>
                    </div>
                    <span className="text-muted">
                      {item.count} &middot; {item.percentage}%
                    </span>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
