"use client";

import React, { useEffect, useState } from "react";
import { Radio, AlertTriangle, ShieldCheck, ShieldAlert, Search } from "lucide-react";
import { API_BASE, EventItem } from "@/lib/api";

interface LiveAlertFeedProps {
  initialEvents: EventItem[];
  onSelectEvent: (event: EventItem) => void;
}

export function LiveAlertFeed({
  initialEvents,
  onSelectEvent,
}: LiveAlertFeedProps) {
  const [events, setEvents] = useState<EventItem[]>(initialEvents);
  const [filterVerdict, setFilterVerdict] = useState<string>("all");
  const [filterQuery, setFilterQuery] = useState<string>("");
  const [connected, setConnected] = useState<boolean>(false);

  useEffect(() => {
    setEvents(initialEvents);
  }, [initialEvents]);

  // Connect to SSE stream
  useEffect(() => {
    let eventSource: EventSource | null = null;
    try {
      eventSource = new EventSource(`${API_BASE}/api/stream`);

      eventSource.onopen = () => {
        setConnected(true);
      };

      eventSource.addEventListener("alert", (e) => {
        try {
          const newEvent: EventItem = JSON.parse(e.data);
          setEvents((prev) => [newEvent, ...prev.slice(0, 99)]);
        } catch (err) {
          console.error("Error parsing SSE event:", err);
        }
      });

      eventSource.onerror = () => {
        setConnected(false);
      };
    } catch (e) {
      console.error("SSE connection failed:", e);
    }

    return () => {
      if (eventSource) eventSource.close();
    };
  }, []);

  const filtered = events.filter((ev) => {
    if (filterVerdict !== "all" && ev.verdict !== filterVerdict) return false;
    if (filterQuery) {
      const q = filterQuery.toLowerCase();
      return (
        ev.path.toLowerCase().includes(q) ||
        ev.client_ip.toLowerCase().includes(q) ||
        ev.attack_type.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800/80 gap-3">
        <div className="flex items-center gap-2.5">
          <h3 className="text-sm font-semibold text-slate-200">
            Live Alert Feed
          </h3>
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-slate-950 border border-slate-800 text-[11px]">
            <span
              className={`w-2 h-2 rounded-full ${
                connected ? "bg-emerald-500 animate-pulse" : "bg-slate-600"
              }`}
            />
            <span className={connected ? "text-emerald-400" : "text-slate-400"}>
              {connected ? "LIVE SSE" : "OFFLINE"}
            </span>
          </div>
        </div>

        {/* Filter controls */}
        <div className="flex items-center gap-2 self-start sm:self-auto flex-wrap">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search IP, path, type..."
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              className="bg-slate-950/80 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>

          <div className="flex items-center gap-1 bg-slate-950/80 p-0.5 rounded-lg border border-slate-800">
            {["all", "block", "flag", "allow"].map((v) => (
              <button
                key={v}
                onClick={() => setFilterVerdict(v)}
                className={`px-2 py-1 text-[11px] font-medium rounded capitalize transition-colors ${
                  filterVerdict === v
                    ? "bg-slate-800 text-white"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {v}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="mt-4 overflow-x-auto max-h-[460px] overflow-y-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead className="sticky top-0 bg-slate-900 border-b border-slate-800 text-slate-400 font-sans">
            <tr>
              <th className="py-2 px-3">Time</th>
              <th className="py-2 px-3">Verdict</th>
              <th className="py-2 px-3">Type</th>
              <th className="py-2 px-3">Method & Path</th>
              <th className="py-2 px-3">Client IP</th>
              <th className="py-2 px-3 text-right">ML Score</th>
              <th className="py-2 px-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="text-center py-8 text-slate-500">
                  No alerts match your filter criteria.
                </td>
              </tr>
            ) : (
              filtered.map((ev) => {
                let badgeBg = "bg-slate-800/60 text-slate-300 border-slate-700";
                if (ev.verdict === "block") {
                  badgeBg = "bg-rose-500/10 text-rose-400 border-rose-500/30";
                } else if (ev.verdict === "flag") {
                  badgeBg = "bg-amber-500/10 text-amber-400 border-amber-500/30";
                } else if (ev.verdict === "allow") {
                  badgeBg = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
                }

                return (
                  <tr
                    key={ev.id}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                    onClick={() => onSelectEvent(ev)}
                  >
                    <td className="py-2 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                      {ev.ts ? ev.ts.slice(11, 19) : "--:--:--"}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border ${badgeBg}`}
                      >
                        {ev.verdict}
                      </span>
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <span className="text-slate-300 capitalize text-xs">
                        {ev.attack_type}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-200 truncate max-w-[280px]">
                      <span className="font-semibold text-sky-400 mr-2">
                        {ev.method}
                      </span>
                      {/* Strictly rendered as plain text string to prevent XSS */}
                      <span>{ev.path}</span>
                    </td>
                    <td className="py-2 px-3 text-slate-400 whitespace-nowrap">
                      {ev.client_ip}
                    </td>
                    <td className="py-2 px-3 text-right text-slate-300 whitespace-nowrap">
                      {ev.ml_score.toFixed(3)}
                    </td>
                    <td className="py-2 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectEvent(ev);
                        }}
                        className="text-xs text-sky-400 hover:text-sky-300 hover:underline"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
