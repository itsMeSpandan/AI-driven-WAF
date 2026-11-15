"use client";

import React, { useEffect, useState } from "react";
import {
  Radio,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  Zap,
  Flame,
  Bug,
} from "lucide-react";
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
  const [filterAttackType, setFilterAttackType] = useState<string>("all");
  const [filterAnomaly, setFilterAnomaly] = useState<string>("all");
  const [filterFeedback, setFilterFeedback] = useState<string>("all");
  const [filterQuery, setFilterQuery] = useState<string>("");
  const [connected, setConnected] = useState<boolean>(false);
  const [reconnecting, setReconnecting] = useState<boolean>(false);

  // Pagination state
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 15;

  useEffect(() => {
    setEvents(initialEvents);
  }, [initialEvents]);

  // Connect to SSE stream
  useEffect(() => {
    let eventSource: EventSource | null = null;
    let reconnectTimer: any = null;

    const connectSSE = () => {
      try {
        eventSource = new EventSource(`${API_BASE}/api/stream`);

        eventSource.onopen = () => {
          setConnected(true);
          setReconnecting(false);
        };

        eventSource.addEventListener("alert", (e) => {
          try {
            const newEvent: EventItem = JSON.parse(e.data);
            setEvents((prev) => [newEvent, ...prev.slice(0, 199)]);
          } catch (err) {
            console.error("Error parsing SSE event:", err);
          }
        });

        eventSource.onerror = () => {
          setConnected(false);
          setReconnecting(true);
          if (eventSource) eventSource.close();
          // Attempt retry in 5s
          reconnectTimer = setTimeout(connectSSE, 5000);
        };
      } catch (e) {
        console.error("SSE connection failed:", e);
        setConnected(false);
      }
    };

    connectSSE();

    return () => {
      if (eventSource) eventSource.close();
      if (reconnectTimer) clearTimeout(reconnectTimer);
    };
  }, []);

  // Multi-facet filtering
  const filtered = events.filter((ev) => {
    if (filterVerdict !== "all" && ev.verdict !== filterVerdict) return false;
    if (filterAttackType !== "all" && ev.attack_type.toLowerCase() !== filterAttackType.toLowerCase()) return false;
    if (filterAnomaly !== "all" && ev.anomaly_flag !== filterAnomaly) return false;
    if (filterFeedback === "unlabeled" && ev.feedback) return false;
    if (filterFeedback === "fp" && ev.feedback !== "fp") return false;
    if (filterFeedback === "tp" && ev.feedback !== "tp") return false;

    if (filterQuery) {
      const q = filterQuery.toLowerCase();
      const matchPath = ev.path?.toLowerCase().includes(q);
      const matchIp = ev.client_ip?.toLowerCase().includes(q);
      const matchType = ev.attack_type?.toLowerCase().includes(q);
      const matchMethod = ev.method?.toLowerCase().includes(q);
      const matchQuery = ev.query_summary?.toLowerCase().includes(q);
      if (!matchPath && !matchIp && !matchType && !matchMethod && !matchQuery) {
        return false;
      }
    }
    return true;
  });

  // Calculate pagination slice
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const activePage = Math.min(currentPage, totalPages);
  const pagedEvents = filtered.slice((activePage - 1) * pageSize, activePage * pageSize);

  return (
    <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg flex flex-col justify-between">
      <div>
        {/* Header with Title and Connection Pill */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800/80 gap-3">
          <div className="flex items-center gap-2.5">
            <h3 className="text-sm font-semibold text-slate-200">
              Live Alert & Audit Feed
            </h3>
            <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-slate-950 border border-slate-800 text-[11px]">
              <span
                className={`w-2 h-2 rounded-full ${
                  connected
                    ? "bg-emerald-500 animate-pulse"
                    : reconnecting
                    ? "bg-amber-500 animate-ping"
                    : "bg-slate-600"
                }`}
              />
              <span
                className={
                  connected
                    ? "text-emerald-400 font-medium"
                    : reconnecting
                    ? "text-amber-400 font-medium"
                    : "text-slate-400 font-medium"
                }
              >
                {connected ? "LIVE SSE" : reconnecting ? "RECONNECTING" : "OFFLINE"}
              </span>
            </div>
            <span className="text-[11px] text-slate-500 font-mono hidden sm:inline">
              ({filtered.length} matching)
            </span>
          </div>

          {/* Quick Search */}
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search IP, path, query..."
              value={filterQuery}
              onChange={(e) => {
                setFilterQuery(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-slate-950/80 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
            />
          </div>
        </div>

        {/* Multi-facet Filter Bar */}
        <div className="flex items-center gap-2 py-3 border-b border-slate-800/60 flex-wrap text-xs">
          <span className="text-slate-500 text-[11px] flex items-center gap-1 mr-1">
            <Filter className="w-3 h-3" /> Filters:
          </span>

          {/* Verdict Filter */}
          <select
            value={filterVerdict}
            onChange={(e) => {
              setFilterVerdict(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 text-xs focus:outline-none focus:border-sky-500"
          >
            <option value="all">All Verdicts</option>
            <option value="block">Block Only</option>
            <option value="flag">Flag Only</option>
            <option value="allow">Allow Only</option>
          </select>

          {/* Attack Type Filter */}
          <select
            value={filterAttackType}
            onChange={(e) => {
              setFilterAttackType(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 text-xs focus:outline-none focus:border-sky-500"
          >
            <option value="all">All Threat Types</option>
            <option value="sqli">SQLi</option>
            <option value="xss">XSS</option>
            <option value="path_traversal">Path Traversal</option>
            <option value="rce">Command Injection</option>
            <option value="scanner">Scanner Probe</option>
            <option value="benign">Benign Only</option>
          </select>

          {/* Anomaly Flag Filter */}
          <select
            value={filterAnomaly}
            onChange={(e) => {
              setFilterAnomaly(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 text-xs focus:outline-none focus:border-sky-500"
          >
            <option value="all">All Anomaly Flags</option>
            <option value="rate_burst">Rate Burst Flag</option>
            <option value="block_burst">Block Burst Flag</option>
            <option value="scanner_like">Scanner Probing Flag</option>
          </select>

          {/* Feedback Filter */}
          <select
            value={filterFeedback}
            onChange={(e) => {
              setFilterFeedback(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 text-xs focus:outline-none focus:border-sky-500"
          >
            <option value="all">All Feedback</option>
            <option value="unlabeled">Unlabeled Only</option>
            <option value="fp">False Positive (FP)</option>
            <option value="tp">True Threat (TP)</option>
          </select>

          {(filterVerdict !== "all" ||
            filterAttackType !== "all" ||
            filterAnomaly !== "all" ||
            filterFeedback !== "all" ||
            filterQuery) && (
            <button
              onClick={() => {
                setFilterVerdict("all");
                setFilterAttackType("all");
                setFilterAnomaly("all");
                setFilterFeedback("all");
                setFilterQuery("");
                setCurrentPage(1);
              }}
              className="text-[11px] text-sky-400 hover:underline ml-auto"
            >
              Reset Filters
            </button>
          )}
        </div>

        {/* Table of Events */}
        <div className="mt-2 overflow-x-auto min-h-[360px]">
          <table className="w-full text-left text-xs font-mono">
            <thead className="sticky top-0 bg-slate-900 border-b border-slate-800 text-slate-400 font-sans">
              <tr>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Verdict</th>
                <th className="py-2.5 px-3">Threat & Anomaly</th>
                <th className="py-2.5 px-3">Method & Path</th>
                <th className="py-2.5 px-3">Client IP</th>
                <th className="py-2.5 px-3 text-right">ML Score</th>
                <th className="py-2.5 px-3 text-right">Feedback</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {pagedEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-12 text-slate-500 font-sans">
                    No requests match your selected filters.
                  </td>
                </tr>
              ) : (
                pagedEvents.map((ev) => {
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
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-slate-300 capitalize text-xs">
                            {ev.attack_type}
                          </span>
                          {ev.anomaly_flag === "rate_burst" && (
                            <span className="inline-flex items-center gap-0.5 px-1.5 py-0.2 rounded text-[9px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                              <Zap className="w-2.5 h-2.5" /> burst
                            </span>
                          )}
                          {ev.anomaly_flag === "block_burst" && (
                            <span className="inline-flex items-center gap-0.5 px-1.5 py-0.2 rounded text-[9px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                              <ShieldAlert className="w-2.5 h-2.5" /> block_burst
                            </span>
                          )}
                          {ev.anomaly_flag === "scanner_like" && (
                            <span className="inline-flex items-center gap-0.5 px-1.5 py-0.2 rounded text-[9px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                              <Bug className="w-2.5 h-2.5" /> scanner
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-2 px-3 text-slate-200 truncate max-w-[260px]">
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
                        {ev.feedback ? (
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                              ev.feedback === "fp"
                                ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                                : "bg-rose-500/10 text-rose-400 border-rose-500/30"
                            }`}
                          >
                            {ev.feedback.toUpperCase()}
                          </span>
                        ) : (
                          <span className="text-slate-600 text-[10px]">—</span>
                        )}
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

      {/* Pagination Controls */}
      <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
        <div>
          Showing{" "}
          <strong className="text-slate-200">
            {filtered.length === 0 ? 0 : (activePage - 1) * pageSize + 1}
          </strong>{" "}
          to{" "}
          <strong className="text-slate-200">
            {Math.min(activePage * pageSize, filtered.length)}
          </strong>{" "}
          of <strong className="text-slate-200">{filtered.length}</strong> events
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            disabled={activePage <= 1}
            className="p-1 rounded bg-slate-950 border border-slate-800 disabled:opacity-40 hover:text-white"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="font-mono text-[11px]">
            Page {activePage} of {totalPages}
          </span>
          <button
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            disabled={activePage >= totalPages}
            className="p-1 rounded bg-slate-950 border border-slate-800 disabled:opacity-40 hover:text-white"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
