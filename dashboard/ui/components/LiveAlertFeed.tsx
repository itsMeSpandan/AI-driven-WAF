"use client";

import React, { useEffect, useState } from "react";
import { API_BASE, EventItem } from "@/lib/api";
import { getAttackLabel } from "@/lib/chart-colors";

interface LiveAlertFeedProps {
  initialEvents: EventItem[];
  onSelectEvent: (event: EventItem) => void;
}

function formatLocalTime(ts: string | undefined): string {
  if (!ts) return "--:--:--";
  try {
    const utcIso =
      ts.includes("Z") || ts.includes("+") ? ts : ts.replace(" ", "T") + "Z";
    const date = new Date(utcIso);
    if (isNaN(date.getTime())) return ts.slice(11, 19);
    return date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return ts.slice(11, 19);
  }
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
    <div className="bg-panel border border-ink">
      {/* Header Strip with Title and Stream Status */}
      <div className="px-4 py-2.5 border-b border-ink flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-[11px] uppercase tracking-[0.06em]">
        <div className="flex items-center gap-3">
          <span className="font-semibold text-ink">LIVE EVENTS</span>
          <span className="text-muted">({filtered.length} EVENTS)</span>
          <div className="flex items-center gap-1.5 ml-2">
            {connected ? (
              <span className="inline-flex items-center gap-1.5 text-ink font-semibold">
                <span className="w-2 h-2 bg-ink inline-block" /> LIVE
              </span>
            ) : reconnecting ? (
              <span className="inline-flex items-center gap-1.5 text-muted">
                <span className="w-2 h-2 border border-ink inline-block" /> RECONNECTING
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-muted">
                PAUSED
              </span>
            )}
          </div>
        </div>

        {/* Quick Search */}
        <div className="w-full sm:w-64">
          <input
            type="text"
            placeholder="Search IP, path, query..."
            value={filterQuery}
            onChange={(e) => {
              setFilterQuery(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full bg-panel text-ink border border-ink px-2.5 py-1 text-[12px] font-mono focus:outline-none placeholder:text-muted"
          />
        </div>
      </div>

      {/* Filter Bar */}
      <div className="px-4 py-2 border-b border-hair flex items-center gap-2 flex-wrap text-[12px] font-mono bg-panel">
        <span className="text-muted text-[11px] uppercase tracking-[0.06em] mr-1">
          FILTERS:
        </span>

        {/* Verdict Filter */}
        <select
          value={filterVerdict}
          onChange={(e) => {
            setFilterVerdict(e.target.value);
            setCurrentPage(1);
          }}
          className="bg-panel text-ink border border-ink px-2 py-1 text-[12px] font-mono focus:outline-none"
        >
          <option value="all">ALL VERDICTS</option>
          <option value="block">BLOCK ONLY</option>
          <option value="flag">FLAG ONLY</option>
          <option value="allow">ALLOW ONLY</option>
        </select>

        {/* Attack Type Filter */}
        <select
          value={filterAttackType}
          onChange={(e) => {
            setFilterAttackType(e.target.value);
            setCurrentPage(1);
          }}
          className="bg-panel text-ink border border-ink px-2 py-1 text-[12px] font-mono focus:outline-none"
        >
          <option value="all">ALL THREAT TYPES</option>
          <option value="sqli">SQLi</option>
          <option value="xss">XSS</option>
          <option value="path_traversal">PATH TRAVERSAL</option>
          <option value="rce">COMMAND INJECTION</option>
          <option value="scanner">SCANNER PROBE</option>
          <option value="benign">BENIGN ONLY</option>
        </select>

        {/* Anomaly Flag Filter */}
        <select
          value={filterAnomaly}
          onChange={(e) => {
            setFilterAnomaly(e.target.value);
            setCurrentPage(1);
          }}
          className="bg-panel text-ink border border-ink px-2 py-1 text-[12px] font-mono focus:outline-none"
        >
          <option value="all">ALL ANOMALIES</option>
          <option value="rate_burst">RATE BURST</option>
          <option value="block_burst">BLOCK BURST</option>
          <option value="scanner_like">SCANNER PROBE</option>
        </select>

        {/* Feedback Filter */}
        <select
          value={filterFeedback}
          onChange={(e) => {
            setFilterFeedback(e.target.value);
            setCurrentPage(1);
          }}
          className="bg-panel text-ink border border-ink px-2 py-1 text-[12px] font-mono focus:outline-none"
        >
          <option value="all">ALL FEEDBACK</option>
          <option value="unlabeled">UNLABELED</option>
          <option value="fp">FALSE POSITIVE (FP)</option>
          <option value="tp">CONFIRMED THREAT (TP)</option>
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
            className="text-[11px] text-ink underline hover:text-muted ml-auto font-mono uppercase"
          >
            Reset Filters
          </button>
        )}
      </div>

      {/* Events Table */}
      <div className="overflow-x-auto min-h-[360px]">
        <table className="w-full text-left font-mono text-[12px] border-collapse">
          <thead>
            <tr className="bg-ink text-white text-[11px] uppercase tracking-[0.06em]">
              <th className="px-3.5 py-2 font-medium">Time</th>
              <th className="px-3.5 py-2 font-medium">Verdict</th>
              <th className="px-3.5 py-2 font-medium">Threat</th>
              <th className="px-3.5 py-2 font-medium">Request</th>
              <th className="px-3.5 py-2 font-medium">Client IP</th>
              <th className="px-3.5 py-2 font-medium text-right">Score</th>
              <th className="px-3.5 py-2 font-medium text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-hair">
            {pagedEvents.length === 0 ? (
              <tr>
                <td colSpan={7} className="text-center py-12 text-muted font-mono">
                  NO REQUESTS MATCH YOUR SELECTED FILTERS.
                </td>
              </tr>
            ) : (
              pagedEvents.map((ev) => {
                const verdictUpper = (ev.verdict || "").toUpperCase();
                return (
                  <tr
                    key={ev.id}
                    className="even:bg-panel odd:bg-zebra hover:bg-hover cursor-pointer transition-colors"
                    onClick={() => onSelectEvent(ev)}
                  >
                    <td className="px-3.5 py-2 text-ink whitespace-nowrap" title={ev.ts}>
                      {formatLocalTime(ev.ts)}
                    </td>
                    <td className="px-3.5 py-2 whitespace-nowrap">
                      {verdictUpper === "BLOCK" ? (
                        <span className="font-semibold text-ink">BLOCK</span>
                      ) : verdictUpper === "FLAG" ? (
                        <span className="font-semibold text-ink border border-ink px-1">FLAG</span>
                      ) : (
                        <span className="text-muted font-normal">ALLOW</span>
                      )}
                    </td>
                    <td className="px-3.5 py-2 whitespace-nowrap">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-ink">
                          {getAttackLabel(ev.attack_type)}
                        </span>
                        {ev.anomaly_flag && (
                          <span className="font-mono text-[10px] text-muted border border-hair px-1 uppercase">
                            {ev.anomaly_flag}
                          </span>
                        )}
                        {ev.feedback && (
                          <span className="font-mono text-[10px] text-ink border border-ink px-1 uppercase">
                            {ev.feedback}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-3.5 py-2 text-ink truncate max-w-[280px]">
                      <span className="font-semibold mr-2">{ev.method}</span>
                      <span>{ev.path}</span>
                    </td>
                    <td className="px-3.5 py-2 text-ink whitespace-nowrap">
                      {ev.client_ip}
                    </td>
                    <td className="px-3.5 py-2 text-right text-ink whitespace-nowrap font-medium">
                      {ev.ml_score.toFixed(3)}
                    </td>
                    <td className="px-3.5 py-2 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectEvent(ev);
                        }}
                        className="text-ink underline hover:text-muted"
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

      {/* Pagination Controls */}
      <div className="px-4 py-2.5 border-t border-hair flex items-center justify-between text-[11px] font-mono text-muted bg-panel">
        <div>
          SHOWING{" "}
          <strong className="text-ink">
            {filtered.length === 0 ? 0 : (activePage - 1) * pageSize + 1}
          </strong>{" "}
          TO{" "}
          <strong className="text-ink">
            {Math.min(activePage * pageSize, filtered.length)}
          </strong>{" "}
          OF <strong className="text-ink">{filtered.length}</strong> EVENTS
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            disabled={activePage <= 1}
            className="px-2 py-1 border border-ink text-ink disabled:text-muted disabled:border-hair hover:bg-hover transition-colors"
          >
            PREV
          </button>
          <span>
            PAGE {activePage} OF {totalPages}
          </span>
          <button
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            disabled={activePage >= totalPages}
            className="px-2 py-1 border border-ink text-ink disabled:text-muted disabled:border-hair hover:bg-hover transition-colors"
          >
            NEXT
          </button>
        </div>
      </div>
    </div>
  );
}
