"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Shield,
  Sliders,
  ExternalLink,
  Cpu,
  RefreshCw,
  Bell,
} from "lucide-react";
import {
  API_BASE,
  AttackTypeItem,
  EventItem,
  SummaryStats,
  TimeSeriesPoint,
  TopEndpointItem,
  WAFConfig,
  fetchAttackTypes,
  fetchConfig,
  fetchEvents,
  fetchSummary,
  fetchTimeSeries,
  fetchTopEndpoints,
} from "@/lib/api";
import { KPICards } from "@/components/KPICards";
import { TrafficThreatsChart } from "@/components/TrafficThreatsChart";
import { AttackTypeDonut } from "@/components/AttackTypeDonut";
import { TopEndpointsTable } from "@/components/TopEndpointsTable";
import { LiveAlertFeed } from "@/components/LiveAlertFeed";
import { RequestDetailDrawer } from "@/components/RequestDetailDrawer";
import { SettingsModal } from "@/components/SettingsModal";

export default function DashboardPage() {
  const [stats, setStats] = useState<SummaryStats | null>(null);
  const [timeSeries, setTimeSeries] = useState<TimeSeriesPoint[]>([]);
  const [attackTypes, setAttackTypes] = useState<AttackTypeItem[]>([]);
  const [topEndpoints, setTopEndpoints] = useState<TopEndpointItem[]>([]);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [config, setConfig] = useState<WAFConfig | null>(null);

  const [timeRange, setTimeRange] = useState<string>("24h");
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  // Modals & Drawers
  const [selectedEvent, setSelectedEvent] = useState<EventItem | null>(null);
  const [settingsOpen, setSettingsOpen] = useState<boolean>(false);

  const loadAllData = async (showLoading = false) => {
    try {
      if (showLoading) setLoading(true);
      else setRefreshing(true);

      const [s, ts, at, ep, ev, cfg] = await Promise.all([
        fetchSummary(timeRange),
        fetchTimeSeries(timeRange, timeRange === "1h" ? "1m" : "1h"),
        fetchAttackTypes(timeRange),
        fetchTopEndpoints(5, timeRange),
        fetchEvents(50),
        fetchConfig(),
      ]);

      setStats(s);
      setTimeSeries(ts.points);
      setAttackTypes(at.items);
      setTopEndpoints(ep.items);
      setEvents(ev.items);
      setConfig(cfg);
    } catch (err) {
      console.error("Error refreshing dashboard data:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadAllData(true);
  }, [timeRange]);

  // Periodic polling every 10s for summary aggregations
  useEffect(() => {
    const interval = setInterval(() => {
      loadAllData(false);
    }, 10000);
    return () => clearInterval(interval);
  }, [timeRange]);

  const handleFeedbackUpdated = (id: string, feedback: "fp" | "tp") => {
    setEvents((prev) =>
      prev.map((e) => (e.id === id ? { ...e, feedback } : e))
    );
    if (selectedEvent && selectedEvent.id === id) {
      setSelectedEvent((prev) => (prev ? { ...prev, feedback } : null));
    }
  };

  return (
    <div className="min-h-screen bg-[#090d16] p-4 sm:p-6 lg:p-8 max-w-[1600px] mx-auto text-slate-100">
      {/* Top Navigation Bar */}
      <header className="flex flex-col md:flex-row md:items-center justify-between pb-6 border-b border-slate-800 gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-gradient-to-tr from-sky-500 to-indigo-600 shadow-md shadow-sky-500/20">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-extrabold tracking-tight text-white">
                AI-Driven WAF
              </h1>
              <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-sky-500/10 border border-sky-500/30 text-sky-400">
                SecOps Console
              </span>
            </div>
            <p className="text-xs text-slate-400">
              L7 Reverse-Proxy Inspection & Machine Learning Anomaly Detection
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Active Mode Pill */}
          {config && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs">
              <span className="text-slate-400">Mode:</span>
              <span
                className={`font-bold uppercase tracking-wider ${
                  config.waf_mode === "block"
                    ? "text-rose-400"
                    : "text-amber-400"
                }`}
              >
                {config.waf_mode}
              </span>
              <span className="text-slate-600">|</span>
              <span className="text-slate-400">Threshold:</span>
              <span className="font-mono text-sky-400 font-bold">
                {config.ml_threshold}
              </span>
            </div>
          )}

          {/* Model / Eval Link */}
          <Link
            href="/eval"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <Cpu className="w-3.5 h-3.5 text-sky-400" />
            <span>Model / Eval</span>
          </Link>

          {/* API Docs Link */}
          <a
            href={`${API_BASE}/docs`}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
            <span>API Docs</span>
          </a>

          {/* Manual Refresh */}
          <button
            onClick={() => loadAllData(false)}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            title="Refresh Telemetry"
          >
            <RefreshCw
              className={`w-3.5 h-3.5 ${refreshing ? "animate-spin" : ""}`}
            />
          </button>

          {/* Settings Button */}
          <button
            onClick={() => setSettingsOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-white text-xs font-semibold shadow-md shadow-sky-500/20 transition-all"
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Configure WAF</span>
          </button>
        </div>
      </header>

      {/* Main Content Sections */}
      <main className="mt-6 space-y-6">
        {/* KPI Cards Row */}
        <KPICards stats={stats} loading={loading} />

        {/* Charts & Analytics Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <TrafficThreatsChart
              data={timeSeries}
              range={timeRange}
              onRangeChange={setTimeRange}
              loading={loading}
            />
          </div>
          <div>
            <AttackTypeDonut data={attackTypes} loading={loading} />
          </div>
        </div>

        {/* Top Endpoints & Live Alerts */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1">
            <TopEndpointsTable data={topEndpoints} loading={loading} />
          </div>
          <div className="lg:col-span-2">
            <LiveAlertFeed
              initialEvents={events}
              onSelectEvent={(ev) => setSelectedEvent(ev)}
            />
          </div>
        </div>
      </main>

      {/* Slide-out Request Detail Drawer */}
      <RequestDetailDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
        onFeedbackUpdated={handleFeedbackUpdated}
      />

      {/* Settings Modal */}
      <SettingsModal
        config={config}
        isOpen={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        onConfigUpdated={(newCfg) => setConfig(newCfg)}
      />
    </div>
  );
}
