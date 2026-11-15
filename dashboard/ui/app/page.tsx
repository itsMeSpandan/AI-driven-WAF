"use client";

import React, { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import {
  Shield,
  Sliders,
  ExternalLink,
  Cpu,
  RefreshCw,
  Play,
  Pause,
  Lock,
  LogOut,
  User,
  Clock,
} from "lucide-react";
import {
  API_BASE,
  AttackTypeItem,
  AuthUser,
  EventItem,
  SummaryStats,
  TimeSeriesPoint,
  TopEndpointItem,
  TopIPItem,
  WAFConfig,
  fetchAttackTypes,
  fetchConfig,
  fetchCurrentUser,
  fetchEventDetail,
  fetchEvents,
  fetchSummary,
  fetchTimeSeries,
  fetchTopEndpoints,
  fetchTopIPs,
  logoutAdmin,
} from "@/lib/api";
import { KPICards } from "@/components/KPICards";
import { TrafficThreatsChart } from "@/components/TrafficThreatsChart";
import { AttackTypeDonut } from "@/components/AttackTypeDonut";
import { TopEndpointsTable } from "@/components/TopEndpointsTable";
import { TopIPsTable } from "@/components/TopIPsTable";
import { LiveAlertFeed } from "@/components/LiveAlertFeed";
import { RequestDetailDrawer } from "@/components/RequestDetailDrawer";
import { SettingsModal } from "@/components/SettingsModal";
import { LoginModal } from "@/components/LoginModal";

export default function DashboardPage() {
  const [stats, setStats] = useState<SummaryStats | null>(null);
  const [timeSeries, setTimeSeries] = useState<TimeSeriesPoint[]>([]);
  const [attackTypes, setAttackTypes] = useState<AttackTypeItem[]>([]);
  const [topEndpoints, setTopEndpoints] = useState<TopEndpointItem[]>([]);
  const [topIPs, setTopIPs] = useState<TopIPItem[]>([]);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [config, setConfig] = useState<WAFConfig | null>(null);

  // Global Time Range Selector: 5m | 1h | 24h | 7d
  const [timeRange, setTimeRange] = useState<string>("24h");
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  // Auto-refresh controls
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [nextRefreshIn, setNextRefreshIn] = useState<number>(10);

  // Auth state
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [loginModalOpen, setLoginModalOpen] = useState<boolean>(false);

  // Modals & Drawers
  const [selectedEvent, setSelectedEvent] = useState<EventItem | null>(null);
  const [settingsOpen, setSettingsOpen] = useState<boolean>(false);

  const loadAllData = useCallback(async (showLoading = false) => {
    try {
      if (showLoading) setLoading(true);
      else setRefreshing(true);

      const bucket = timeRange === "5m" ? "1m" : timeRange === "1h" ? "1m" : "1h";

      const [s, ts, at, ep, ips, ev, cfg] = await Promise.all([
        fetchSummary(timeRange),
        fetchTimeSeries(timeRange, bucket),
        fetchAttackTypes(timeRange),
        fetchTopEndpoints(5, timeRange),
        fetchTopIPs(5, timeRange),
        fetchEvents(100),
        fetchConfig(),
      ]);

      setStats(s);
      setTimeSeries(ts.points);
      setAttackTypes(at.items);
      setTopEndpoints(ep.items);
      setTopIPs(ips.items);
      setEvents(ev.items);
      setConfig(cfg);
    } catch (err) {
      console.error("Error refreshing dashboard data:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
      setNextRefreshIn(10);
    }
  }, [timeRange]);

  // Initial data fetch & auth check
  useEffect(() => {
    loadAllData(true);
    fetchCurrentUser().then((u) => setCurrentUser(u));
  }, [loadAllData]);

  // URL Deep-linking: check for ?event=<id> on initial page load
  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const eventId = params.get("event");
      if (eventId) {
        fetchEventDetail(eventId)
          .then((ev) => setSelectedEvent(ev))
          .catch((err) => console.warn("Could not load deep-linked event:", err));
      }
    }
  }, []);

  // Update URL search params when drawer opens/closes
  const handleSelectEvent = (ev: EventItem) => {
    setSelectedEvent(ev);
    if (typeof window !== "undefined") {
      const url = new URL(window.location.href);
      url.searchParams.set("event", ev.id);
      window.history.replaceState(null, "", url.toString());
    }
  };

  const handleCloseDrawer = () => {
    setSelectedEvent(null);
    if (typeof window !== "undefined") {
      const url = new URL(window.location.href);
      url.searchParams.delete("event");
      window.history.replaceState(null, "", url.toString());
    }
  };

  // Periodic polling every 10s (auto-pauses when drawer or settings modal is active, or if toggled off)
  useEffect(() => {
    if (!autoRefresh || selectedEvent !== null || settingsOpen) {
      return;
    }

    const timer = setInterval(() => {
      setNextRefreshIn((prev) => {
        if (prev <= 1) {
          loadAllData(false);
          return 10;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [autoRefresh, selectedEvent, settingsOpen, loadAllData]);

  const handleFeedbackUpdated = (id: string, feedback: "fp" | "tp" | null) => {
    setEvents((prev) =>
      prev.map((e) => (e.id === id ? { ...e, feedback } : e))
    );
    if (selectedEvent && selectedEvent.id === id) {
      setSelectedEvent((prev) => (prev ? { ...prev, feedback } : null));
    }
  };

  const handleLogout = async () => {
    await logoutAdmin();
    setCurrentUser(null);
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

        {/* Action Controls & Top Navigation */}
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
              <span className="text-slate-400">Thresh:</span>
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

          {/* Global Time Range Selector */}
          <div className="flex items-center bg-slate-900 border border-slate-800 rounded-lg p-0.5 text-xs">
            {["5m", "1h", "24h", "7d"].map((r) => (
              <button
                key={r}
                onClick={() => setTimeRange(r)}
                className={`px-2.5 py-1 rounded font-medium transition-colors ${
                  timeRange === r
                    ? "bg-slate-800 text-white font-bold"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {r}
              </button>
            ))}
          </div>

          {/* Auto-Refresh Toggle Pill */}
          <div className="flex items-center bg-slate-900 border border-slate-800 rounded-lg px-2 py-1 gap-2 text-xs">
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className="flex items-center gap-1 text-slate-300 hover:text-white"
              title={autoRefresh ? "Pause auto-refresh" : "Resume auto-refresh"}
            >
              {autoRefresh ? (
                <>
                  <Pause className="w-3 h-3 text-amber-400" />
                  <span className="text-[11px] text-slate-400 font-mono">
                    {nextRefreshIn}s
                  </span>
                </>
              ) : (
                <>
                  <Play className="w-3 h-3 text-emerald-400" />
                  <span className="text-[11px] text-amber-400 font-semibold">
                    PAUSED
                  </span>
                </>
              )}
            </button>
            <button
              onClick={() => loadAllData(false)}
              className="text-slate-400 hover:text-white"
              title="Refresh Telemetry Now"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${refreshing ? "animate-spin" : ""}`}
              />
            </button>
          </div>

          {/* Auth Status & User Pill */}
          {currentUser ? (
            <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs">
              <User className="w-3.5 h-3.5 text-emerald-400" />
              <span className="font-mono text-slate-200 font-semibold">
                {currentUser.username}
              </span>
              <button
                onClick={handleLogout}
                className="text-slate-500 hover:text-rose-400 p-0.5 rounded transition-colors"
                title="Sign out of SecOps session"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <button
              onClick={() => setLoginModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-800 transition-colors"
            >
              <Lock className="w-3.5 h-3.5 text-sky-400" />
              <span>Login</span>
            </button>
          )}

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

        {/* Source Breakdown: Top Endpoints & Top IPs */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <TopEndpointsTable data={topEndpoints} loading={loading} />
          <TopIPsTable data={topIPs} loading={loading} />
        </div>

        {/* Live Alert & Event Audit Feed */}
        <div>
          <LiveAlertFeed
            initialEvents={events}
            onSelectEvent={handleSelectEvent}
          />
        </div>
      </main>

      {/* Slide-out Request Detail Drawer */}
      <RequestDetailDrawer
        event={selectedEvent}
        onClose={handleCloseDrawer}
        onFeedbackUpdated={handleFeedbackUpdated}
      />

      {/* Settings Modal */}
      <SettingsModal
        config={config}
        isOpen={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        onConfigUpdated={(newCfg) => setConfig(newCfg)}
      />

      {/* SecOps Authentication Modal */}
      <LoginModal
        isOpen={loginModalOpen}
        onClose={() => setLoginModalOpen(false)}
        onLoginSuccess={(user) => setCurrentUser(user)}
      />
    </div>
  );
}
