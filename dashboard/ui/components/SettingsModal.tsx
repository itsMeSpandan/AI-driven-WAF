"use client";

import React, { useEffect, useState } from "react";
import {
  X,
  Sliders,
  Shield,
  Save,
  AlertTriangle,
  History,
  Activity,
  CheckCircle,
  HelpCircle,
} from "lucide-react";
import {
  ConfigAuditItem,
  ThresholdSweepPoint,
  WAFConfig,
  fetchConfigAudit,
  fetchThresholdSweep,
  updateConfig,
} from "@/lib/api";

interface SettingsModalProps {
  config: WAFConfig | null;
  isOpen: boolean;
  onClose: () => void;
  onConfigUpdated: (c: WAFConfig) => void;
}

export function SettingsModal({
  config,
  isOpen,
  onClose,
  onConfigUpdated,
}: SettingsModalProps) {
  const [currentConfig, setCurrentConfig] = useState<WAFConfig>(
    config || {
      waf_mode: "block",
      ml_threshold: 0.94,
      max_body_inspect_bytes: 16384,
      fail_mode: "closed",
      rate_limit_enabled: true,
      rate_limit_window_sec: 10,
      rate_limit_burst: 30,
      rate_enforce: false,
    }
  );

  const [initialConfig, setInitialConfig] = useState<WAFConfig | null>(config);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState<"controls" | "audit">("controls");
  const [auditLogs, setAuditLogs] = useState<ConfigAuditItem[]>([]);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [confirmBlockMode, setConfirmBlockMode] = useState(false);
  const [sweepPoints, setSweepPoints] = useState<ThresholdSweepPoint[]>([]);
  const [suggestedThreshold, setSuggestedThreshold] = useState<number>(0.94);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (config) {
      setCurrentConfig(config);
      setInitialConfig(config);
    }
  }, [config]);

  useEffect(() => {
    if (isOpen) {
      setErrorMessage(null);
      // Fetch threshold sweep curve
      fetchThresholdSweep()
        .then((data) => {
          setSweepPoints(data.points || []);
          setSuggestedThreshold(data.suggested_threshold || 0.94);
        })
        .catch(() => {});

      // Fetch audit logs
      setLoadingAudit(true);
      fetchConfigAudit(15)
        .then((data) => setAuditLogs(data.items || []))
        .catch(() => {})
        .finally(() => setLoadingAudit(false));
    }
  }, [isOpen]);

  if (!isOpen) return null;

  // Find nearest threshold point for real-time trade-off feedback
  const currentPoint = sweepPoints.reduce((prev, curr) => {
    return Math.abs(curr.threshold - currentConfig.ml_threshold) <
      Math.abs(prev.threshold - currentConfig.ml_threshold)
      ? curr
      : prev;
  }, sweepPoints[0] || { threshold: 0.94, fpr: 0.0, recall: 99.9, f1: 0.9995 });

  const handleModeChange = (newMode: "monitor" | "block") => {
    if (newMode === "block" && currentConfig.waf_mode !== "block") {
      setConfirmBlockMode(true);
    } else {
      setConfirmBlockMode(false);
    }
    setCurrentConfig((prev) => ({ ...prev, waf_mode: newMode }));
  };

  const handleSave = async () => {
    const backup = { ...currentConfig };
    try {
      setSaving(true);
      setErrorMessage(null);
      // Optimistic update
      onConfigUpdated(currentConfig);
      const updated = await updateConfig(currentConfig);
      onConfigUpdated(updated);
      onClose();
    } catch (e: any) {
      // Rollback on failure
      if (initialConfig) {
        setCurrentConfig(initialConfig);
        onConfigUpdated(initialConfig);
      }
      setErrorMessage(e?.message || "Failed to persist configuration settings");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-sky-400" />
            <h2 className="text-sm font-bold text-white">
              WAF Runtime Configuration & Controls
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-slate-800 bg-slate-950/40 px-4 pt-2">
          <button
            onClick={() => setActiveTab("controls")}
            className={`pb-2.5 px-3 text-xs font-medium border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === "controls"
                ? "border-sky-500 text-sky-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            Security & Model Policies
          </button>
          <button
            onClick={() => setActiveTab("audit")}
            className={`pb-2.5 px-3 text-xs font-medium border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === "audit"
                ? "border-sky-500 text-sky-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <History className="w-3.5 h-3.5" />
            Audit Trail ({auditLogs.length})
          </button>
        </div>

        {/* Body content */}
        <div className="p-5 overflow-y-auto space-y-5 text-xs flex-1">
          {errorMessage && (
            <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{errorMessage} (rolled back to previous config)</span>
            </div>
          )}

          {activeTab === "controls" ? (
            <>
              {/* Operating Mode */}
              <div>
                <label className="text-slate-300 font-medium block mb-2">
                  Operating Enforcement Mode (TRD 2.2)
                </label>
                <div className="grid grid-cols-2 gap-2 bg-slate-950 p-1 rounded-lg border border-slate-800">
                  <button
                    type="button"
                    onClick={() => handleModeChange("monitor")}
                    className={`py-2 rounded-md font-medium text-center transition-all ${
                      currentConfig.waf_mode === "monitor"
                        ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Monitor Mode (Telemetry Only)
                  </button>
                  <button
                    type="button"
                    onClick={() => handleModeChange("block")}
                    className={`py-2 rounded-md font-medium text-center transition-all ${
                      currentConfig.waf_mode === "block"
                        ? "bg-rose-500/20 text-rose-300 border border-rose-500/40 font-semibold"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Block Mode (Active 403)
                  </button>
                </div>

                {confirmBlockMode && currentConfig.waf_mode === "block" && (
                  <div className="mt-2.5 p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 flex items-start gap-2 text-[11px]">
                    <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold block">Confirm Block Mode Activation</span>
                      Requests exceeding the threat threshold or violating rules will be actively rejected with HTTP 403 Forbidden.
                    </div>
                  </div>
                )}
              </div>

              {/* Threshold Slider with Trade-off Feedback */}
              <div className="space-y-2 bg-slate-950 p-3.5 rounded-lg border border-slate-800">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <label className="text-slate-300 font-medium">
                      ML Threat Decision Boundary
                    </label>
                    <span className="text-[10px] bg-sky-950 text-sky-400 border border-sky-800 px-1 rounded">
                      Calibrated: {suggestedThreshold.toFixed(2)}
                    </span>
                  </div>
                  <span className="font-mono text-sky-400 font-bold text-sm">
                    {currentConfig.ml_threshold.toFixed(2)}
                  </span>
                </div>

                <input
                  type="range"
                  min="0.10"
                  max="0.99"
                  step="0.01"
                  value={currentConfig.ml_threshold}
                  onChange={(e) =>
                    setCurrentConfig({
                      ...currentConfig,
                      ml_threshold: parseFloat(e.target.value),
                    })
                  }
                  className="w-full accent-sky-500 cursor-pointer"
                />

                {/* Validation Trade-off Indicator */}
                {currentPoint && (
                  <div className="grid grid-cols-3 gap-2 pt-2 border-t border-slate-800/80 text-center font-mono text-[11px]">
                    <div className="bg-slate-900 p-1.5 rounded">
                      <span className="text-slate-500 block text-[9px] font-sans">Validation FPR</span>
                      <span className={currentPoint.fpr <= 0.5 ? "text-emerald-400" : "text-amber-400"}>
                        {currentPoint.fpr.toFixed(2)}%
                      </span>
                    </div>
                    <div className="bg-slate-900 p-1.5 rounded">
                      <span className="text-slate-500 block text-[9px] font-sans">Attack Recall</span>
                      <span className="text-sky-400 font-semibold">{currentPoint.recall.toFixed(1)}%</span>
                    </div>
                    <div className="bg-slate-900 p-1.5 rounded">
                      <span className="text-slate-500 block text-[9px] font-sans">F1 Score</span>
                      <span className="text-indigo-300">{currentPoint.f1.toFixed(4)}</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Rate Limiting & Burst Anomaly Detection */}
              <div className="space-y-3 bg-slate-950 p-3.5 rounded-lg border border-slate-800">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <Activity className="w-3.5 h-3.5 text-amber-400" />
                    <span className="text-slate-300 font-medium">Per-IP Rate Anomaly Detection</span>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={currentConfig.rate_limit_enabled ?? true}
                      onChange={(e) =>
                        setCurrentConfig({
                          ...currentConfig,
                          rate_limit_enabled: e.target.checked,
                        })
                      }
                      className="sr-only peer"
                    />
                    <div className="w-8 h-4 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-sky-500"></div>
                  </label>
                </div>

                <div className="grid grid-cols-2 gap-3 pt-1">
                  <div>
                    <span className="text-slate-400 block text-[11px] mb-1">Window Duration</span>
                    <div className="flex items-center gap-2">
                      <input
                        type="number"
                        min="1"
                        max="300"
                        value={currentConfig.rate_limit_window_sec ?? 10}
                        onChange={(e) =>
                          setCurrentConfig({
                            ...currentConfig,
                            rate_limit_window_sec: parseInt(e.target.value) || 10,
                          })
                        }
                        className="w-full bg-slate-900 border border-slate-800 rounded p-1.5 text-slate-200 font-mono text-xs"
                      />
                      <span className="text-slate-500 text-[10px]">sec</span>
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px] mb-1">Burst Limit</span>
                    <div className="flex items-center gap-2">
                      <input
                        type="number"
                        min="1"
                        max="1000"
                        value={currentConfig.rate_limit_burst ?? 30}
                        onChange={(e) =>
                          setCurrentConfig({
                            ...currentConfig,
                            rate_limit_burst: parseInt(e.target.value) || 30,
                          })
                        }
                        className="w-full bg-slate-900 border border-slate-800 rounded p-1.5 text-slate-200 font-mono text-xs"
                      />
                      <span className="text-slate-500 text-[10px]">reqs</span>
                    </div>
                  </div>
                </div>

                {/* Rate Enforcement Mode Toggle */}
                <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
                  <div>
                    <span className="text-slate-300 font-medium block text-[11px]">
                      Enforce HTTP 429 Rejection
                    </span>
                    <span className="text-slate-500 text-[10px]">
                      Default: Flag-only anomaly tagging
                    </span>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={currentConfig.rate_enforce ?? false}
                      onChange={(e) =>
                        setCurrentConfig({
                          ...currentConfig,
                          rate_enforce: e.target.checked,
                        })
                      }
                      className="sr-only peer"
                    />
                    <div className="w-8 h-4 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-rose-500"></div>
                  </label>
                </div>
              </div>

              {/* Inspection Payload Cap & Internal Error Behavior */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Inspection Cap</label>
                  <select
                    value={currentConfig.max_body_inspect_bytes}
                    onChange={(e) =>
                      setCurrentConfig({
                        ...currentConfig,
                        max_body_inspect_bytes: parseInt(e.target.value, 10),
                      })
                    }
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-sky-500 text-xs"
                  >
                    <option value={8192}>8 KB (Fastest)</option>
                    <option value={16384}>16 KB (Default)</option>
                    <option value={32768}>32 KB (Deeper)</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Fail Mode</label>
                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-300 text-xs flex items-center justify-between font-mono">
                    <span className="uppercase">{currentConfig.fail_mode}</span>
                    <span className="text-[10px] text-slate-500 font-sans">Read-only</span>
                  </div>
                </div>
              </div>
            </>
          ) : (
            /* Audit Trail View */
            <div className="space-y-3">
              <span className="text-xs text-slate-400 font-medium block">
                Immutable Configuration Audit Log (TRD G1 & PRD 1.6)
              </span>
              {loadingAudit ? (
                <div className="text-center py-6 text-slate-500">Loading audit history...</div>
              ) : auditLogs.length === 0 ? (
                <div className="text-center py-6 text-slate-500 italic">No configuration modifications logged yet.</div>
              ) : (
                <div className="space-y-2 font-mono text-[11px]">
                  {auditLogs.map((log) => (
                    <div
                      key={log.id}
                      className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 flex flex-col gap-1"
                    >
                      <div className="flex items-center justify-between text-slate-400">
                        <span className="text-sky-400 font-semibold">{log.key}</span>
                        <span className="text-[10px] text-slate-500">
                          {new Date(log.ts).toLocaleString()} &bull; {log.actor}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-slate-300">
                        <span className="text-rose-400 line-through truncate max-w-[150px]">
                          {log.old_value || "(none)"}
                        </span>
                        <span className="text-slate-500">&rarr;</span>
                        <span className="text-emerald-400 font-bold truncate max-w-[150px]">
                          {log.new_value}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between gap-3">
          <span className="text-[11px] text-slate-500">
            Changes apply to WAF gateway without restart
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg border border-slate-800 text-slate-400 text-xs hover:bg-slate-800 hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              disabled={saving}
              onClick={handleSave}
              className="px-4 py-1.5 rounded-lg bg-sky-500 text-white text-xs font-semibold hover:bg-sky-400 flex items-center gap-1.5 shadow-md shadow-sky-500/20 disabled:opacity-50 transition-colors"
            >
              <Save className="w-3.5 h-3.5" />
              {saving ? "Applying..." : "Save Settings"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
