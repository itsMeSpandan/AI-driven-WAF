"use client";

import React, { useEffect, useState } from "react";
import { X } from "lucide-react";
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
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 overflow-y-auto"
      style={{ backgroundColor: "rgba(17, 17, 17, 0.45)" }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg bg-panel border border-ink text-ink flex flex-col max-h-[90vh] shadow-none"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header Strip */}
        <div className="bg-ink text-white px-5 py-3.5 flex items-center justify-between border-b border-ink on-dark font-mono text-[11px] uppercase tracking-[0.06em]">
          <span className="font-semibold text-white">
            WAF RUNTIME CONFIGURATION &amp; CONTROLS
          </span>
          <button
            onClick={onClose}
            className="text-on-dark-muted hover:text-white transition-colors"
            aria-label="Close settings modal"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-ink bg-panel px-5 pt-3 font-mono text-[12px]">
          <button
            onClick={() => setActiveTab("controls")}
            className={`pb-2 px-3 transition-colors ${
              activeTab === "controls"
                ? "border-b-2 border-ink font-bold text-ink"
                : "text-muted hover:text-ink"
            }`}
          >
            POLICIES &amp; CONTROLS
          </button>
          <button
            onClick={() => setActiveTab("audit")}
            className={`pb-2 px-3 transition-colors ${
              activeTab === "audit"
                ? "border-b-2 border-ink font-bold text-ink"
                : "text-muted hover:text-ink"
            }`}
          >
            AUDIT TRAIL ({auditLogs.length})
          </button>
        </div>

        {/* Body Content */}
        <div className="p-5 overflow-y-auto space-y-4 text-xs font-mono flex-1">
          {errorMessage && (
            <div
              role="alert"
              aria-live="assertive"
              className="border-l-2 border-ink pl-3 py-1 text-ink bg-zebra"
            >
              {errorMessage} (rolled back to previous config)
            </div>
          )}

          {activeTab === "controls" ? (
            <>
              {/* Operating Mode Toggle (Segmented Square Control) */}
              <div>
                <label className="text-muted uppercase text-[11px] block mb-1.5">
                  OPERATING ENFORCEMENT MODE
                </label>
                <div className="grid grid-cols-2 border border-ink">
                  <button
                    type="button"
                    onClick={() => handleModeChange("monitor")}
                    className={`py-2 text-center transition-colors font-mono text-[12px] uppercase ${
                      currentConfig.waf_mode === "monitor"
                        ? "bg-ink text-white font-bold"
                        : "bg-panel text-ink hover:bg-hover"
                    }`}
                  >
                    MONITOR (DRY-RUN)
                  </button>
                  <button
                    type="button"
                    onClick={() => handleModeChange("block")}
                    className={`py-2 text-center transition-colors font-mono text-[12px] uppercase border-l border-ink ${
                      currentConfig.waf_mode === "block"
                        ? "bg-ink text-white font-bold"
                        : "bg-panel text-ink hover:bg-hover"
                    }`}
                  >
                    BLOCK (ENFORCEMENT)
                  </button>
                </div>

                {/* Confirmation Box for Switching to Block */}
                {confirmBlockMode && currentConfig.waf_mode === "block" && (
                  <div className="mt-2 p-3 border border-ink bg-zebra text-ink text-[11px]">
                    <span className="font-bold block uppercase mb-1">
                      CONFIRM BLOCK MODE ACTIVATION
                    </span>
                    Requests exceeding the ML threshold or matching security rules will be actively rejected with HTTP 403 Forbidden.
                  </div>
                )}
              </div>

              {/* Threshold Slider with Trade-off Feedback */}
              <div className="border border-ink p-3 space-y-2.5 bg-panel">
                <div className="flex items-center justify-between">
                  <span className="text-muted uppercase text-[11px]">
                    ML DECISION THRESHOLD
                  </span>
                  <span className="font-bold text-ink text-sm">
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
                  className="w-full accent-ink cursor-pointer"
                />

                {/* Validation Trade-off Indicator */}
                {currentPoint && (
                  <div className="grid grid-cols-3 gap-2 pt-2 border-t border-hair text-center text-[11px]">
                    <div className="border border-hair p-1.5 bg-zebra">
                      <span className="text-muted block text-[10px] uppercase">FPR</span>
                      <span className="text-ink font-semibold">{currentPoint.fpr.toFixed(2)}%</span>
                    </div>
                    <div className="border border-hair p-1.5 bg-zebra">
                      <span className="text-muted block text-[10px] uppercase">RECALL</span>
                      <span className="text-ink font-semibold">{currentPoint.recall.toFixed(1)}%</span>
                    </div>
                    <div className="border border-hair p-1.5 bg-zebra">
                      <span className="text-muted block text-[10px] uppercase">F1 SCORE</span>
                      <span className="text-ink font-semibold">{currentPoint.f1.toFixed(4)}</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Rate Limiting & Burst Anomaly Detection */}
              <div className="border border-ink p-3 space-y-3 bg-panel">
                <div className="flex items-center justify-between">
                  <span className="text-muted uppercase text-[11px]">
                    PER-IP RATE ANOMALY DETECTION
                  </span>
                  <input
                    type="checkbox"
                    checked={currentConfig.rate_limit_enabled ?? true}
                    onChange={(e) =>
                      setCurrentConfig({
                        ...currentConfig,
                        rate_limit_enabled: e.target.checked,
                      })
                    }
                    className="accent-ink w-4 h-4 cursor-pointer"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3 pt-1">
                  <div>
                    <span className="text-muted block text-[10px] uppercase mb-1">
                      WINDOW DURATION (SEC)
                    </span>
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
                      className="w-full bg-panel border border-ink p-1.5 text-ink text-xs focus:outline-none"
                    />
                  </div>
                  <div>
                    <span className="text-muted block text-[10px] uppercase mb-1">
                      BURST LIMIT (REQS)
                    </span>
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
                      className="w-full bg-panel border border-ink p-1.5 text-ink text-xs focus:outline-none"
                    />
                  </div>
                </div>

                <div className="pt-2 border-t border-hair flex items-center justify-between">
                  <span className="text-muted uppercase text-[10px]">
                    ENFORCE HTTP 429 REJECTION (DEFAULT: FLAG ONLY)
                  </span>
                  <input
                    type="checkbox"
                    checked={currentConfig.rate_enforce ?? false}
                    onChange={(e) =>
                      setCurrentConfig({
                        ...currentConfig,
                        rate_enforce: e.target.checked,
                      })
                    }
                    className="accent-ink w-4 h-4 cursor-pointer"
                  />
                </div>
              </div>

              {/* Inspection Cap & Fail Mode */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-muted block text-[10px] uppercase mb-1">
                    INSPECTION CAP
                  </label>
                  <select
                    value={currentConfig.max_body_inspect_bytes}
                    onChange={(e) =>
                      setCurrentConfig({
                        ...currentConfig,
                        max_body_inspect_bytes: parseInt(e.target.value, 10),
                      })
                    }
                    className="w-full bg-panel border border-ink p-2 text-ink text-xs focus:outline-none"
                  >
                    <option value={8192}>8 KB (Fastest)</option>
                    <option value={16384}>16 KB (Default)</option>
                    <option value={32768}>32 KB (Deeper)</option>
                  </select>
                </div>
                <div>
                  <label className="text-muted block text-[10px] uppercase mb-1">
                    FAIL MODE
                  </label>
                  <div className="bg-zebra border border-ink p-2 text-ink text-xs flex items-center justify-between">
                    <span className="uppercase font-bold">{currentConfig.fail_mode}</span>
                    <span className="text-muted text-[10px]">READ-ONLY</span>
                  </div>
                </div>
              </div>
            </>
          ) : (
            /* Audit Trail View */
            <div className="space-y-2">
              <span className="text-[11px] text-muted uppercase block">
                IMMUTABLE AUDIT LOG (RECENT CONFIG CHANGES)
              </span>
              {loadingAudit ? (
                <div className="text-center py-6 text-muted">LOADING AUDIT TRAIL...</div>
              ) : auditLogs.length === 0 ? (
                <div className="text-center py-6 text-muted italic">NO CONFIGURATION CHANGES RECORDED YET.</div>
              ) : (
                <div className="border border-ink divide-y divide-hair">
                  {auditLogs.map((log) => (
                    <div key={log.id} className="p-2.5 bg-panel even:bg-zebra">
                      <div className="flex items-center justify-between text-muted text-[10px]">
                        <span className="font-bold text-ink uppercase">{log.key}</span>
                        <span>{new Date(log.ts).toLocaleString()} &bull; {log.actor}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-1 text-ink text-[11px]">
                        <span className="line-through text-muted truncate max-w-[150px]">{log.old_value || "(none)"}</span>
                        <span>&rarr;</span>
                        <span className="font-bold truncate max-w-[150px]">{log.new_value}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-ink bg-panel flex items-center justify-between font-mono text-[12px]">
          <span className="text-muted text-[10px] uppercase">
            CHANGES APPLY IMMEDIATELY
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-3.5 py-1.5 border border-ink bg-panel text-ink hover:bg-hover transition-colors"
            >
              CANCEL
            </button>
            <button
              disabled={saving}
              onClick={handleSave}
              className="px-4 py-1.5 border border-ink bg-ink text-white hover:bg-[#262626] transition-colors disabled:opacity-50"
            >
              {saving ? "SAVING..." : "SAVE CONFIG"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
