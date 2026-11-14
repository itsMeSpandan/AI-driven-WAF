"use client";

import React, { useState } from "react";
import { X, Sliders, Shield, Save } from "lucide-react";
import { WAFConfig, updateConfig } from "@/lib/api";

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
      ml_threshold: 0.75,
      max_body_inspect_bytes: 16384,
      fail_mode: "closed",
    }
  );
  const [saving, setSaving] = useState(false);

  if (!isOpen) return null;

  const handleSave = async () => {
    try {
      setSaving(true);
      const updated = await updateConfig(currentConfig);
      onConfigUpdated(updated);
      onClose();
    } catch (e) {
      alert("Failed to update WAF settings: " + e);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-sky-400" />
            <h2 className="text-sm font-bold text-white">
              WAF Runtime Configuration
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="mt-4 space-y-5 text-xs">
          {/* Mode Toggle */}
          <div>
            <label className="text-slate-300 font-medium block mb-2">
              Operating Mode (TRD 2.2)
            </label>
            <div className="grid grid-cols-2 gap-2 bg-slate-950 p-1 rounded-lg border border-slate-800">
              <button
                type="button"
                onClick={() =>
                  setCurrentConfig({ ...currentConfig, waf_mode: "monitor" })
                }
                className={`py-2 rounded-md font-medium text-center transition-all ${
                  currentConfig.waf_mode === "monitor"
                    ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Monitor Mode (Log Only)
              </button>
              <button
                type="button"
                onClick={() =>
                  setCurrentConfig({ ...currentConfig, waf_mode: "block" })
                }
                className={`py-2 rounded-md font-medium text-center transition-all ${
                  currentConfig.waf_mode === "block"
                    ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Block Mode (Active 403)
              </button>
            </div>
            <p className="mt-1 text-[11px] text-slate-500">
              {currentConfig.waf_mode === "block"
                ? "Malicious requests are immediately rejected with HTTP 403."
                : "Requests are inspected and flagged but allowed to proceed to upstream."}
            </p>
          </div>

          {/* Threshold Slider */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-slate-300 font-medium">
                ML Anomaly Decision Threshold
              </label>
              <span className="font-mono text-sky-400 font-bold">
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
            <div className="flex justify-between text-[10px] text-slate-500 mt-1">
              <span>0.10 (High sensitivity)</span>
              <span>0.99 (High precision)</span>
            </div>
          </div>

          {/* Max Body Inspect Cap */}
          <div>
            <label className="text-slate-300 font-medium block mb-1.5">
              Body Inspection Cap (Bytes)
            </label>
            <select
              value={currentConfig.max_body_inspect_bytes}
              onChange={(e) =>
                setCurrentConfig({
                  ...currentConfig,
                  max_body_inspect_bytes: parseInt(e.target.value, 10),
                })
              }
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-sky-500"
            >
              <option value={8192}>8 KB (Fastest)</option>
              <option value={16384}>16 KB (Default Recommended)</option>
              <option value={32768}>32 KB (Deeper payload scan)</option>
            </select>
          </div>

          {/* Fail Mode */}
          <div>
            <label className="text-slate-300 font-medium block mb-1.5">
              Internal Error Fallback (FAIL_MODE)
            </label>
            <div className="grid grid-cols-2 gap-2 bg-slate-950 p-1 rounded-lg border border-slate-800">
              <button
                type="button"
                onClick={() =>
                  setCurrentConfig({ ...currentConfig, fail_mode: "closed" })
                }
                className={`py-1.5 rounded-md font-medium text-center ${
                  currentConfig.fail_mode === "closed"
                    ? "bg-slate-800 text-white"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Closed (Secure Default)
              </button>
              <button
                type="button"
                onClick={() =>
                  setCurrentConfig({ ...currentConfig, fail_mode: "open" })
                }
                className={`py-1.5 rounded-md font-medium text-center ${
                  currentConfig.fail_mode === "open"
                    ? "bg-slate-800 text-white"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Open (High Availability)
              </button>
            </div>
          </div>
        </div>

        <div className="pt-4 border-t border-slate-800 mt-6 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg border border-slate-800 text-slate-400 text-xs hover:bg-slate-800 hover:text-white"
          >
            Cancel
          </button>
          <button
            disabled={saving}
            onClick={handleSave}
            className="px-4 py-1.5 rounded-lg bg-sky-500 text-white text-xs font-semibold hover:bg-sky-400 flex items-center gap-1.5 shadow-md shadow-sky-500/20 disabled:opacity-50"
          >
            <Save className="w-3.5 h-3.5" />
            {saving ? "Saving..." : "Apply Settings"}
          </button>
        </div>
      </div>
    </div>
  );
}
