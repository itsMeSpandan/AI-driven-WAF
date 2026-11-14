"use client";

import React, { useState } from "react";
import { X, ShieldAlert, CheckCircle, ThumbsDown, ThumbsUp, HelpCircle } from "lucide-react";
import { EventItem, submitFeedback } from "@/lib/api";

interface RequestDetailDrawerProps {
  event: EventItem | null;
  onClose: () => void;
  onFeedbackUpdated: (id: string, feedback: "fp" | "tp") => void;
}

export function RequestDetailDrawer({
  event,
  onClose,
  onFeedbackUpdated,
}: RequestDetailDrawerProps) {
  const [submitting, setSubmitting] = useState(false);

  if (!event) return null;

  const handleFeedback = async (type: "fp" | "tp") => {
    try {
      setSubmitting(true);
      await submitFeedback(event.id, type);
      onFeedbackUpdated(event.id, type);
    } catch (e) {
      alert("Failed to submit feedback: " + e);
    } finally {
      setSubmitting(false);
    }
  };

  const tokens = event.explanation?.top_tokens || [];

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-opacity">
      <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
        <div>
          {/* Header */}
          <div className="flex items-start justify-between pb-4 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-sky-400">
                  {event.id}
                </span>
                {event.feedback && (
                  <span
                    className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border ${
                      event.feedback === "fp"
                        ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                        : "bg-rose-500/10 text-rose-400 border-rose-500/30"
                    }`}
                  >
                    Feedback: {event.feedback}
                  </span>
                )}
              </div>
              <h2 className="text-lg font-bold text-white mt-1">
                Request Inspection
              </h2>
            </div>
            <button
              onClick={onClose}
              className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Quick Metrics */}
          <div className="grid grid-cols-3 gap-3 my-4">
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400">Verdict</span>
              <div className="text-sm font-bold uppercase mt-0.5 text-rose-400">
                {event.verdict}
              </div>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400">ML Threat Score</span>
              <div className="text-sm font-bold mt-0.5 text-sky-400">
                {event.ml_score.toFixed(3)}
              </div>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400">Latency</span>
              <div className="text-sm font-bold mt-0.5 text-indigo-400">
                {event.latency_ms} ms
              </div>
            </div>
          </div>

          {/* Diagnostic Details */}
          <div className="space-y-4 text-xs font-mono">
            <div>
              <span className="text-slate-400 block font-sans font-medium mb-1">
                Target Endpoint
              </span>
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-slate-200 break-all">
                <span className="text-sky-400 font-bold mr-2">{event.method}</span>
                {/* Plain text escaping */}
                <span>{event.path}</span>
              </div>
            </div>

            {event.query_summary && (
              <div>
                <span className="text-slate-400 block font-sans font-medium mb-1">
                  Query String Parameters
                </span>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-slate-300 break-all">
                  {event.query_summary}
                </div>
              </div>
            )}

            {event.body_summary && (
              <div>
                <span className="text-slate-400 block font-sans font-medium mb-1">
                  Request Body Payload
                </span>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-slate-300 break-all whitespace-pre-wrap">
                  {event.body_summary}
                </div>
              </div>
            )}

            <div className="grid grid-cols-2 gap-3 font-sans">
              <div>
                <span className="text-slate-400 block font-medium mb-1">
                  Client IP
                </span>
                <div className="bg-slate-950 p-2 rounded-lg border border-slate-800 font-mono text-slate-300">
                  {event.client_ip}
                </div>
              </div>
              <div>
                <span className="text-slate-400 block font-medium mb-1">
                  Rule Signature
                </span>
                <div className="bg-slate-950 p-2 rounded-lg border border-slate-800 font-mono text-amber-400 truncate">
                  {event.rule_hit || "No rule hit"}
                </div>
              </div>
            </div>

            {/* Explainability Tokens */}
            <div className="font-sans">
              <span className="text-slate-400 block font-medium mb-1">
                Explainability & Trigger Tokens (TRD 2.4)
              </span>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                {tokens.length === 0 ? (
                  <p className="text-slate-500 italic text-[11px]">
                    No anomalous tokens isolated (Stage 1 stub / benign request)
                  </p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {tokens.map((t, i) => (
                      <span
                        key={i}
                        className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 font-mono text-xs"
                      >
                        <span>{t.token}</span>
                        <span className="text-[10px] bg-rose-500/20 px-1 rounded text-rose-200">
                          {t.weight}
                        </span>
                      </span>
                    ))}
                  </div>
                )}
                {event.explanation?.summary && (
                  <p className="mt-2 text-[11px] text-slate-400">
                    {event.explanation.summary}
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Action / Feedback Footer */}
        <div className="pt-4 border-t border-slate-800 mt-6 flex items-center justify-between gap-3">
          <div className="text-[11px] text-slate-500">
            Helps calibrate detection boundaries
          </div>
          <div className="flex items-center gap-2">
            <button
              disabled={submitting}
              onClick={() => handleFeedback("fp")}
              className="px-3 py-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 text-amber-300 text-xs font-medium hover:bg-amber-500/20 flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <ThumbsDown className="w-3.5 h-3.5" />
              Mark False Positive
            </button>
            <button
              disabled={submitting}
              onClick={() => handleFeedback("tp")}
              className="px-3 py-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 text-rose-300 text-xs font-medium hover:bg-rose-500/20 flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <ThumbsUp className="w-3.5 h-3.5" />
              Confirm Threat
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
