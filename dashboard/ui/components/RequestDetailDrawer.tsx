"use client";

import React, { useState } from "react";
import {
  X,
  ShieldAlert,
  CheckCircle,
  ThumbsDown,
  ThumbsUp,
  ChevronDown,
  ChevronRight,
  Flame,
  Activity,
  Code2,
} from "lucide-react";
import { EventItem, ExplanationToken, submitFeedback } from "@/lib/api";

interface RequestDetailDrawerProps {
  event: EventItem | null;
  onClose: () => void;
  onFeedbackUpdated: (id: string, feedback: "fp" | "tp") => void;
}

/**
 * Safely renders canonical text with highlighted token spans.
 * Strictly guarantees ZERO usage of dangerouslySetInnerHTML.
 * All substrings are rendered as standard React text nodes.
 */
function renderHighlightedCanonicalText(
  canonicalText: string,
  tokens: ExplanationToken[]
) {
  if (!canonicalText) {
    return <span className="text-slate-500 italic">No inspected payload text available</span>;
  }

  // Filter valid spans that have character start and end bounds
  const validSpans = tokens
    .filter(
      (t) =>
        t.start !== undefined &&
        t.end !== undefined &&
        t.start >= 0 &&
        t.end <= canonicalText.length &&
        t.start < t.end
    )
    .sort((a, b) => (a.start ?? 0) - (b.start ?? 0));

  if (validSpans.length === 0) {
    return <span className="text-slate-300">{canonicalText}</span>;
  }

  const nodes: React.ReactNode[] = [];
  let cursor = 0;

  validSpans.forEach((span, idx) => {
    const s = Math.max(span.start ?? 0, cursor);
    const e = span.end ?? 0;
    if (s >= e) return;

    // Preceding unhighlighted segment
    if (s > cursor) {
      nodes.push(
        <span key={`txt-${idx}`} className="text-slate-300">
          {canonicalText.substring(cursor, s)}
        </span>
      );
    }

    // Highlighted malicious token span
    nodes.push(
      <mark
        key={`tok-${idx}`}
        className="bg-rose-500/30 text-rose-200 border-b-2 border-rose-400 font-bold px-1 rounded-sm cursor-help hover:bg-rose-500/50 transition-colors"
        title={`Attribution weight: +${span.weight.toFixed(4)}`}
      >
        {canonicalText.substring(s, e)}
      </mark>
    );

    cursor = e;
  });

  // Trailing unhighlighted segment
  if (cursor < canonicalText.length) {
    nodes.push(
      <span key="txt-end" className="text-slate-300">
        {canonicalText.substring(cursor)}
      </span>
    );
  }

  return <>{nodes}</>;
}

export function RequestDetailDrawer({
  event,
  onClose,
  onFeedbackUpdated,
}: RequestDetailDrawerProps) {
  const [submitting, setSubmitting] = useState(false);
  const [showRawAccordion, setShowRawAccordion] = useState(false);

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
  const features = event.explanation?.features || [];
  const ruleDetail = event.explanation?.matched_rule_detail;

  // Use the canonical text from the explanation or fallback to reconstructed method + path + query
  const canonicalDisplay =
    event.explanation?.canonical_text ||
    `${event.method} ${event.path}${event.query_summary ? "?" + event.query_summary : ""}`;

  // Find max weight for proportional bar indicators
  const maxWeight = Math.max(...tokens.map((t) => t.weight || 0.1), 0.5);

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-opacity">
      <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
        <div className="space-y-5">
          {/* Header */}
          <div className="flex items-start justify-between pb-4 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-sky-400">{event.id}</span>
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
                Inspection & Diagnostic Explanation
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
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400">Verdict</span>
              <div
                className={`text-sm font-bold uppercase mt-0.5 ${
                  event.verdict === "block"
                    ? "text-rose-400"
                    : event.verdict === "flag"
                    ? "text-amber-400"
                    : "text-emerald-400"
                }`}
              >
                {event.verdict}
              </div>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400">ML Threat Score</span>
              <div className="text-sm font-bold mt-0.5 text-sky-400">
                {event.ml_score.toFixed(4)}
              </div>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400">Latency</span>
              <div className="text-sm font-bold mt-0.5 text-indigo-400">
                {event.latency_ms} ms
              </div>
            </div>
          </div>

          {/* Diagnostic Summary Banner */}
          {event.explanation?.summary && (
            <div
              className={`p-3 rounded-lg border text-xs flex items-start gap-2.5 ${
                event.verdict === "block"
                  ? "bg-rose-950/30 border-rose-900/60 text-rose-300"
                  : event.verdict === "flag"
                  ? "bg-amber-950/30 border-amber-900/60 text-amber-300"
                  : "bg-emerald-950/30 border-emerald-900/60 text-emerald-300"
              }`}
            >
              <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold block">Decision Diagnostic</span>
                <span>{event.explanation.summary}</span>
              </div>
            </div>
          )}

          {/* Canonical Payload with Token Highlighting (Stage 3 TRD 2.4) */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                <Code2 className="w-3.5 h-3.5 text-sky-400" />
                Inspected Canonical Request (Token Highlights)
              </span>
              <span className="text-[10px] text-slate-500">Escaped string render</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs break-all leading-relaxed whitespace-pre-wrap select-text">
              {renderHighlightedCanonicalText(canonicalDisplay, tokens)}
            </div>
          </div>

          {/* Top Contributing Tokens & Bar Indicators */}
          <div className="space-y-2.5">
            <span className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
              <Flame className="w-3.5 h-3.5 text-rose-400" />
              Top Contributing N-Gram Tokens
            </span>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-3">
              {tokens.length === 0 ? (
                <p className="text-slate-500 italic text-xs">
                  Clean request — no anomalous token attributions.
                </p>
              ) : (
                tokens.slice(0, 3).map((t, idx) => {
                  const pct = Math.min(
                    100,
                    Math.round(((t.weight || 0) / maxWeight) * 100)
                  );
                  return (
                    <div key={idx} className="space-y-1">
                      <div className="flex justify-between items-center text-xs">
                        <span className="font-mono text-rose-300 bg-rose-950/50 border border-rose-900/60 px-2 py-0.5 rounded text-[11px]">
                          {t.token || t.text}
                        </span>
                        <span className="font-mono text-slate-400 text-[11px]">
                          +{Number(t.weight).toFixed(4)}
                        </span>
                      </div>
                      <div className="w-full bg-slate-800/80 rounded-full h-1.5 overflow-hidden">
                        <div
                          className="bg-gradient-to-r from-rose-500 to-amber-500 h-1.5 rounded-full transition-all"
                          style={{ width: `${Math.max(pct, 8)}%` }}
                        />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Notable Lexical & Statistical Features */}
          {features.length > 0 && (
            <div className="space-y-2">
              <span className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-amber-400" />
                Structural & Lexical Indicators
              </span>
              <div className="grid grid-cols-2 gap-2">
                {features.map((f, idx) => (
                  <div
                    key={idx}
                    className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-xs"
                  >
                    <div className="text-amber-300 font-medium">{f.note}</div>
                    <div className="text-slate-500 font-mono text-[10px] mt-0.5">
                      {f.name}: {f.value}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Rule Signature Match Details */}
          {event.rule_hit && (
            <div className="space-y-1.5">
              <span className="text-xs font-medium text-slate-300">
                Rule Layer Signature Hit
              </span>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs space-y-1">
                <div className="flex justify-between">
                  <span className="text-amber-400 font-mono font-bold">
                    {event.rule_hit}
                  </span>
                  <span className="text-slate-400 uppercase text-[10px] bg-slate-800 px-1.5 py-0.5 rounded">
                    {ruleDetail?.category || event.attack_type}
                  </span>
                </div>
                {ruleDetail?.description && (
                  <p className="text-slate-400 text-[11px]">{ruleDetail.description}</p>
                )}
                {ruleDetail?.pattern && (
                  <div className="text-slate-500 font-mono text-[10px] truncate">
                    Matched: {ruleDetail.pattern}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Collapsible Accordion: Masked Raw Request Details */}
          <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-950/60">
            <button
              onClick={() => setShowRawAccordion(!showRawAccordion)}
              className="w-full p-3 flex items-center justify-between text-xs text-slate-300 hover:bg-slate-800/40 transition-colors"
            >
              <span className="font-medium">Raw Request Metadata & Sanitized Payloads</span>
              {showRawAccordion ? (
                <ChevronDown className="w-4 h-4 text-slate-400" />
              ) : (
                <ChevronRight className="w-4 h-4 text-slate-400" />
              )}
            </button>

            {showRawAccordion && (
              <div className="p-3 border-t border-slate-800/80 space-y-2 text-xs font-mono">
                <div>
                  <span className="text-slate-500 block text-[10px] font-sans">
                    Endpoint
                  </span>
                  <div className="text-slate-300">
                    <span className="text-sky-400 font-bold mr-2">{event.method}</span>
                    <span>{event.path}</span>
                  </div>
                </div>

                <div>
                  <span className="text-slate-500 block text-[10px] font-sans">
                    Client IP & Agent
                  </span>
                  <div className="text-slate-400 text-[11px]">
                    {event.client_ip} &bull; {event.user_agent || "No User-Agent"}
                  </div>
                </div>

                {event.query_summary && (
                  <div>
                    <span className="text-slate-500 block text-[10px] font-sans">
                      Masked Query String
                    </span>
                    <div className="bg-slate-900 p-2 rounded text-slate-300 break-all">
                      {event.query_summary}
                    </div>
                  </div>
                )}

                {event.body_summary && (
                  <div>
                    <span className="text-slate-500 block text-[10px] font-sans">
                      Masked Body Summary
                    </span>
                    <div className="bg-slate-900 p-2 rounded text-slate-300 break-all whitespace-pre-wrap">
                      {event.body_summary}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Action / Feedback Footer */}
        <div className="pt-4 border-t border-slate-800 mt-6 flex items-center justify-between gap-3">
          <div className="text-[11px] text-slate-500">
            Analyst feedback loop for model calibration
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
