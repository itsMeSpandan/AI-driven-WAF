"use client";

import React, { useState } from "react";
import { X, ChevronDown, ChevronRight } from "lucide-react";
import { EventItem, ExplanationToken, submitFeedback } from "@/lib/api";
import { VerdictText } from "@/components/monolith/ui";

interface RequestDetailDrawerProps {
  event: EventItem | null;
  onClose: () => void;
  onFeedbackUpdated: (id: string, feedback: "fp" | "tp" | null) => void;
}

/**
 * Safely renders canonical text with highlighted token spans.
 * Strictly guarantees ZERO usage of dangerouslySetInnerHTML.
 * All substrings are rendered as standard React text nodes.
 * Monolith spec: Top tokens rendered as <mark> with black bg and white text;
 * lower-weight tokens with a 2px black underline.
 */
function renderHighlightedCanonicalText(
  canonicalText: string,
  tokens: ExplanationToken[]
) {
  if (!canonicalText) {
    return <span className="text-muted italic">No inspected payload text available</span>;
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
    return <span className="text-ink">{canonicalText}</span>;
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
        <span key={`txt-${idx}`} className="text-ink">
          {canonicalText.substring(cursor, s)}
        </span>
      );
    }

    // Monolith Token Highlight:
    // Top tokens (or index 0) black bg with white text; secondary with 2px underline
    if (idx === 0 || span.weight >= 0.5) {
      nodes.push(
        <mark
          key={`tok-${idx}`}
          className="bg-ink text-white font-mono font-medium px-1 py-0.5 cursor-help"
          title={`Attribution weight: +${span.weight.toFixed(4)}`}
        >
          {canonicalText.substring(s, e)}
        </mark>
      );
    } else {
      nodes.push(
        <span
          key={`tok-${idx}`}
          className="border-b-2 border-ink font-mono font-medium text-ink cursor-help"
          title={`Attribution weight: +${span.weight.toFixed(4)}`}
        >
          {canonicalText.substring(s, e)}
        </span>
      );
    }

    cursor = e;
  });

  // Trailing unhighlighted segment
  if (cursor < canonicalText.length) {
    nodes.push(
      <span key="txt-end" className="text-ink">
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
  const [notes, setNotes] = useState("");
  const [showRawAccordion, setShowRawAccordion] = useState(false);

  if (!event) return null;

  const handleFeedback = async (type: "fp" | "tp" | "clear") => {
    try {
      setSubmitting(true);
      await submitFeedback(event.id, type, notes.trim() || undefined);
      onFeedbackUpdated(event.id, type === "clear" ? null : type);
      setNotes("");
    } catch (e) {
      alert("Failed to submit feedback: " + e);
    } finally {
      setSubmitting(false);
    }
  };

  const tokens = event.explanation?.top_tokens || [];
  const features = event.explanation?.features || [];
  const ruleDetail = event.explanation?.matched_rule_detail;

  const canonicalDisplay =
    event.explanation?.canonical_text ||
    `${event.method} ${event.path}${event.query_summary ? "?" + event.query_summary : ""}`;

  const maxWeight = Math.max(...tokens.map((t) => t.weight || 0.1), 0.5);

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end"
      style={{ backgroundColor: "rgba(17, 17, 17, 0.45)" }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-xl bg-panel border-l border-ink text-ink flex flex-col justify-between overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div>
          {/* Header Strip */}
          <div className="bg-ink text-white px-5 py-3.5 flex items-center justify-between border-b border-ink on-dark">
            <div>
              <div className="font-mono text-[11px] uppercase tracking-[0.06em] text-on-dark-muted">
                EVENT ID: {event.id}
              </div>
              <h2 className="text-sm font-semibold text-white mt-0.5">
                REQUEST DIAGNOSTICS & EXPLANATION
              </h2>
            </div>
            <button
              onClick={onClose}
              className="text-on-dark-muted hover:text-white p-1 transition-colors"
              aria-label="Close request drawer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="p-5 space-y-4">
            {/* Quick Metrics (3 tiles) */}
            <div className="grid grid-cols-3 gap-2">
              <div className="border border-ink p-3 bg-panel">
                <span className="font-mono text-[10px] text-muted uppercase tracking-[0.06em] block">
                  VERDICT
                </span>
                <div className="mt-1">
                  <VerdictText verdict={event.verdict} />
                </div>
              </div>
              <div className="border border-ink p-3 bg-panel">
                <span className="font-mono text-[10px] text-muted uppercase tracking-[0.06em] block">
                  ML THREAT SCORE
                </span>
                <div className="font-mono text-[15px] font-bold text-ink mt-0.5">
                  {event.ml_score.toFixed(4)}
                </div>
              </div>
              <div className="border border-ink p-3 bg-panel">
                <span className="font-mono text-[10px] text-muted uppercase tracking-[0.06em] block">
                  LATENCY
                </span>
                <div className="font-mono text-[15px] font-bold text-ink mt-0.5">
                  {event.latency_ms} ms
                </div>
              </div>
            </div>

            {/* Diagnostic Summary */}
            {event.explanation?.summary && (
              <div className="border border-ink p-3 bg-zebra font-mono text-[12px] text-ink">
                <span className="font-semibold block uppercase text-[10px] text-muted tracking-[0.06em] mb-1">
                  DECISION DIAGNOSTIC
                </span>
                <span>{event.explanation.summary}</span>
              </div>
            )}

            {/* Canonical Request (Token Attribution) */}
            <div className="border border-ink bg-panel">
              <div className="px-3.5 py-2 border-b border-ink font-mono text-[11px] uppercase tracking-[0.06em] font-semibold text-ink flex items-center justify-between">
                <span>INSPECTED CANONICAL REQUEST</span>
                <span className="text-muted text-[10px]">ESCAPED RENDER</span>
              </div>
              <div className="p-3 font-mono text-[12px] break-all leading-relaxed whitespace-pre-wrap select-text bg-panel text-ink">
                {renderHighlightedCanonicalText(canonicalDisplay, tokens)}
              </div>
            </div>

            {/* Top Contributing Tokens & Bar Indicators */}
            <div className="border border-ink bg-panel">
              <div className="px-3.5 py-2 border-b border-ink font-mono text-[11px] uppercase tracking-[0.06em] font-semibold text-ink">
                TOP CONTRIBUTING N-GRAM TOKENS
              </div>
              <div className="p-3 space-y-3">
                {tokens.length === 0 ? (
                  <p className="font-mono text-[11px] text-muted">
                    CLEAN REQUEST &mdash; NO ANOMALOUS TOKEN ATTRIBUTIONS.
                  </p>
                ) : (
                  tokens.slice(0, 3).map((t, idx) => {
                    const pct = Math.min(
                      100,
                      Math.round(((t.weight || 0) / maxWeight) * 100)
                    );
                    return (
                      <div key={idx} className="space-y-1">
                        <div className="flex justify-between items-center font-mono text-[11px]">
                          <span className="border border-ink px-1.5 py-0.5 bg-zebra font-semibold text-ink">
                            {t.token || t.text}
                          </span>
                          <span className="text-muted">
                            +{Number(t.weight).toFixed(4)}
                          </span>
                        </div>
                        {/* Flat ink on hair track */}
                        <div className="w-full bg-hair h-2 overflow-hidden border border-hair">
                          <div
                            className="bg-ink h-full"
                            style={{ width: `${Math.max(pct, 5)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Structural & Lexical Indicators */}
            {features.length > 0 && (
              <div className="border border-ink bg-panel">
                <div className="px-3.5 py-2 border-b border-ink font-mono text-[11px] uppercase tracking-[0.06em] font-semibold text-ink">
                  STRUCTURAL &amp; LEXICAL INDICATORS
                </div>
                <div className="p-3 grid grid-cols-2 gap-2">
                  {features.map((f, idx) => (
                    <div
                      key={idx}
                      className="border border-hair p-2 bg-zebra font-mono text-[11px]"
                    >
                      <div className="font-semibold text-ink">{f.note}</div>
                      <div className="text-muted text-[10px] mt-0.5">
                        {f.name}: {f.value}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Rule Signature Match Details */}
            {event.rule_hit && (
              <div className="border border-ink bg-panel">
                <div className="px-3.5 py-2 border-b border-ink font-mono text-[11px] uppercase tracking-[0.06em] font-semibold text-ink flex items-center justify-between">
                  <span>RULE LAYER SIGNATURE HIT</span>
                  <span className="border border-ink px-1 text-[10px]">
                    {ruleDetail?.category || event.attack_type}
                  </span>
                </div>
                <div className="p-3 font-mono text-[12px] space-y-1.5">
                  <div className="font-bold text-ink">{event.rule_hit}</div>
                  {ruleDetail?.description && (
                    <p className="text-muted text-[11px]">{ruleDetail.description}</p>
                  )}
                  {ruleDetail?.pattern && (
                    <div className="text-muted text-[10px] break-all border-t border-hair pt-1">
                      Matched: {ruleDetail.pattern}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Collapsible Accordion: Masked Raw Request Details */}
            <div className="border border-ink bg-panel">
              <button
                onClick={() => setShowRawAccordion(!showRawAccordion)}
                className="w-full px-3.5 py-2.5 flex items-center justify-between font-mono text-[11px] uppercase tracking-[0.06em] font-semibold text-ink hover:bg-hover transition-colors"
              >
                <span>RAW REQUEST METADATA &amp; SANITIZED PAYLOADS</span>
                {showRawAccordion ? (
                  <ChevronDown className="w-4 h-4 text-ink" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-ink" />
                )}
              </button>

              {showRawAccordion && (
                <div className="p-3 border-t border-ink space-y-2.5 font-mono text-[12px]">
                  <div>
                    <span className="text-muted block text-[10px] uppercase">
                      ENDPOINT
                    </span>
                    <div className="text-ink">
                      <span className="font-bold mr-2">{event.method}</span>
                      <span>{event.path}</span>
                    </div>
                  </div>

                  <div>
                    <span className="text-muted block text-[10px] uppercase">
                      TIMESTAMP
                    </span>
                    <div className="text-ink text-[11px]">
                      {event.ts ? (
                        <>
                          <span>
                            {(() => {
                              try {
                                const utcIso =
                                  event.ts.includes("Z") || event.ts.includes("+")
                                    ? event.ts
                                    : event.ts.replace(" ", "T") + "Z";
                                const d = new Date(utcIso);
                                return isNaN(d.getTime()) ? event.ts : d.toLocaleString();
                              } catch {
                                return event.ts;
                              }
                            })()}
                          </span>
                          <span className="text-muted ml-2">({event.ts} UTC)</span>
                        </>
                      ) : (
                        "N/A"
                      )}
                    </div>
                  </div>

                  <div>
                    <span className="text-muted block text-[10px] uppercase">
                      CLIENT IP &amp; AGENT
                    </span>
                    <div className="text-ink text-[11px]">
                      {event.client_ip} &bull; {event.user_agent || "No User-Agent"}
                    </div>
                  </div>

                  {event.query_summary && (
                    <div>
                      <span className="text-muted block text-[10px] uppercase">
                        MASKED QUERY STRING
                      </span>
                      <div className="bg-zebra p-2 border border-hair text-ink break-all">
                        {event.query_summary}
                      </div>
                    </div>
                  )}

                  {event.body_summary && (
                    <div>
                      <span className="text-muted block text-[10px] uppercase">
                        MASKED BODY SUMMARY
                      </span>
                      <div className="bg-zebra p-2 border border-hair text-ink break-all whitespace-pre-wrap">
                        {event.body_summary}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Action / Feedback Footer */}
        <div className="p-5 border-t border-ink bg-panel space-y-3">
          <div>
            <label className="text-[11px] font-mono uppercase text-muted block mb-1">
              ANALYST REVIEW NOTES (OPTIONAL)
            </label>
            <input
              type="text"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="e.g. Legitimate internal API traffic with single quotes"
              maxLength={256}
              className="w-full bg-panel text-ink border border-ink font-mono text-[12px] px-2.5 py-1.5 focus:outline-none"
            />
          </div>

          <div className="flex items-center justify-between gap-3 pt-1">
            <div className="font-mono text-[11px] text-muted uppercase">
              {event.feedback ? (
                <span>
                  LABEL: <strong className="text-ink">{event.feedback}</strong>
                </span>
              ) : (
                <span>CALIBRATION LOOP</span>
              )}
            </div>
            <div className="flex items-center gap-2">
              {event.feedback && (
                <button
                  type="button"
                  disabled={submitting}
                  onClick={() => handleFeedback("clear")}
                  className="font-mono text-[11px] px-2.5 py-1.5 border border-ink bg-panel text-muted hover:text-ink transition-colors disabled:opacity-50"
                >
                  CLEAR
                </button>
              )}
              {/* Secondary button (white/transparent, 1px black border) */}
              <button
                type="button"
                disabled={submitting}
                onClick={() => handleFeedback("fp")}
                className={`font-mono text-[12px] px-3 py-1.5 border border-ink transition-colors disabled:opacity-50 ${
                  event.feedback === "fp"
                    ? "bg-ink text-white"
                    : "bg-panel text-ink hover:bg-hover"
                }`}
              >
                Mark false positive
              </button>
              {/* Primary button (black bg, white text) */}
              <button
                type="button"
                disabled={submitting}
                onClick={() => handleFeedback("tp")}
                className={`font-mono text-[12px] px-3 py-1.5 border border-ink transition-colors disabled:opacity-50 ${
                  event.feedback === "tp"
                    ? "bg-white text-ink"
                    : "bg-ink text-white hover:bg-[#262626]"
                }`}
              >
                Confirm threat
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
