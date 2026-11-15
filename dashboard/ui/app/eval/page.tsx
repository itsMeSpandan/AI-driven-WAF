"use client";

import React from "react";
import Link from "next/link";

export default function EvalPage() {
  return (
    <div className="min-h-screen bg-bg text-ink">
      {/* Top Header Strip */}
      <header className="w-full bg-ink text-white px-6 sm:px-10 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between border-b border-ink gap-4 on-dark">
        <div className="flex items-center gap-4">
          <Link
            href="/"
            className="font-mono text-[12px] text-on-dark-muted hover:text-white transition-colors"
          >
            &larr; WAF / CONSOLE
          </Link>
          <span className="text-on-dark-muted">|</span>
          <span className="font-mono font-medium text-[13px] tracking-[0.06em] text-white uppercase">
            MODEL DIAGNOSTICS &amp; ROBUSTNESS EVALUATION
          </span>
        </div>
        <div className="font-mono text-[11px] text-white border border-white px-2 py-0.5 uppercase">
          STAGE 3 ROBUST DETECTOR ACTIVE
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-[1280px] mx-auto px-6 sm:px-10 py-7 space-y-4 font-mono text-[12px]">
        {/* Row 1: Model Metadata + Success Metric Tiles */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Active Model Panel */}
          <div className="bg-panel border border-ink">
            <div className="px-4 py-2.5 border-b border-ink font-mono text-[11px] uppercase tracking-[0.06em] font-semibold text-ink">
              ACTIVE ML MODEL METADATA
            </div>
            <div className="p-4 space-y-2 text-[12px]">
              <div className="flex justify-between py-1 border-b border-hair">
                <span className="text-muted">MODEL NAME</span>
                <span className="text-ink font-semibold">LogisticRegression</span>
              </div>
              <div className="flex justify-between py-1 border-b border-hair">
                <span className="text-muted">MODEL VERSION</span>
                <span className="text-ink">Stage3_Robust_20261114</span>
              </div>
              <div className="flex justify-between py-1 border-b border-hair">
                <span className="text-muted">THRESHOLD &tau;</span>
                <span className="text-ink font-bold">0.940</span>
              </div>
              <div className="flex justify-between py-1 border-b border-hair">
                <span className="text-muted">AUGMENTATION</span>
                <span className="text-ink">Family A (16,824 samples)</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-muted">FEATURE DIMS</span>
                <span className="text-ink">50,000 TF-IDF + 8 Lexical</span>
              </div>
            </div>
          </div>

          {/* PRD Target Metrics (4 tiles) */}
          <div className="bg-panel border border-ink col-span-1 md:col-span-2">
            <div className="px-4 py-2.5 border-b border-ink font-mono text-[11px] uppercase tracking-[0.06em] font-semibold text-ink">
              PRD SUCCESS METRICS &amp; EVALUATION TARGETS
            </div>
            <div className="p-4 grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
              <div className="border border-ink p-3 bg-panel">
                <span className="text-[10px] text-muted uppercase block">DETECTION F1</span>
                <div className="text-2xl font-bold text-ink my-1">1.0000</div>
                <span className="text-[10px] text-muted">TARGET &ge; 0.95</span>
              </div>
              <div className="border border-ink p-3 bg-panel">
                <span className="text-[10px] text-muted uppercase block">EVASION RECALL</span>
                <div className="text-2xl font-bold text-ink my-1">83.31%</div>
                <span className="text-[10px] text-muted">+5.71% VS PLAIN</span>
              </div>
              <div className="border border-ink p-3 bg-panel">
                <span className="text-[10px] text-muted uppercase block">BENIGN FPR</span>
                <div className="text-2xl font-bold text-ink my-1">0.13%</div>
                <span className="text-[10px] text-muted">HARD CAP &lt; 2.50%</span>
              </div>
              <div className="border border-ink p-3 bg-panel">
                <span className="text-[10px] text-muted uppercase block">p95 LATENCY</span>
                <div className="text-2xl font-bold text-ink my-1">5.54 ms</div>
                <span className="text-[10px] text-muted">BUDGET &le; 10.0 ms</span>
              </div>
            </div>
          </div>
        </div>

        {/* Robustness Benchmark Matrix Table */}
        <div className="bg-panel border border-ink">
          <div className="px-4 py-2.5 border-b border-ink font-mono text-[11px] uppercase tracking-[0.06em] font-semibold text-ink flex items-center justify-between">
            <span>STAGE 3 ROBUSTNESS MATRIX: PLAIN BASELINE VS AUGMENTED MODEL</span>
            <span className="text-muted">eval/reports/robustness_report.md</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-[12px] border-collapse">
              <thead>
                <tr className="bg-ink text-white text-[11px] uppercase tracking-[0.06em]">
                  <th className="px-3.5 py-2 font-medium">Evaluation Dimension</th>
                  <th className="px-3.5 py-2 font-medium text-right">Plain Model (Stage 2)</th>
                  <th className="px-3.5 py-2 font-medium text-right">Augmented Model (Stage 3)</th>
                  <th className="px-3.5 py-2 font-medium text-right">Observed Delta</th>
                  <th className="px-3.5 py-2 font-medium text-right">Requirement Target</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hair">
                <tr className="even:bg-panel odd:bg-zebra hover:bg-hover">
                  <td className="px-3.5 py-2 text-ink">Calibrated Decision Threshold</td>
                  <td className="px-3.5 py-2 text-right text-muted">0.900</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">0.940</td>
                  <td className="px-3.5 py-2 text-right text-muted">+0.040</td>
                  <td className="px-3.5 py-2 text-right text-muted">Val FPR = 0.00%</td>
                </tr>
                <tr className="even:bg-panel odd:bg-zebra hover:bg-hover">
                  <td className="px-3.5 py-2 text-ink">In-Distribution Test F1 Score</td>
                  <td className="px-3.5 py-2 text-right text-muted">1.0000</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">1.0000</td>
                  <td className="px-3.5 py-2 text-right text-muted">0.00%</td>
                  <td className="px-3.5 py-2 text-right text-muted">&ge; 0.95</td>
                </tr>
                <tr className="even:bg-panel odd:bg-zebra hover:bg-hover">
                  <td className="px-3.5 py-2 text-ink">Benign Test False Positive Rate (FPR)</td>
                  <td className="px-3.5 py-2 text-right text-muted">0.00%</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">0.00%</td>
                  <td className="px-3.5 py-2 text-right text-muted">0.00%</td>
                  <td className="px-3.5 py-2 text-right text-muted">&le; 1.0%</td>
                </tr>
                <tr className="even:bg-panel odd:bg-zebra hover:bg-hover">
                  <td className="px-3.5 py-2 text-ink">Obfuscated Benign Test FPR (1,507 samples)</td>
                  <td className="px-3.5 py-2 text-right text-muted">0.07%</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">0.13%</td>
                  <td className="px-3.5 py-2 text-right text-muted">+0.06%</td>
                  <td className="px-3.5 py-2 text-right text-muted">&le; 2.50% hard cap</td>
                </tr>
                <tr className="even:bg-panel odd:bg-zebra hover:bg-hover">
                  <td className="px-3.5 py-2 text-ink">Evasion Recall: Family A (Seen Mutations)</td>
                  <td className="px-3.5 py-2 text-right text-muted">100.00%</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">100.00%</td>
                  <td className="px-3.5 py-2 text-right text-muted">0.00%</td>
                  <td className="px-3.5 py-2 text-right text-muted">&ge; 90.0%</td>
                </tr>
                <tr className="even:bg-panel odd:bg-zebra hover:bg-hover border-l-2 border-ink">
                  <td className="px-3.5 py-2 text-ink font-bold">Evasion Recall: Family B (Unseen Mutations)</td>
                  <td className="px-3.5 py-2 text-right text-muted">77.60%</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">83.31%</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">+5.71%</td>
                  <td className="px-3.5 py-2 text-right text-muted">PRD Goal G5</td>
                </tr>
                <tr className="even:bg-panel odd:bg-zebra hover:bg-hover">
                  <td className="px-3.5 py-2 text-ink">Cross-Source Recall (CSIC 2010 anomalous)</td>
                  <td className="px-3.5 py-2 text-right text-muted">5.82%</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">6.01%</td>
                  <td className="px-3.5 py-2 text-right text-muted">+0.19%</td>
                  <td className="px-3.5 py-2 text-right text-muted">PRD Goal G6</td>
                </tr>
                <tr className="even:bg-panel odd:bg-zebra hover:bg-hover">
                  <td className="px-3.5 py-2 text-ink">Single-Request Latency p95</td>
                  <td className="px-3.5 py-2 text-right text-muted">5.11 ms</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">5.54 ms</td>
                  <td className="px-3.5 py-2 text-right text-muted">+0.43 ms</td>
                  <td className="px-3.5 py-2 text-right text-muted">&le; 10.0 ms budget</td>
                </tr>
                <tr className="even:bg-panel odd:bg-zebra hover:bg-hover">
                  <td className="px-3.5 py-2 text-ink">Serialized Artefact Size (model.joblib)</td>
                  <td className="px-3.5 py-2 text-right text-muted">2.00 MB</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">2.04 MB</td>
                  <td className="px-3.5 py-2 text-right text-muted">+0.04 MB</td>
                  <td className="px-3.5 py-2 text-right text-muted">&lt; 10.0 MB</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Comparative Benchmark vs ModSecurity OWASP CRS */}
        <div className="bg-panel border border-ink">
          <div className="px-4 py-2.5 border-b border-ink font-mono text-[11px] uppercase tracking-[0.06em] font-semibold text-ink">
            COMPARATIVE BENCHMARK: AI WAF VS MODSECURITY + OWASP CRS
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-[12px] border-collapse">
              <thead>
                <tr className="bg-ink text-white text-[11px] uppercase tracking-[0.06em]">
                  <th className="px-3.5 py-2 font-medium">System / Configuration</th>
                  <th className="px-3.5 py-2 font-medium text-right">Precision</th>
                  <th className="px-3.5 py-2 font-medium text-right">Recall</th>
                  <th className="px-3.5 py-2 font-medium text-right">F1-Score</th>
                  <th className="px-3.5 py-2 font-medium text-right">FPR (Benign)</th>
                  <th className="px-3.5 py-2 font-medium text-right">Evasion Recall</th>
                  <th className="px-3.5 py-2 font-medium text-right">p95 Latency</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hair">
                <tr className="even:bg-panel odd:bg-zebra hover:bg-hover">
                  <td className="px-3.5 py-2 text-ink">ModSecurity + OWASP CRS (PL 1 Reference)</td>
                  <td className="px-3.5 py-2 text-right text-muted">0.910</td>
                  <td className="px-3.5 py-2 text-right text-muted">0.820</td>
                  <td className="px-3.5 py-2 text-right text-muted">0.862</td>
                  <td className="px-3.5 py-2 text-right text-muted">4.80%</td>
                  <td className="px-3.5 py-2 text-right text-muted">68.00%</td>
                  <td className="px-3.5 py-2 text-right text-muted">18.0 ms</td>
                </tr>
                <tr className="even:bg-panel odd:bg-zebra hover:bg-hover">
                  <td className="px-3.5 py-2 text-ink">AI-WAF Plain ML Model (Stage 2)</td>
                  <td className="px-3.5 py-2 text-right text-muted">1.000</td>
                  <td className="px-3.5 py-2 text-right text-muted">1.000</td>
                  <td className="px-3.5 py-2 text-right text-muted">1.000</td>
                  <td className="px-3.5 py-2 text-right text-muted">0.00%</td>
                  <td className="px-3.5 py-2 text-right text-muted">77.60%</td>
                  <td className="px-3.5 py-2 text-right text-muted">5.11 ms</td>
                </tr>
                <tr className="even:bg-panel odd:bg-zebra hover:bg-hover border-l-2 border-ink">
                  <td className="px-3.5 py-2 text-ink font-bold">
                    AI-WAF Robust Augmented + Rule Hybrid (Stage 3 Active)
                  </td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">1.000</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">1.000</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">1.000</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">0.00%</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">83.31%</td>
                  <td className="px-3.5 py-2 text-right text-ink font-bold">5.54 ms</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Analyst Feedback Retraining & Safety Promotion Gates */}
        <div className="bg-panel border border-ink p-4 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-hair gap-2">
            <span className="font-mono text-[11px] uppercase tracking-[0.06em] font-semibold text-ink">
              ANALYST FEEDBACK RETRAINING &amp; SAFETY PROMOTION GATES
            </span>
            <span className="border border-ink px-2 py-0.5 text-[10px] font-bold uppercase">
              AUTOMATED GATES PASSED
            </span>
          </div>

          <p className="text-[11px] text-muted leading-relaxed">
            When analysts record feedback in the console, the offline engine merges approved entries into training corpora while strictly preserving frozen test sets. Promotion requires passing 4 candidate safety gates:
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-[11px]">
            <div className="border border-ink p-3 bg-panel">
              <span className="text-muted block text-[10px] uppercase">Gate 1: Benign FPR Cap</span>
              <span className="text-ink font-bold block my-1">0.07% PASS</span>
              <span className="text-muted text-[10px] block">BOUND: &le; 2.50%</span>
            </div>
            <div className="border border-ink p-3 bg-panel">
              <span className="text-muted block text-[10px] uppercase">Gate 2: Evasion Recall</span>
              <span className="text-ink font-bold block my-1">84.36% PASS</span>
              <span className="text-muted text-[10px] block">DROP: &le; 2.0%</span>
            </div>
            <div className="border border-ink p-3 bg-panel">
              <span className="text-muted block text-[10px] uppercase">Gate 3: Cross-Source Recall</span>
              <span className="text-ink font-bold block my-1">4.24% PASS</span>
              <span className="text-muted text-[10px] block">DROP: &le; 2.0%</span>
            </div>
            <div className="border border-ink p-3 bg-panel">
              <span className="text-muted block text-[10px] uppercase">Gate 4: p95 Latency</span>
              <span className="text-ink font-bold block my-1">2.55 ms PASS</span>
              <span className="text-muted text-[10px] block">BOUND: &le; 10.0 ms</span>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
