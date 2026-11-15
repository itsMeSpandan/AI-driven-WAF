"use client";

import React from "react";
import Link from "next/link";
import {
  ArrowLeft,
  Cpu,
  Scale,
  CheckCircle2,
  Clock,
  ShieldCheck,
  AlertTriangle,
  Zap,
  Layers,
} from "lucide-react";

export default function EvalPage() {
  return (
    <div className="min-h-screen bg-[#090d16] p-6 lg:p-8 max-w-7xl mx-auto space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-slate-800 gap-4">
        <div className="flex items-center gap-3">
          <Link
            href="/"
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <h1 className="text-xl font-bold text-white">
              Model Diagnostics & Robustness Evaluation
            </h1>
            <p className="text-xs text-slate-400">
              TRD 2.12 Evaluation Framework & Stage 3 Plain vs Augmented Matrix
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            Stage 3 Robust Detector Active
          </span>
        </div>
      </div>

      {/* Cards Row: Model Metadata + Target Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Active Model Card */}
        <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
            <Cpu className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-semibold text-slate-200">Active ML Model</h3>
          </div>
          <div className="mt-4 space-y-2.5 text-xs">
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Model Name</span>
              <span className="font-mono text-sky-300 font-semibold">
                LogisticRegression (Augmented)
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Model Version</span>
              <span className="font-mono text-slate-200">
                Stage3_Robust_20261114_204029
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Decision Threshold</span>
              <span className="font-mono text-amber-400 font-bold">0.940</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Augmentation Config</span>
              <span className="font-mono text-slate-300">Family A (16,824 samples)</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">Feature Dimensions</span>
              <span className="font-mono text-slate-300">50,000 TF-IDF + 8 Lexical</span>
            </div>
          </div>
        </div>

        {/* PRD Success Metrics Targets */}
        <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg col-span-1 md:col-span-2">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              PRD Goals (G3, G5, G6) & Success Metrics
            </h3>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-4 text-center">
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400">Detection F1</span>
              <div className="text-lg font-bold text-emerald-400 mt-1">1.0000</div>
              <span className="text-[10px] text-slate-500">Target ≥ 0.95</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400">Unseen Evasion Recall</span>
              <div className="text-lg font-bold text-amber-400 mt-1">83.31%</div>
              <span className="text-[10px] text-emerald-400">+5.71% lift vs plain</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400">False Positive Rate</span>
              <div className="text-lg font-bold text-sky-400 mt-1">0.13%</div>
              <span className="text-[10px] text-slate-500">Hard Cap &lt; 2.50%</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400">Added Latency (p95)</span>
              <div className="text-lg font-bold text-indigo-400 mt-1">5.54 ms</div>
              <span className="text-[10px] text-slate-500">Budget ≤ 10.0 ms</span>
            </div>
          </div>
        </div>
      </div>

      {/* Robustness Benchmark Matrix (Stage 3 Task 3 & 4 Deliverable) */}
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Scale className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              Stage 3 Robustness Matrix: Plain Baseline vs Augmented Model
            </h3>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            eval/reports/robustness_report.md
          </span>
        </div>

        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-sans">
                <th className="py-3 px-3">Evaluation Dimension</th>
                <th className="py-3 px-3 text-right">Plain Model (Stage 2)</th>
                <th className="py-3 px-3 text-right">Augmented Model (Stage 3)</th>
                <th className="py-3 px-3 text-right">Observed Delta / Lift</th>
                <th className="py-3 px-3 text-right">Target Requirement</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 font-sans text-slate-300">
                  Calibrated Decision Threshold
                </td>
                <td className="py-2.5 px-3 text-right text-slate-300">0.900</td>
                <td className="py-2.5 px-3 text-right text-amber-300 font-bold">0.940</td>
                <td className="py-2.5 px-3 text-right text-slate-400">+0.040</td>
                <td className="py-2.5 px-3 text-right text-slate-500">Val FPR = 0.00%</td>
              </tr>
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 font-sans text-slate-300">
                  In-Distribution Test F1 Score
                </td>
                <td className="py-2.5 px-3 text-right text-slate-300">1.0000</td>
                <td className="py-2.5 px-3 text-right text-emerald-400 font-bold">1.0000</td>
                <td className="py-2.5 px-3 text-right text-emerald-400">0.00%</td>
                <td className="py-2.5 px-3 text-right text-slate-500">≥ 0.95</td>
              </tr>
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 font-sans text-slate-300">
                  Benign Test False Positive Rate (FPR)
                </td>
                <td className="py-2.5 px-3 text-right text-emerald-400">0.00%</td>
                <td className="py-2.5 px-3 text-right text-emerald-400 font-bold">0.00%</td>
                <td className="py-2.5 px-3 text-right text-emerald-400">0.00%</td>
                <td className="py-2.5 px-3 text-right text-slate-500">≤ 1.0%</td>
              </tr>
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 font-sans text-slate-300">
                  Obfuscated Benign Test FPR (1,507 samples)
                </td>
                <td className="py-2.5 px-3 text-right text-slate-300">0.07%</td>
                <td className="py-2.5 px-3 text-right text-emerald-400 font-bold">0.13%</td>
                <td className="py-2.5 px-3 text-right text-slate-400">+0.06%</td>
                <td className="py-2.5 px-3 text-right text-slate-500">≤ 2.50% hard cap</td>
              </tr>
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 font-sans text-slate-300">
                  Evasion Recall: Family A (Seen Mutations)
                </td>
                <td className="py-2.5 px-3 text-right text-slate-300">100.00%</td>
                <td className="py-2.5 px-3 text-right text-emerald-400 font-bold">100.00%</td>
                <td className="py-2.5 px-3 text-right text-emerald-400">0.00%</td>
                <td className="py-2.5 px-3 text-right text-slate-500">≥ 90.0%</td>
              </tr>
              <tr className="bg-sky-500/5 hover:bg-sky-500/10 border-l-2 border-sky-400">
                <td className="py-2.5 px-3 font-sans font-semibold text-sky-200">
                  Evasion Recall: Family B (Unseen Zero-Day Payloads)
                </td>
                <td className="py-2.5 px-3 text-right text-slate-400">77.60%</td>
                <td className="py-2.5 px-3 text-right text-emerald-300 font-bold">83.31%</td>
                <td className="py-2.5 px-3 text-right text-emerald-400 font-bold">
                  +5.71% lift
                </td>
                <td className="py-2.5 px-3 text-right text-slate-500">PRD Goal G5</td>
              </tr>
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 font-sans text-slate-300">
                  Cross-Source Recall (CSIC 2010 anomalous)
                </td>
                <td className="py-2.5 px-3 text-right text-slate-400">5.82%</td>
                <td className="py-2.5 px-3 text-right text-slate-200 font-semibold">6.01%</td>
                <td className="py-2.5 px-3 text-right text-emerald-400">+0.19%</td>
                <td className="py-2.5 px-3 text-right text-slate-500">PRD Goal G6</td>
              </tr>
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 font-sans text-slate-300">
                  Single-Request Latency p95
                </td>
                <td className="py-2.5 px-3 text-right text-slate-300">5.11 ms</td>
                <td className="py-2.5 px-3 text-right text-indigo-300 font-semibold">5.54 ms</td>
                <td className="py-2.5 px-3 text-right text-slate-400">+0.43 ms</td>
                <td className="py-2.5 px-3 text-right text-slate-500">≤ 10.0 ms budget</td>
              </tr>
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 font-sans text-slate-300">
                  Serialized Artefact Size (model.joblib)
                </td>
                <td className="py-2.5 px-3 text-right text-slate-300">2.00 MB</td>
                <td className="py-2.5 px-3 text-right text-slate-200 font-semibold">2.04 MB</td>
                <td className="py-2.5 px-3 text-right text-slate-400">+0.04 MB</td>
                <td className="py-2.5 px-3 text-right text-slate-500">&lt; 10.0 MB</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Baseline Benchmark vs ModSecurity OWASP CRS */}
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg">
        <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
          <Layers className="w-4 h-4 text-sky-400" />
          <h3 className="text-sm font-semibold text-slate-200">
            Comparative Benchmark: AI WAF vs ModSecurity + OWASP CRS
          </h3>
        </div>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-sans">
                <th className="py-2.5 px-3">System / Configuration</th>
                <th className="py-2.5 px-3 text-right">Precision</th>
                <th className="py-2.5 px-3 text-right">Recall</th>
                <th className="py-2.5 px-3 text-right">F1-Score</th>
                <th className="py-2.5 px-3 text-right">FPR (Benign)</th>
                <th className="py-2.5 px-3 text-right">Evasion Recall</th>
                <th className="py-2.5 px-3 text-right">p95 Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 font-sans text-slate-300">
                  ModSecurity + OWASP CRS (PL 1 Reference)
                </td>
                <td className="py-2.5 px-3 text-right text-slate-400">0.910</td>
                <td className="py-2.5 px-3 text-right text-slate-400">0.820</td>
                <td className="py-2.5 px-3 text-right text-slate-400">0.862</td>
                <td className="py-2.5 px-3 text-right text-rose-400">4.80%</td>
                <td className="py-2.5 px-3 text-right text-amber-400">68.00%</td>
                <td className="py-2.5 px-3 text-right text-slate-400">18.0 ms</td>
              </tr>
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 font-sans text-slate-300">
                  AI-WAF Plain ML Model (Stage 2)
                </td>
                <td className="py-2.5 px-3 text-right text-slate-300">1.000</td>
                <td className="py-2.5 px-3 text-right text-slate-300">1.000</td>
                <td className="py-2.5 px-3 text-right text-slate-300">1.000</td>
                <td className="py-2.5 px-3 text-right text-emerald-400">0.00%</td>
                <td className="py-2.5 px-3 text-right text-slate-300">77.60%</td>
                <td className="py-2.5 px-3 text-right text-slate-300">5.11 ms</td>
              </tr>
              <tr className="bg-emerald-500/5 hover:bg-emerald-500/10 border-l-2 border-emerald-400">
                <td className="py-2.5 px-3 font-sans font-semibold text-emerald-300">
                  AI-WAF Robust Augmented + Rule Hybrid (Stage 3 Active)
                </td>
                <td className="py-2.5 px-3 text-right font-semibold text-emerald-400">1.000</td>
                <td className="py-2.5 px-3 text-right font-semibold text-emerald-400">1.000</td>
                <td className="py-2.5 px-3 text-right font-semibold text-emerald-400">1.000</td>
                <td className="py-2.5 px-3 text-right font-semibold text-emerald-400">0.00%</td>
                <td className="py-2.5 px-3 text-right font-semibold text-emerald-400">83.31%</td>
                <td className="py-2.5 px-3 text-right font-semibold text-emerald-400">5.54 ms</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Analyst Feedback Retraining & Model Safety Promotion Gates (Stage 4) */}
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800 gap-2">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              Analyst Feedback Retraining & Safety Promotion Gates (Stage 4)
            </h3>
          </div>
          <span className="px-2.5 py-0.5 rounded text-[11px] font-bold uppercase bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            Automated Gates Passed
          </span>
        </div>

        <p className="text-xs text-slate-400">
          When analysts mark False Positives (FP) or True Positives (TP) in the console, the offline retraining engine (
          <code className="text-sky-300">ml/retrain_feedback.py</code>) merges feedback into candidate training data while strictly preserving frozen test sets. Promotion requires passing 4 automated safety gates.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs">
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[11px] block">Gate 1: Benign FPR Cap</span>
            <span className="text-emerald-400 font-bold font-mono text-sm">0.07% (PASS)</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">Bound: ≤ 2.50%</span>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[11px] block">Gate 2: Evasion Recall</span>
            <span className="text-emerald-400 font-bold font-mono text-sm">84.36% (PASS)</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">Drop: ≤ 2.0% vs active (+1.05%)</span>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[11px] block">Gate 3: Cross-Source Recall</span>
            <span className="text-emerald-400 font-bold font-mono text-sm">4.24% (PASS)</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">Drop: ≤ 2.0% vs active (+0.45%)</span>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-400 text-[11px] block">Gate 4: p95 Latency</span>
            <span className="text-emerald-400 font-bold font-mono text-sm">2.55 ms (PASS)</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">Bound: ≤ 10.0 ms</span>
          </div>
        </div>

        <div className="pt-2 flex flex-wrap items-center justify-between text-xs border-t border-slate-800/80 gap-3">
          <div className="text-slate-400">
            Poisoning Defense: Conflicting FP labels on high-severity rule signatures are automatically rejected.
          </div>
          <div className="flex items-center gap-2 font-mono text-[11px]">
            <span className="text-slate-500">make promote-model</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-500">make rollback-model</span>
          </div>
        </div>
      </div>
    </div>
  );
}
