"use client";

import React from "react";
import Link from "next/link";
import { ArrowLeft, Cpu, Scale, CheckCircle2, Clock } from "lucide-react";

export default function EvalPage() {
  return (
    <div className="min-h-screen bg-[#090d16] p-6 lg:p-8 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex items-center justify-between pb-6 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <Link
            href="/"
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <h1 className="text-xl font-bold text-white">
              Model Diagnostics & Baseline Evaluation
            </h1>
            <p className="text-xs text-slate-400">
              TRD 2.12 Evaluation Framework & ModSecurity Benchmark Matrix
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 border border-amber-500/30 text-amber-400">
            Stage 1 Scaffold (Training in Stage 2)
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-6">
        {/* Active Model Card */}
        <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
            <Cpu className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-semibold text-slate-200">Active Model</h3>
          </div>
          <div className="mt-4 space-y-3 text-xs">
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Architecture</span>
              <span className="font-mono text-slate-200">TF-IDF + Linear Classifier</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Feature Extraction</span>
              <span className="font-mono text-slate-200">Char n-grams (2–5)</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Model Version</span>
              <span className="font-mono text-slate-200">v0.1.0-stub</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">Training Dataset</span>
              <span className="font-mono text-slate-200">CSIC 2010 + SecLists</span>
            </div>
          </div>
        </div>

        {/* PRD Success Metrics Targets */}
        <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg col-span-1 md:col-span-2">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-semibold text-slate-200">PRD 1.8 Target Metrics</h3>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-4 text-center">
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400">Detection F1</span>
              <div className="text-lg font-bold text-emerald-400 mt-1">≥ 0.95</div>
              <span className="text-[10px] text-slate-500">Held-out test set</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400">Evasion Recall</span>
              <div className="text-lg font-bold text-amber-400 mt-1">≥ 0.85</div>
              <span className="text-[10px] text-slate-500">Obfuscated payloads</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400">False Positive Rate</span>
              <div className="text-lg font-bold text-sky-400 mt-1">&lt; Baseline</div>
              <span className="text-[10px] text-slate-500">Lower than CRS</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400">Added Latency</span>
              <div className="text-lg font-bold text-indigo-400 mt-1">&lt; 25 ms</div>
              <span className="text-[10px] text-slate-500">p95 per request</span>
            </div>
          </div>
        </div>
      </div>

      {/* Baseline Comparison Matrix */}
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-lg mt-6">
        <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
          <Scale className="w-4 h-4 text-sky-400" />
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
                  ModSecurity + OWASP CRS (PL 1 Default)
                </td>
                <td className="py-2.5 px-3 text-right text-slate-400">0.91</td>
                <td className="py-2.5 px-3 text-right text-slate-400">0.82</td>
                <td className="py-2.5 px-3 text-right text-slate-400">0.86</td>
                <td className="py-2.5 px-3 text-right text-rose-400">4.8%</td>
                <td className="py-2.5 px-3 text-right text-amber-400">0.68</td>
                <td className="py-2.5 px-3 text-right text-slate-400">18 ms</td>
              </tr>
              <tr className="hover:bg-slate-800/30">
                <td className="py-2.5 px-3 font-sans text-slate-300">
                  AI-WAF Baseline (Plain ML Model)
                </td>
                <td className="py-2.5 px-3 text-right text-slate-500">Pending Stage 2</td>
                <td className="py-2.5 px-3 text-right text-slate-500">Pending Stage 2</td>
                <td className="py-2.5 px-3 text-right text-slate-500">Pending Stage 2</td>
                <td className="py-2.5 px-3 text-right text-slate-500">Pending Stage 2</td>
                <td className="py-2.5 px-3 text-right text-slate-500">Pending Stage 3</td>
                <td className="py-2.5 px-3 text-right text-slate-500">Pending Stage 5</td>
              </tr>
              <tr className="bg-sky-500/5 hover:bg-sky-500/10 border-l-2 border-sky-400">
                <td className="py-2.5 px-3 font-sans font-semibold text-sky-300">
                  AI-WAF Augmented + Rule Hybrid (Target)
                </td>
                <td className="py-2.5 px-3 text-right font-semibold text-emerald-400">≥ 0.96</td>
                <td className="py-2.5 px-3 text-right font-semibold text-emerald-400">≥ 0.95</td>
                <td className="py-2.5 px-3 text-right font-semibold text-emerald-400">≥ 0.95</td>
                <td className="py-2.5 px-3 text-right font-semibold text-emerald-400">&lt; 2.5%</td>
                <td className="py-2.5 px-3 text-right font-semibold text-emerald-400">≥ 0.85</td>
                <td className="py-2.5 px-3 text-right font-semibold text-emerald-400">&lt; 25 ms</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
