"use client";

import React, { useState } from "react";
import { loginAdmin, AuthUser } from "@/lib/api";

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLoginSuccess: (user: AuthUser) => void;
}

export function LoginModal({ isOpen, onClose, onLoginSuccess }: LoginModalProps) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await loginAdmin(username, password);
      onLoginSuccess({ username, authenticated: true, role: "admin" });
      setPassword("");
      onClose();
    } catch (err: any) {
      setError(err.message || "Failed to authenticate");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ backgroundColor: "rgba(17, 17, 17, 0.45)" }}
      onClick={onClose}
    >
      <div
        className="bg-panel border border-ink max-w-sm w-full text-ink shadow-none"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Black Header Strip */}
        <div className="bg-ink text-white px-5 py-3 border-b border-ink font-mono text-[11px] uppercase tracking-[0.06em] font-semibold on-dark">
          SECOPS AUTHENTICATION
        </div>

        <div className="p-5 space-y-4">
          <p className="font-mono text-[11px] text-muted uppercase">
            ADMIN CREDENTIALS REQUIRED FOR WRITE CONTROLS
          </p>

          {error && (
            <div
              role="alert"
              aria-live="assertive"
              className="border-l-2 border-ink pl-3 py-1 font-mono text-[12px] text-ink bg-zebra"
            >
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1">
              <label className="font-mono text-[11px] uppercase text-muted block">
                USERNAME
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full bg-panel border border-ink px-3 py-1.5 text-xs text-ink focus:outline-none font-mono"
              />
            </div>

            <div className="space-y-1">
              <label className="font-mono text-[11px] uppercase text-muted block">
                PASSWORD
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                className="w-full bg-panel border border-ink px-3 py-1.5 text-xs text-ink focus:outline-none font-mono"
              />
            </div>

            <div className="pt-2 flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={onClose}
                className="px-3 py-1.5 border border-ink bg-panel text-ink font-mono text-[12px] hover:bg-hover transition-colors"
              >
                CANCEL
              </button>
              <button
                type="submit"
                disabled={loading}
                className="px-4 py-1.5 border border-ink bg-ink text-white font-mono text-[12px] hover:bg-[#262626] transition-colors disabled:opacity-50"
              >
                {loading ? "AUTHENTICATING..." : "SIGN IN"}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
