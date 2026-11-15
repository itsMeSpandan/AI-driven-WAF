import React from "react";

export function Panel({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`bg-panel border border-ink ${className}`}>
      {children}
    </div>
  );
}

export function PanelHeader({
  title,
  actions,
  className = "",
}: {
  title: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`px-4 py-2.5 border-b border-ink flex items-center justify-between font-mono text-[11px] uppercase tracking-[0.06em] text-muted bg-panel ${className}`}
    >
      <div className="font-semibold text-ink">{title}</div>
      {actions && <div>{actions}</div>}
    </div>
  );
}

export function Tile({
  label,
  value,
  sublabel,
  inverted = false,
  className = "",
}: {
  label: string;
  value: React.ReactNode;
  sublabel?: React.ReactNode;
  inverted?: boolean;
  className?: string;
}) {
  return (
    <div
      className={`p-4 border border-ink flex flex-col justify-between ${
        inverted ? "bg-ink text-white" : "bg-panel text-ink"
      } ${className}`}
    >
      <div
        className={`font-mono text-[11px] uppercase tracking-[0.06em] ${
          inverted ? "text-[#bdbdb9]" : "text-muted"
        }`}
      >
        {label}
      </div>
      <div className="font-mono font-medium text-[38px] leading-[1.1] my-2">
        {value}
      </div>
      {sublabel && (
        <div
          className={`font-mono text-[11px] uppercase tracking-[0.06em] ${
            inverted ? "text-[#bdbdb9]" : "text-muted"
          }`}
        >
          {sublabel}
        </div>
      )}
    </div>
  );
}

export function Button({
  variant = "primary",
  children,
  className = "",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "on-dark";
}) {
  const base =
    "font-mono text-[12px] font-medium px-3 py-1.5 border transition-colors inline-flex items-center justify-center cursor-pointer";
  let styles = "";
  if (variant === "primary") {
    styles = "bg-ink text-white border-ink hover:bg-[#262626]";
  } else if (variant === "secondary") {
    styles = "bg-panel text-ink border-ink hover:bg-hover";
  } else if (variant === "on-dark") {
    styles = "bg-white text-ink border-white hover:bg-[#e9e9e6]";
  }
  return (
    <button className={`${base} ${styles} ${className}`} {...props}>
      {children}
    </button>
  );
}

export function Input({
  className = "",
  ...props
}: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={`bg-panel text-ink border border-ink font-mono text-[12px] px-2.5 py-1.5 focus:outline-none ${className}`}
      {...props}
    />
  );
}

export function Select({
  className = "",
  children,
  ...props
}: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={`bg-panel text-ink border border-ink font-mono text-[12px] px-2.5 py-1.5 focus:outline-none ${className}`}
      {...props}
    >
      {children}
    </select>
  );
}

export function VerdictText({ verdict }: { verdict: string }) {
  const v = (verdict || "").toLowerCase();
  if (v === "block") {
    return (
      <span className="font-mono font-semibold text-[12px] text-ink tracking-[0.04em] uppercase">
        BLOCK
      </span>
    );
  }
  if (v === "flag") {
    return (
      <span className="font-mono font-semibold text-[12px] text-ink border border-ink px-1 tracking-[0.04em] uppercase">
        FLAG
      </span>
    );
  }
  return (
    <span className="font-mono font-normal text-[12px] text-muted tracking-[0.04em] uppercase">
      ALLOW
    </span>
  );
}

export function Tag({ children }: { children: React.ReactNode }) {
  return (
    <span className="font-mono text-[11px] text-muted border border-hair px-1 py-0.5 uppercase">
      {children}
    </span>
  );
}

export function StatusSquare({
  status,
}: {
  status: "live" | "reconnecting" | "paused";
}) {
  if (status === "live") {
    return (
      <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-ink uppercase">
        <span className="w-2 h-2 bg-ink inline-block" /> LIVE
      </span>
    );
  }
  if (status === "reconnecting") {
    return (
      <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-muted uppercase">
        <span className="w-2 h-2 border border-ink inline-block" /> RECONNECTING
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-muted uppercase">
      PAUSED
    </span>
  );
}

export function Overlay({
  onClick,
  children,
}: {
  onClick?: () => void;
  children: React.ReactNode;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ backgroundColor: "rgba(17, 17, 17, 0.45)" }}
      onClick={onClick}
    >
      <div onClick={(e) => e.stopPropagation()}>{children}</div>
    </div>
  );
}
