/**
 * Monolith Chart Palette Constants
 * Saturated color mapping reserved strictly for data visualization inside charts.
 */

export const ATTACK_COLORS: Record<string, { label: string; color: string }> = {
  sqli: { label: "SQL injection", color: "#ea580c" },
  ml_anomaly: { label: "ML anomaly", color: "#1d4ed8" },
  xss: { label: "XSS", color: "#0f766e" },
  path_traversal: { label: "Path traversal", color: "#a16207" },
  cmdi: { label: "Command injection", color: "#7c2d12" },
  scanner_like: { label: "Scanner / other", color: "#6b7280" },
  other: { label: "Other anomaly", color: "#6b7280" },
};

export const TRAFFIC_COLOR = "#1d4ed8";
export const THREAT_COLOR = "#ea580c";

export function getAttackColor(type: string): string {
  const norm = (type || "").toLowerCase().trim();
  if (norm.includes("sql")) return ATTACK_COLORS.sqli.color;
  if (norm.includes("xss")) return ATTACK_COLORS.xss.color;
  if (norm.includes("path") || norm.includes("traversal") || norm.includes("lfi")) return ATTACK_COLORS.path_traversal.color;
  if (norm.includes("cmd") || norm.includes("command") || norm.includes("rce")) return ATTACK_COLORS.cmdi.color;
  if (norm.includes("scan") || norm.includes("burst")) return ATTACK_COLORS.scanner_like.color;
  if (norm.includes("anomaly") || norm.includes("ml")) return ATTACK_COLORS.ml_anomaly.color;
  return ATTACK_COLORS.other.color;
}

export function getAttackLabel(type: string): string {
  const norm = (type || "").toLowerCase().trim();
  if (norm.includes("sql")) return ATTACK_COLORS.sqli.label;
  if (norm.includes("xss")) return ATTACK_COLORS.xss.label;
  if (norm.includes("path") || norm.includes("traversal")) return ATTACK_COLORS.path_traversal.label;
  if (norm.includes("cmd") || norm.includes("command")) return ATTACK_COLORS.cmdi.label;
  if (norm.includes("scan") || norm.includes("burst")) return ATTACK_COLORS.scanner_like.label;
  if (norm.includes("anomaly") || norm.includes("ml")) return ATTACK_COLORS.ml_anomaly.label;
  return type || ATTACK_COLORS.other.label;
}
