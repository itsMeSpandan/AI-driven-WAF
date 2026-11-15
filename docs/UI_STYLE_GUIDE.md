# Monolith UI Style Guide

## 1. Overview & Philosophy
**Monolith** is a high-contrast, black-and-grey, square-cornered, monospace-data interface designed for security operations and telemetry analysis. 
Saturated colour is strictly forbidden across UI chrome and is reserved **exclusively inside data visualization charts**.

---

## 2. Design Tokens

### Core Neutral Palette
| Token | Hex Value | Application |
|---|---|---|
| `--bg` | `#e9e9e6` | Main page canvas background |
| `--panel` | `#ffffff` | Panels, KPI tiles, modal cards, table containers |
| `--ink` | `#111111` | Primary text, 1px borders, top navigation bar, inverted tiles |
| `--muted` | `#555555` | Secondary text, sub-labels (maintains &ge; 4.5:1 contrast) |
| `--hair` | `#d6d6d2` | Inner hairline dividers, row separators |
| `--zebra` | `#f4f4f2` | Alternating table rows, code blocks |
| `--hover` | `#e9e9e6` | Interactive row hover state |
| `--on-dark-muted` | `#c4c4c0` | Secondary links on black top bar |
| `--grid` | `#e1e1de` | Chart horizontal gridlines |

### Chart Palette (Reserved Exclusively for Data Visualization)
| Category | Hex Value | Representation |
|---|---|---|
| **Traffic Area Fill** | `#1d4ed8` | Total request volume (fill at 16% opacity, 2px stroke) |
| **Threats / Blocked** | `#ea580c` | Malicious threats curve (2px stroke) |
| **SQL Injection** | `#ea580c` | Stacked bar segment & swatch |
| **ML Anomaly** | `#1d4ed8` | Stacked bar segment & swatch |
| **XSS** | `#0f766e` | Stacked bar segment & swatch |
| **Path Traversal** | `#a16207` | Stacked bar segment & swatch |
| **Command Injection** | `#7c2d12` | Stacked bar segment & swatch |
| **Scanner / Other** | `#6b7280` | Stacked bar segment & swatch |

---

## 3. Typography
Loaded locally via `next/font/google`:
* **Body / Prose:** `IBM Plex Sans` (400 / 500 / 600), 14px / 1.45 line-height.
* **Data & Readouts:** `IBM Plex Mono` (400 / 500) for all numbers, IPs, paths, timestamps, and scores.
* **Labels:** Mono 11px, uppercase, letter-spacing `0.06em`, colour `--muted` (or `#c4c4c0` on black).
* **KPI Metrics:** Mono 500, 38px / 1.1 line-height.
* **Table Cells:** 12px Mono for data, 13px Sans for plain descriptions.

---

## 4. Geometry & Spacing
* **Border Radius:** Strictly `0px` everywhere. No rounded corners (`rounded-none`).
* **Borders:** `1px solid var(--ink)` on outer containers, tiles, and panels; `1px solid var(--hair)` for inner dividers.
* **Shadows & Effects:** Zero box-shadows, zero text-shadows, zero background gradients, zero blur or glassmorphism.
* **Page Width:** Maximum container width `1280px`, padding `28px 40px`, grid gap `12px`.

---

## 5. Component Patterns

### Top Bar
* Full-width black strip (`#111111`), 14px 40px padding.
* Left: `WAF / CONSOLE` in white mono.
* Right: `Model / Eval`, `API docs`, segmented time range (`5m 1h 24h 7d` with white 2px underline on active), mono mode readout (`BLOCK · 0.94`), and square white `Configure WAF` button.

### KPI Tiles
* 5 equal tiles: `Total requests`, `Blocked`, `Flagged`, `Block rate`, `Avg latency`.
* **Inverted Blocked Tile:** The Blocked tile is inverted with a black background (`#111111`) and white text (`#ffffff`).

### Charts
* **Traffic vs Threats:** Recharts AreaChart with horizontal grid lines only (`--grid`), flat fill (no gradients), square tooltip with 1px black border.
* **Attack Breakdown:** Single 100% stacked horizontal bar (34px height) with hairline list rows below it.

### Tables & Live Events
* Header row: Solid black `#111111` with uppercase white mono text.
* Data rows: Alternating white (`--panel`) and light grey (`--zebra`), hover `--hover`.
* Verdicts: Monochrome only (`BLOCK` bold ink; `FLAG` 1px black box; `ALLOW` muted).
* Stream indicator: Solid black square for `LIVE`, hollow square for `RECONNECTING`.

### Request Detail Drawer
* White slide-over panel with 1px black left border and flat `rgba(17,17,17,.45)` overlay (no blur).
* Token explanations: Top tokens as `<mark>` with black background and white text; secondary tokens with 2px black underline.

---

## 6. Do / Don't Rules
* **DO** use monospace font for all tabular values, IPs, payloads, and scores.
* **DO** enforce visible focus indicators: 2px solid `--ink` (or white on dark).
* **DON'T** use gradient backgrounds, neon rings, or decorative pill shapes.
* **DON'T** use saturated colours outside chart surfaces.
* **DON'T** use `dangerouslySetInnerHTML` under any circumstances.
