/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "media",
  theme: {
    borderRadius: {
      none: "0px",
      DEFAULT: "0px",
      sm: "0px",
      md: "0px",
      lg: "0px",
      xl: "0px",
      "2xl": "0px",
      full: "0px",
    },
    boxShadow: {
      none: "none",
      DEFAULT: "none",
    },
    extend: {
      colors: {
        bg: "var(--bg)",
        panel: "var(--panel)",
        ink: "var(--ink)",
        muted: "var(--muted)",
        hair: "var(--hair)",
        zebra: "var(--zebra)",
        hover: "var(--hover)",
        "on-dark-muted": "var(--on-dark-muted)",
        grid: "var(--grid)",

        // Chart saturated palette
        "chart-traffic": "var(--chart-traffic)",
        "chart-threat": "var(--chart-threat)",
        "chart-sqli": "var(--chart-sqli)",
        "chart-anomaly": "var(--chart-anomaly)",
        "chart-xss": "var(--chart-xss)",
        "chart-path": "var(--chart-path)",
        "chart-cmdi": "var(--chart-cmdi)",
        "chart-other": "var(--chart-other)",
      },
      fontFamily: {
        sans: ["var(--font-ibm-sans)", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["var(--font-ibm-mono)", "ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
