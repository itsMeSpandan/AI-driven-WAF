/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        background: "#090d16",
        surface: "#0f172a",
        "surface-card": "#1e293b",
        "surface-border": "#334155",
        accent: "#38bdf8",
        danger: "#f43f5e",
        warning: "#fbbf24",
        success: "#10b981",
      },
    },
  },
  plugins: [],
};
