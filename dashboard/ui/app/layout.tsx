import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "AI WAF Analytics & SecOps Dashboard",
  description: "Real-time threat monitoring, ML anomaly detection, and explainability",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#090d16] text-slate-100 antialiased selection:bg-sky-500 selection:text-white">
        {children}
      </body>
    </html>
  );
}
