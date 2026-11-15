import "./globals.css";
import type { Metadata } from "next";
import { IBM_Plex_Sans, IBM_Plex_Mono } from "next/font/google";

const ibmSans = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-ibm-sans",
  display: "swap",
});

const ibmMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-ibm-mono",
  display: "swap",
});

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
    <html lang="en" className={`${ibmSans.variable} ${ibmMono.variable}`}>
      <body className="min-h-screen bg-[var(--bg)] text-[var(--ink)] font-sans antialiased selection:bg-[var(--ink)] selection:text-[var(--panel)]">
        {children}
      </body>
    </html>
  );
}
