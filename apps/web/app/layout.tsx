import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://sentinel-edge-console.tharukamaduwantha62.workers.dev"),
  title: {
    default: "Sentinel Edge — AI & API Security Gateway",
    template: "%s · Sentinel Edge",
  },
  description: "Inspect, govern, and monitor AI and API traffic at Cloudflare's edge.",
  applicationName: "Sentinel Edge",
  openGraph: {
    title: "Sentinel Edge",
    description: "AI & API Security Gateway",
    type: "website",
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "Sentinel Edge AI and API Security Gateway" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "Sentinel Edge",
    description: "AI & API Security Gateway",
    images: ["/og.png"],
  },
};

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  // Reading request headers forces per-request rendering so Next can apply the CSP nonce.
  await headers();
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
