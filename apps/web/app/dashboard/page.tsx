import type { Metadata } from "next";
import { OverviewDashboard } from "@/components/overview-dashboard";

export const metadata: Metadata = { title: "Threat posture" };

export default function DashboardPage() {
  return <OverviewDashboard />;
}
